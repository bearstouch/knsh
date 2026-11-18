//! The XPC control service and the code-signing checks on its peers (KNSH-067, FR-AUTH-12 – FR-AUTH-14).
//!
//! Hand-written bindings to `libxpc`, `libdispatch` (both in libSystem) and the Security framework; no third-party
//! crate and no Swift helper. The decision itself is [`PeerGate::admit`], pure and tested with a fake; this module
//! only moves bytes and reads signatures.
//!
//! # One connection's life
//!
//! 1. **Accept** (listener queue). With no trusted authority the connection is cancelled before it is resumed, so
//!    nothing is ever read from it (FR-AUTH-12). A peer running as another user is cancelled the same way.
//!    Otherwise the [`peer_requirement`](crate::peer_requirement) is set with
//!    `xpc_connection_set_peer_code_signing_requirement` (FR-AUTH-13): XPC refuses a peer that does not satisfy it
//!    before its first message is delivered (observed in KNSH-026, claim C7, and in this module's tests). The
//!    connection gets a serial queue of its own, so a slow handler holds only its own peer.
//! 2. **Every message** (peer queue). The sender is identified by the message's audit token
//!    ([`SecCodeSigning`]: `SecCodeCreateWithXPCMessage`), never by pid, and admitted by [`PeerGate::admit`] before
//!    the message is read (FR-AUTH-14: hardened runtime, valid live signature, not debuggable, minimum version). A
//!    refusal cancels the connection; the message is never read and nothing is answered. Only then is the payload
//!    checked (exactly one key, [`JSON_KEY`](crate::JSON_KEY), an XPC data value of at most
//!    [`MAX_CONTROL_PAYLOAD`] bytes; anything else closes the connection unanswered) and handed to the
//!    [`ControlHandler`].
//! 3. **End.** An XPC error event (the peer left, or XPC refused it), a refused message, or a handler asking to
//!    close ends the connection: [`ControlHandler::closed`] runs once if the connection was ever opened.
//!
//! # Blocks
//!
//! XPC takes its event handlers as blocks. [`EventBlock`] lays one out as clang does (the block ABI of
//! `Block_private.h`, as `presence` does for `LocalAuthentication`): a stack block that `xpc_connection_set_event_handler`
//! copies to the heap. It captures one pointer to a reference-counted [`Callback`]; its copy and dispose helpers take
//! and drop one count per heap copy, so the callback lives exactly as long as XPC can still call it. XPC releases a
//! connection's handler after the connection's final event (`XPC_ERROR_CONNECTION_INVALID`), which also breaks the
//! cycle between a peer and its handler.
//!
//! # Limits
//!
//! The peer requirement and the per-message checks guard what `knshd` *receives*. What `knshd` sends (answers and
//! event notifications) goes to whatever process holds the connection; a peer that exec'd since its last message
//! would receive it, but is refused at its next message. No answer or notification sent here carries a secret yet;
//! decision requests (KNSH-069) and secrets (KNSH-089) must keep that in mind.

use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use crate::control::{
    AfterMessage, BYTES_KEY, CodeSigning, ConnectionId, ControlHandler, ControlPeer, JSON_KEY, MAX_CONTROL_PAYLOAD,
    PeerGate, PeerRejection, SignatureFacts,
};
use crate::error::{Operation, PlatformError};

/// An XPC object (`xpc_object_t`, also `xpc_connection_t`).
type Xpc = *mut c_void;
/// A dispatch queue (`dispatch_queue_t`).
type Queue = *mut c_void;
/// A Core Foundation object (`CFTypeRef`).
type CfRef = *const c_void;

/// `XPC_CONNECTION_MACH_SERVICE_LISTENER`.
const MACH_SERVICE_LISTENER: u64 = 1;

/// `errSecSuccess`.
const ERR_SEC_SUCCESS: i32 = 0;
/// `errSecParam`, reported when a requirement string cannot even be handed to the Security framework.
const ERR_SEC_PARAM: i32 = -50;
/// `kSecCSDefaultFlags`.
const SEC_CS_DEFAULT: u32 = 0;
/// `kSecCSSigningInformation | kSecCSDynamicInformation`: the signature's flags and `Info.plist`, and the live status.
const SEC_CS_SIGNING_AND_DYNAMIC: u32 = (1 << 1) | (1 << 3);

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
/// `kCFNumberSInt64Type`: wide enough for a 32-bit flag word stored signed or unsigned.
const K_CF_NUMBER_SINT64: isize = 4;
/// Longest `CFBundleVersion` read, in bytes with the NUL. A valid version is at most 29 bytes; a longer string is
/// refused as no version at all.
const MAX_VERSION_TEXT: usize = 64;

// libxpc and libdispatch are part of libSystem. Type and error objects are declared as bytes: only their addresses
// are used, as the `XPC_TYPE_*` and `XPC_ERROR_*` macros do.
unsafe extern "C" {
    static _xpc_type_connection: u8;
    static _xpc_type_dictionary: u8;
    static _xpc_type_data: u8;
    static _xpc_error_peer_code_signing_requirement: u8;

    fn xpc_connection_create_mach_service(name: *const c_char, queue: Queue, flags: u64) -> Xpc;
    fn xpc_connection_set_event_handler(connection: Xpc, handler: *const c_void);
    fn xpc_connection_set_target_queue(connection: Xpc, queue: Queue);
    fn xpc_connection_set_peer_code_signing_requirement(connection: Xpc, requirement: *const c_char) -> c_int;
    fn xpc_connection_get_euid(connection: Xpc) -> u32;
    fn xpc_connection_resume(connection: Xpc);
    fn xpc_connection_cancel(connection: Xpc);
    fn xpc_connection_send_message(connection: Xpc, message: Xpc);
    fn xpc_get_type(object: Xpc) -> *const c_void;
    fn xpc_retain(object: Xpc) -> Xpc;
    fn xpc_release(object: Xpc);
    fn xpc_dictionary_create(keys: *const *const c_char, values: *const Xpc, count: usize) -> Xpc;
    fn xpc_dictionary_create_reply(original: Xpc) -> Xpc;
    fn xpc_dictionary_get_count(dictionary: Xpc) -> usize;
    fn xpc_dictionary_get_value(dictionary: Xpc, key: *const c_char) -> Xpc;
    fn xpc_dictionary_set_data(dictionary: Xpc, key: *const c_char, bytes: *const c_void, length: usize);
    fn xpc_data_get_length(data: Xpc) -> usize;
    fn xpc_data_get_bytes_ptr(data: Xpc) -> *const c_void;

    fn dispatch_queue_create(label: *const c_char, attributes: *const c_void) -> Queue;
    fn dispatch_release(object: Queue);

    /// The class of blocks that live on the stack. Declared as `void *[32]` in `<Block.h>`; only its address is used.
    static _NSConcreteStackBlock: [*const c_void; 32];
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    /// Declared exactly as in `presence` and `keychain` (a mutable object pointer), so the declarations agree.
    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        is_external: u8,
    ) -> *mut c_void;
    fn CFDictionaryGetValue(dictionary: CfRef, key: CfRef) -> CfRef;
    fn CFNumberGetValue(number: CfRef, kind: isize, value: *mut c_void) -> u8;
    fn CFStringGetCString(string: CfRef, buffer: *mut c_char, size: isize, encoding: u32) -> u8;
    fn CFGetTypeID(object: CfRef) -> usize;
    fn CFNumberGetTypeID() -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFRelease(object: CfRef);
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoFlags: CfRef;
    static kSecCodeInfoStatus: CfRef;
    static kSecCodeInfoPList: CfRef;

    fn SecCodeCreateWithXPCMessage(message: Xpc, flags: u32, code: *mut CfRef) -> i32;
    fn SecRequirementCreateWithString(text: CfRef, flags: u32, requirement: *mut CfRef) -> i32;
    fn SecCodeCheckValidity(code: CfRef, flags: u32, requirement: CfRef) -> i32;
    fn SecCodeCopySigningInformation(code: CfRef, flags: u32, information: *mut CfRef) -> i32;
}

/// An owned Core Foundation object, released on drop. Never null.
struct Cf(CfRef);

impl Cf {
    /// Takes ownership of `object` (a Create or Copy result), or `None` if it is null.
    fn new(object: CfRef) -> Option<Self> {
        // Not `then_some`: its argument is built eagerly, so a null would be wrapped and then released on drop.
        if object.is_null() { None } else { Some(Self(object)) }
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null object this value owns one reference to, released exactly once, here.
        unsafe { CFRelease(self.0) };
    }
}

/// A new `CFString` holding `text` (UTF-8), or `None` if it is too long or cannot be created.
fn cf_string(text: &str) -> Option<Cf> {
    let length = isize::try_from(text.len()).ok()?;
    // SAFETY: `text` is valid UTF-8 of `length` bytes for the duration of the call, which copies it.
    Cf::new(unsafe { CFStringCreateWithBytes(std::ptr::null(), text.as_ptr(), length, K_CF_STRING_ENCODING_UTF8, 0) })
}

/// [`PlatformError::Security`] for `operation`.
const fn security(operation: Operation, status: i32) -> PlatformError {
    PlatformError::Security { operation, status }
}

/// A message received on a control connection, borrowed for the duration of its event handler.
#[derive(Debug)]
pub struct XpcMessage(Xpc);

/// Reads a message sender's signature with the Security framework, by the message's audit token, and checks it
/// against one compiled requirement (decision 13).
#[derive(Debug)]
pub struct SecCodeSigning {
    /// The compiled `SecRequirementRef`.
    requirement: CfRef,
}

// SAFETY: a `SecRequirement` is an immutable Core Foundation object, and Core Foundation allows immutable objects to
// be used from any thread.
unsafe impl Send for SecCodeSigning {}
// SAFETY: as above; nothing here mutates the requirement.
unsafe impl Sync for SecCodeSigning {}

impl SecCodeSigning {
    /// Compiles `requirement` (the code-signing requirement language).
    ///
    /// # Errors
    ///
    /// [`PlatformError::Security`] with [`Operation::CodeRequirement`] if the text does not compile.
    pub fn new(requirement: &str) -> Result<Self, PlatformError> {
        let fail = |status| security(Operation::CodeRequirement, status);
        let text = cf_string(requirement).ok_or_else(|| fail(ERR_SEC_PARAM))?;
        let mut compiled: CfRef = std::ptr::null();
        // SAFETY: `text` is a live `CFString`; `compiled` is a valid place for the +1 result.
        let status = unsafe { SecRequirementCreateWithString(text.0, SEC_CS_DEFAULT, &raw mut compiled) };
        if status != ERR_SEC_SUCCESS || compiled.is_null() {
            return Err(fail(status));
        }
        Ok(Self { requirement: compiled })
    }

    /// The facts about `code` (a `SecCodeRef`), checked against this requirement.
    fn facts_of(&self, code: &Cf) -> Result<SignatureFacts, PlatformError> {
        // SAFETY: `code` and the requirement are live Security objects.
        let validity = unsafe { SecCodeCheckValidity(code.0, SEC_CS_DEFAULT, self.requirement) };
        let mut information: CfRef = std::ptr::null();
        // SAFETY: `code` is live; `information` is a valid place for the +1 dictionary.
        let status = unsafe { SecCodeCopySigningInformation(code.0, SEC_CS_SIGNING_AND_DYNAMIC, &raw mut information) };
        let information = match Cf::new(information) {
            Some(information) if status == ERR_SEC_SUCCESS => information,
            _ => return Err(security(Operation::CodeSigning, status)),
        };
        // SAFETY: the keys are the framework's constant strings; `information` is a live dictionary.
        let (flags, live, plist) = unsafe {
            (
                number(information.0, kSecCodeInfoFlags),
                number(information.0, kSecCodeInfoStatus),
                CFDictionaryGetValue(information.0, kSecCodeInfoPList),
            )
        };
        // Without both flag words nothing can be decided: refuse, never assume a default.
        let (Some(signature_flags), Some(live_status)) = (flags, live) else {
            return Err(security(Operation::CodeSigning, ERR_SEC_PARAM));
        };
        Ok(SignatureFacts {
            requirement_met: validity == ERR_SEC_SUCCESS,
            signature_flags,
            status: live_status,
            // SAFETY: `plist` is null or a value borrowed from `information`, which is alive here.
            bundle_version: unsafe { bundle_version(plist) },
        })
    }
}

impl Drop for SecCodeSigning {
    fn drop(&mut self) {
        // SAFETY: the requirement is a +1 object this value owns, released once.
        unsafe { CFRelease(self.requirement) };
    }
}

impl CodeSigning<XpcMessage> for SecCodeSigning {
    fn inspect(&self, message: &XpcMessage) -> Result<SignatureFacts, PlatformError> {
        let mut code: CfRef = std::ptr::null();
        // SAFETY: `message.0` is the live message of the event being handled; `code` is a valid place for the +1
        // result. The code is found by the message's audit token, so it is the exact process instance that sent it.
        let status = unsafe { SecCodeCreateWithXPCMessage(message.0, SEC_CS_DEFAULT, &raw mut code) };
        match Cf::new(code) {
            Some(code) if status == ERR_SEC_SUCCESS => self.facts_of(&code),
            _ => Err(security(Operation::CodeSigning, status)),
        }
    }
}

/// The 32-bit flag word under `key` in `dictionary`, or `None` if it is missing or not such a number.
///
/// # Safety
///
/// `dictionary` must be a live `CFDictionary` and `key` a live `CFString`.
unsafe fn number(dictionary: CfRef, key: CfRef) -> Option<u32> {
    // SAFETY: guaranteed by the caller; the value is borrowed from the dictionary.
    let value = unsafe { CFDictionaryGetValue(dictionary, key) };
    // SAFETY: `value` is checked to be a live `CFNumber` before it is read into an `i64`.
    let wide = unsafe {
        if value.is_null() || CFGetTypeID(value) != CFNumberGetTypeID() {
            return None;
        }
        let mut wide: i64 = 0;
        (CFNumberGetValue(value, K_CF_NUMBER_SINT64, (&raw mut wide).cast()) != 0).then_some(wide)?
    };
    // Flag words are `uint32_t`; one stored as a negative `SInt32` keeps its bits.
    u32::try_from(wide)
        .ok()
        .or_else(|| i32::try_from(wide).ok().map(i32::cast_unsigned))
}

/// `CFBundleVersion` from the signed `Info.plist`, or `None` if there is no plist, no version, or no string that fits.
///
/// # Safety
///
/// `plist` must be null or a live Core Foundation object.
unsafe fn bundle_version(plist: CfRef) -> Option<String> {
    let key = cf_string("CFBundleVersion")?;
    let mut buffer = [0 as c_char; MAX_VERSION_TEXT];
    // SAFETY: each object is checked to be the right type before it is used; the value is borrowed from `plist`, and
    // the buffer holds `MAX_VERSION_TEXT` bytes, which is the size passed.
    unsafe {
        if plist.is_null() || CFGetTypeID(plist) != CFDictionaryGetTypeID() {
            return None;
        }
        let value = CFDictionaryGetValue(plist, key.0);
        if value.is_null() || CFGetTypeID(value) != CFStringGetTypeID() {
            return None;
        }
        #[allow(clippy::cast_possible_wrap, reason = "MAX_VERSION_TEXT is 64")]
        let size = MAX_VERSION_TEXT as isize;
        if CFStringGetCString(value, buffer.as_mut_ptr(), size, K_CF_STRING_ENCODING_UTF8) == 0 {
            return None;
        }
        CStr::from_ptr(buffer.as_ptr()).to_str().ok().map(str::to_owned)
    }
}

/// The XPC control service: a listener on the control Mach service whose every peer is verified (module docs).
/// Dropping it cancels the listener and every connection.
pub struct XpcControlService {
    listener: Xpc,
    queue: Queue,
    service: Arc<Service>,
}

// SAFETY: XPC connections and dispatch queues may be used from any thread; the handles are only cancelled and
// released here, each once.
unsafe impl Send for XpcControlService {}
// SAFETY: as above; `&self` methods only read atomics in `service`.
unsafe impl Sync for XpcControlService {}

impl std::fmt::Debug for XpcControlService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XpcControlService")
            .field("open_connections", &self.open_connections())
            .finish_non_exhaustive()
    }
}

impl XpcControlService {
    /// Serves the Mach service `name`, which must be declared in this job's launchd configuration (FR-AUTH-12;
    /// [`LaunchAgent::render`](crate::LaunchAgent::render) declares it). Every peer must pass `gate`; verified
    /// messages go to `handler`.
    ///
    /// Outside launchd, or for a name the job does not declare, XPC reports the listener invalid and no connection
    /// ever arrives (observed in KNSH-026); that is not reported here.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Security`] if the gate's requirement does not compile, [`PlatformError::Xpc`] if `name` holds a
    /// NUL byte or XPC cannot create the queue or listener.
    pub fn listen(name: &str, gate: PeerGate, handler: Arc<dyn ControlHandler>) -> Result<Self, PlatformError> {
        let name = CString::new(name).map_err(|_| PlatformError::Xpc)?;
        // SAFETY: `name` is NUL-terminated and copied by the call; `queue` is a live queue the listener retains.
        Self::start(gate, handler, |queue| unsafe {
            xpc_connection_create_mach_service(name.as_ptr(), queue, MACH_SERVICE_LISTENER)
        })
    }

    /// Creates the queue, the listener (with `create`) and its handler, then starts listening.
    fn start(
        gate: PeerGate,
        handler: Arc<dyn ControlHandler>,
        create: impl FnOnce(Queue) -> Xpc,
    ) -> Result<Self, PlatformError> {
        Self::start_with(Trust::compile(gate)?, handler, create)
    }

    /// [`XpcControlService::start`] with the trust already compiled. Production compiles the gate's own requirement
    /// ([`Trust::compile`]); tests pass a requirement an ad-hoc test binary meets and a fake, to drive the per-message
    /// gate over real XPC.
    fn start_with(
        trust: Trust,
        handler: Arc<dyn ControlHandler>,
        create: impl FnOnce(Queue) -> Xpc,
    ) -> Result<Self, PlatformError> {
        let service = Arc::new(Service {
            trust: Mutex::new(Arc::new(trust)),
            handler,
            next_id: AtomicU64::new(1),
            open: AtomicUsize::new(0),
            peers: Mutex::new(Vec::new()),
            stopped: AtomicBool::new(false),
            // SAFETY: no preconditions.
            own_uid: unsafe { libc::geteuid() },
        });
        // SAFETY: a static label; a null attribute makes a serial queue. The +1 queue is released on drop.
        let queue = unsafe { dispatch_queue_create(c"knsh.control.listener".as_ptr(), std::ptr::null()) };
        if queue.is_null() {
            return Err(PlatformError::Xpc);
        }
        let listener = create(queue);
        if listener.is_null() {
            // SAFETY: the +1 queue created above, not used by anything else.
            unsafe { dispatch_release(queue) };
            return Err(PlatformError::Xpc);
        }
        let accepting = Arc::clone(&service);
        let callback = Callback::new(move |event| {
            // SAFETY: XPC passes the listener's event, live for this call.
            if unsafe { is_type(event, &raw const _xpc_type_connection) } {
                // SAFETY: as above: a new peer connection, live for this call.
                unsafe { accepting.accept(event) };
            }
            // Listener errors (an undeclared name, or the listener cancelled) need nothing more: no peer can
            // arrive after them.
        });
        // SAFETY: `listener` is a new, not yet resumed connection; the handler is set before it is resumed.
        unsafe {
            set_event_handler(listener, &callback);
            xpc_connection_resume(listener);
        }
        Ok(Self {
            listener,
            queue,
            service,
        })
    }

    /// Connections whose first message passed verification and that have not ended: they keep `knshd` alive.
    #[must_use]
    pub fn open_connections(&self) -> usize {
        self.service.open.load(Ordering::SeqCst)
    }

    /// Serves `gate` from now on: the user trusted another authority, or a first one (KNSH-068, FR-AUTH-10).
    ///
    /// New connections get the new requirement. Every connection accepted under the previous gate is cancelled,
    /// because XPC checked it against the previous requirement: its peer may connect again and is then checked
    /// against this one. A message such a connection sends after the swap, before its cancellation lands, is refused
    /// unread.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Security`] if the gate's requirement does not compile: the previous gate stays in force.
    pub fn set_gate(&self, gate: PeerGate) -> Result<(), PlatformError> {
        self.service.replace_trust(Trust::compile(gate)?);
        Ok(())
    }
}

impl Drop for XpcControlService {
    fn drop(&mut self) {
        self.service.stopped.store(true, Ordering::SeqCst);
        // SAFETY: the listener this value created; cancelling twice is allowed, and it is released only here.
        unsafe {
            xpc_connection_cancel(self.listener);
            xpc_release(self.listener);
        }
        let peers = std::mem::take(&mut *self.service.peers.lock().unwrap_or_else(PoisonError::into_inner));
        for peer in peers.iter().filter_map(Weak::upgrade) {
            // SAFETY: the peer holds its connection retained; cancelling an ended connection does nothing.
            unsafe { xpc_connection_cancel(peer.connection) };
        }
        // SAFETY: the +1 queue created in `start`. The listener holds its own reference until it is torn down.
        unsafe { dispatch_release(self.queue) };
    }
}

/// The gate in force, with what it needs compiled. Replaced as a whole ([`XpcControlService::set_gate`]); each peer
/// keeps the one it was accepted under.
struct Trust {
    gate: PeerGate,
    /// The compiled requirement's checker ([`SecCodeSigning`]); `None` when nothing is trusted.
    signing: Option<Arc<dyn CodeSigning<XpcMessage>>>,
    /// The requirement text for XPC; `None` when nothing is trusted.
    requirement: Option<CString>,
}

impl Trust {
    /// `gate` with its own requirement compiled for XPC and for the per-message check.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Security`] if the requirement does not compile; [`PlatformError::Xpc`] if it holds a NUL
    /// (impossible for a requirement built from a valid trust record).
    fn compile(gate: PeerGate) -> Result<Self, PlatformError> {
        let signing = match gate.requirement() {
            Some(text) => Some(Arc::new(SecCodeSigning::new(text)?) as Arc<dyn CodeSigning<XpcMessage>>),
            None => None,
        };
        let requirement = gate.requirement().map(str::to_owned);
        Self::with(gate, requirement.as_deref(), signing)
    }

    /// `gate` with the XPC requirement text and the per-message checker given separately (tests).
    fn with(
        gate: PeerGate,
        requirement: Option<&str>,
        signing: Option<Arc<dyn CodeSigning<XpcMessage>>>,
    ) -> Result<Self, PlatformError> {
        let requirement = requirement
            .map(|text| CString::new(text).map_err(|_| PlatformError::Xpc))
            .transpose()?;
        Ok(Self {
            gate,
            signing,
            requirement,
        })
    }
}

/// What the listener and its peers share.
struct Service {
    /// The gate in force. Lock order: this, then `peers`; never held while calling the handler.
    trust: Mutex<Arc<Trust>>,
    handler: Arc<dyn ControlHandler>,
    next_id: AtomicU64,
    /// Connections opened and not yet ended.
    open: AtomicUsize,
    /// Every peer accepted, to cancel them all when the service stops. Weak, so ended peers are freed.
    peers: Mutex<Vec<Weak<Peer>>>,
    stopped: AtomicBool,
    own_uid: u32,
}

impl Service {
    /// The gate in force now.
    fn current_trust(&self) -> Arc<Trust> {
        Arc::clone(&self.trust.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Puts `trust` in force and cancels every peer accepted before (XPC checked them against the old requirement).
    /// Their queues then deliver the cancellation, which ends each one and tells the handler, as for any peer that
    /// leaves.
    fn replace_trust(&self, trust: Trust) {
        let mut current = self.trust.lock().unwrap_or_else(PoisonError::into_inner);
        *current = Arc::new(trust);
        let peers: Vec<Arc<Peer>> = self
            .peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        drop(current);
        for peer in peers {
            // SAFETY: the peer holds its connection retained; cancelling an ended connection does nothing.
            unsafe { xpc_connection_cancel(peer.connection) };
        }
    }

    /// A new peer connection (listener queue): refused before it is resumed, or verified by XPC from now on.
    ///
    /// # Safety
    ///
    /// `connection` must be the live, not yet resumed peer connection of a listener event.
    unsafe fn accept(self: &Arc<Self>, connection: Xpc) {
        let refuse = |reason| {
            self.handler.refused(reason);
            // SAFETY: cancelling a connection that was never resumed is allowed (checked in KNSH-067 on macOS 26.6):
            // no event, and in particular no message, is ever delivered for it.
            unsafe { xpc_connection_cancel(connection) };
        };
        let trust = self.current_trust();
        let (Some(requirement), Some(_)) = (trust.requirement.as_ref(), trust.signing.as_ref()) else {
            return refuse(PeerRejection::NoTrustedAuthority);
        };
        if self.stopped.load(Ordering::SeqCst) {
            // SAFETY: as above.
            return unsafe { xpc_connection_cancel(connection) };
        }
        // Only this user's processes may reach the service at all (launchd's per-user domain); root is not the user.
        // SAFETY: `connection` is live.
        if unsafe { xpc_connection_get_euid(connection) } != self.own_uid {
            return refuse(PeerRejection::OtherUser);
        }
        // SAFETY: `connection` is live and not resumed; the requirement text is NUL-terminated and copied.
        if unsafe { xpc_connection_set_peer_code_signing_requirement(connection, requirement.as_ptr()) } != 0 {
            return refuse(PeerRejection::Unverifiable);
        }
        // SAFETY: a static label; a null attribute makes a serial queue, owned by the peer and released with it.
        let queue = unsafe { dispatch_queue_create(c"knsh.control.peer".as_ptr(), std::ptr::null()) };
        if queue.is_null() {
            return refuse(PeerRejection::Unverifiable);
        }
        let peer = Arc::new(Peer {
            id: ConnectionId(self.next_id.fetch_add(1, Ordering::SeqCst)),
            // SAFETY: `connection` is live; the peer owns this +1 reference and releases it on drop.
            connection: unsafe { xpc_retain(connection) },
            queue,
            service: Arc::clone(self),
            trust: Arc::clone(&trust),
            phase: Mutex::new(Phase::New),
        });
        {
            let mut peers = self.peers.lock().unwrap_or_else(PoisonError::into_inner);
            peers.retain(|peer| peer.strong_count() > 0);
            peers.push(Arc::downgrade(&peer));
        }
        let handling = Arc::clone(&peer);
        let callback = Callback::new(move |event| {
            // A panicking handler must not unwind into XPC; the connection is closed instead (fail closed).
            // SAFETY: XPC passes the peer's event, live for this call.
            if catch_unwind(AssertUnwindSafe(|| unsafe { handling.on_event(event) })).is_err() {
                handling.end();
            }
        });
        // SAFETY: the connection is not resumed yet: target queue and handler are set first, as XPC requires.
        unsafe {
            xpc_connection_set_target_queue(connection, queue);
            set_event_handler(connection, &callback);
            xpc_connection_resume(connection);
        }
    }
}

/// Where a connection stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Accepted; no message has passed verification yet.
    New,
    /// A message passed verification: the handler knows the connection.
    Open,
    /// Ended. Nothing more is read or sent.
    Ended,
}

/// One peer connection.
struct Peer {
    id: ConnectionId,
    /// Retained (+1), released on drop.
    connection: Xpc,
    /// The peer's own serial queue (+1), released on drop.
    queue: Queue,
    service: Arc<Service>,
    /// The gate this peer was accepted under. Its messages are checked against it only while it is still the one
    /// in force: a peer from before [`XpcControlService::set_gate`] is refused.
    trust: Arc<Trust>,
    /// Changed on the peer's queue, and by [`ControlPeer::send`] readers on other threads.
    phase: Mutex<Phase>,
}

// SAFETY: XPC connections may be sent to and cancelled from any thread; the phase is behind a lock.
unsafe impl Send for Peer {}
// SAFETY: as above.
unsafe impl Sync for Peer {}

impl Drop for Peer {
    fn drop(&mut self) {
        // SAFETY: the +1 references taken in `Service::accept`, released once. By now XPC has released the handler
        // (it held the last other reference to this peer), so nothing uses the connection through this peer again.
        unsafe {
            xpc_release(self.connection);
            dispatch_release(self.queue);
        }
    }
}

impl Peer {
    /// The connection's phase, locked. A poisoned lock still yields it: the phase is a plain value, always whole.
    fn phase(&self) -> std::sync::MutexGuard<'_, Phase> {
        self.phase.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One event on the peer's queue.
    ///
    /// # Safety
    ///
    /// `event` must be the live event XPC passed to the handler.
    unsafe fn on_event(self: &Arc<Self>, event: Xpc) {
        // SAFETY: `event` is live.
        if unsafe { is_type(event, &raw const _xpc_type_dictionary) } {
            // SAFETY: `event` is a live message.
            unsafe { self.on_message(event) };
            return;
        }
        // Any other event is an error: the peer left, or XPC refused it against the requirement (FR-AUTH-13).
        if std::ptr::eq(
            event.cast_const().cast(),
            &raw const _xpc_error_peer_code_signing_requirement,
        ) {
            self.service.handler.refused(PeerRejection::RequirementNotMet);
        }
        self.end();
    }

    /// One message: verified first, read only if the sender passes (FR-AUTH-14).
    ///
    /// # Safety
    ///
    /// `message` must be a live XPC dictionary received on this connection.
    unsafe fn on_message(self: &Arc<Self>, message: Xpc) {
        if *self.phase() == Phase::Ended || self.service.stopped.load(Ordering::SeqCst) {
            return self.end();
        }
        // Accepted under a gate no longer in force (the user trusted another authority): never read, as with any
        // peer the current gate would not have accepted. Its cancellation is already on the way.
        if !Arc::ptr_eq(&self.trust, &self.service.current_trust()) {
            return self.end();
        }
        let Some(signing) = self.trust.signing.as_ref() else {
            return self.end();
        };
        if let Err(reason) = self.trust.gate.admit(signing.as_ref(), &XpcMessage(message)) {
            // Dropped before the message is read: no answer, and nothing it said reaches the handler.
            self.service.handler.refused(reason);
            return self.end();
        }
        // SAFETY: `message` is a live dictionary.
        let Some(json) = (unsafe { request_payload(message) }) else {
            // Not the control message shape: a transport violation, closed unanswered like a bad frame.
            return self.end();
        };
        let opened = {
            let mut phase = self.phase();
            let opened = *phase == Phase::New;
            *phase = Phase::Open;
            opened
        };
        let handler = &self.service.handler;
        if opened {
            self.service.open.fetch_add(1, Ordering::SeqCst);
            handler.opened(self.id, Arc::new(PeerSender(Arc::clone(self))));
        }
        let reply = Reply {
            peer: self,
            request: message,
        };
        if handler.message(self.id, &json, &reply) == AfterMessage::Close {
            self.end();
        }
    }

    /// Sends `json` (and `bytes`) as the reply to `request`, or as a plain message if the peer expects no reply.
    ///
    /// # Safety
    ///
    /// `request` must be a live dictionary received on this connection.
    unsafe fn send_answer(&self, request: Xpc, json: &[u8], bytes: Option<&[u8]>) -> Result<(), PlatformError> {
        // SAFETY: `request` is live; the result is null when the request expects no reply, otherwise +1.
        let reply = unsafe { xpc_dictionary_create_reply(request) };
        if reply.is_null() {
            return self.send_message(json, bytes);
        }
        // SAFETY: `reply` is a new +1 dictionary, handed over.
        unsafe { self.transmit(reply, json, bytes) };
        Ok(())
    }

    /// Sends `json` (and `bytes`) as a new message on the connection.
    fn send_message(&self, json: &[u8], bytes: Option<&[u8]>) -> Result<(), PlatformError> {
        if *self.phase() == Phase::Ended {
            return Err(PlatformError::Xpc);
        }
        // SAFETY: no preconditions; the result is null or a new, empty +1 dictionary.
        let message = unsafe { xpc_dictionary_create(std::ptr::null(), std::ptr::null(), 0) };
        if message.is_null() {
            return Err(PlatformError::Xpc);
        }
        // SAFETY: `message` is a new +1 dictionary, handed over.
        unsafe { self.transmit(message, json, bytes) };
        Ok(())
    }

    /// Fills `message` with `json` (and `bytes`), sends it on the connection and releases it.
    ///
    /// # Safety
    ///
    /// `message` must be a live, mutable XPC dictionary the caller owns one reference to; that reference is consumed.
    unsafe fn transmit(&self, message: Xpc, json: &[u8], bytes: Option<&[u8]>) {
        // SAFETY: `message` is as the caller guarantees; `self.connection` is live (retained); the send retains what
        // it needs, so the caller's reference is released exactly once, here.
        unsafe {
            fill(message, json, bytes);
            xpc_connection_send_message(self.connection, message);
            xpc_release(message);
        }
    }

    /// Ends the connection: cancels it and, the first time, tells the handler if it ever opened.
    fn end(&self) {
        let previous = std::mem::replace(&mut *self.phase(), Phase::Ended);
        // SAFETY: the connection is retained; cancelling twice is allowed.
        unsafe { xpc_connection_cancel(self.connection) };
        if previous == Phase::Open {
            self.service.open.fetch_sub(1, Ordering::SeqCst);
            self.service.handler.closed(self.id);
        }
    }
}

/// Sends the answer to one request, for the handler, during its [`ControlHandler::message`] call.
struct Reply<'a> {
    peer: &'a Peer,
    /// The request being answered: live for the whole call.
    request: Xpc,
}

// SAFETY: XPC objects may be used from any thread, and the borrow keeps `Reply` from outliving the handler call
// that keeps the request alive.
unsafe impl Send for Reply<'_> {}
// SAFETY: as above; sending a reply only reads the request.
unsafe impl Sync for Reply<'_> {}

impl ControlPeer for Reply<'_> {
    fn send(&self, json: &[u8], bytes: Option<&[u8]>) -> Result<(), PlatformError> {
        if json.len() > MAX_CONTROL_PAYLOAD || *self.peer.phase() == Phase::Ended {
            return Err(PlatformError::Xpc);
        }
        // SAFETY: `request` is the message whose handler is running, so it is live.
        unsafe { self.peer.send_answer(self.request, json, bytes) }
    }
}

/// Sends to one peer for the handler (event notifications).
struct PeerSender(Arc<Peer>);

impl ControlPeer for PeerSender {
    fn send(&self, json: &[u8], bytes: Option<&[u8]>) -> Result<(), PlatformError> {
        if json.len() > MAX_CONTROL_PAYLOAD {
            return Err(PlatformError::Xpc);
        }
        self.0.send_message(json, bytes)
    }
}

/// The JSON payload of a request: exactly one key, [`JSON_KEY`], holding an XPC data value of at most
/// [`MAX_CONTROL_PAYLOAD`] bytes. `None` for any other shape; the length is checked before anything is copied.
///
/// # Safety
///
/// `message` must be a live XPC dictionary.
unsafe fn request_payload(message: Xpc) -> Option<Vec<u8>> {
    let key = CString::new(JSON_KEY).ok()?;
    // SAFETY: `message` is a live dictionary; the value is borrowed from it and checked to be data before use.
    unsafe {
        if xpc_dictionary_get_count(message) != 1 {
            return None;
        }
        let value = xpc_dictionary_get_value(message, key.as_ptr());
        if value.is_null() || !is_type(value, &raw const _xpc_type_data) {
            return None;
        }
        let length = xpc_data_get_length(value);
        if length > MAX_CONTROL_PAYLOAD {
            return None;
        }
        if length == 0 {
            return Some(Vec::new());
        }
        let bytes = xpc_data_get_bytes_ptr(value).cast::<u8>();
        if bytes.is_null() {
            return None;
        }
        Some(std::slice::from_raw_parts(bytes, length).to_vec())
    }
}

/// Writes `json` and `bytes` into `dictionary` under [`JSON_KEY`] and [`BYTES_KEY`].
///
/// # Safety
///
/// `dictionary` must be a live, mutable XPC dictionary.
unsafe fn fill(dictionary: Xpc, json: &[u8], bytes: Option<&[u8]>) {
    let set = |key: &str, data: &[u8]| {
        // The keys are constants without NUL bytes.
        if let Ok(key) = CString::new(key) {
            // SAFETY: `dictionary` is live and mutable; the call copies `data`.
            unsafe { xpc_dictionary_set_data(dictionary, key.as_ptr(), data.as_ptr().cast(), data.len()) };
        }
    };
    set(JSON_KEY, json);
    if let Some(bytes) = bytes {
        set(BYTES_KEY, bytes);
    }
}

/// Whether `object` is of the XPC type at `kind`.
///
/// # Safety
///
/// `object` must be a live XPC object.
unsafe fn is_type(object: Xpc, kind: *const u8) -> bool {
    // SAFETY: guaranteed by the caller.
    std::ptr::eq(unsafe { xpc_get_type(object) }.cast(), kind)
}

/// An event handler as Rust sees it.
struct Callback(Box<dyn Fn(Xpc) + Send + Sync>);

impl Callback {
    fn new(body: impl Fn(Xpc) + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self(Box::new(body)))
    }
}

/// Sets `callback` as `connection`'s event handler: XPC copies the stack block, and the copy keeps `callback` alive.
///
/// # Safety
///
/// `connection` must be a live connection that is not resumed yet.
unsafe fn set_event_handler(connection: Xpc, callback: &Arc<Callback>) {
    let block = EventBlock::on_stack(callback);
    // SAFETY: `block` is a valid stack block that outlives the call; XPC copies it (taking a count through
    // `event_copy`) before relying on it after returning.
    unsafe { xpc_connection_set_event_handler(connection, (&raw const block).cast()) };
}

// Block flags from `Block_private.h`.
/// The descriptor has copy and dispose helpers.
const BLOCK_HAS_COPY_DISPOSE: c_int = 1 << 25;
/// The descriptor has a type signature.
const BLOCK_HAS_SIGNATURE: c_int = 1 << 30;

/// The block's type encoding, `void (^)(xpc_object_t)`.
const SIGNATURE: &CStr = c"v16@?0@8";

/// The block descriptor: `Block_descriptor_1`, `_2` (copy and dispose) and `_3` (signature and layout) in a row.
#[repr(C)]
struct BlockDescriptor {
    reserved: c_ulong,
    size: c_ulong,
    copy: unsafe extern "C" fn(*mut EventBlock, *const EventBlock),
    dispose: unsafe extern "C" fn(*const EventBlock),
    signature: *const c_char,
    /// Extended layout; unused because `BLOCK_HAS_EXTENDED_LAYOUT` is not set.
    layout: *const c_char,
}

// SAFETY: the descriptor is immutable and its pointers are to `'static` data.
unsafe impl Sync for BlockDescriptor {}

static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
    reserved: 0,
    size: size_of::<EventBlock>() as c_ulong,
    copy: event_copy,
    dispose: event_dispose,
    signature: SIGNATURE.as_ptr(),
    layout: std::ptr::null(),
};

/// A block literal of type `void (^)(xpc_object_t)` that captures one pointer to a [`Callback`].
#[repr(C)]
struct EventBlock {
    isa: *const c_void,
    flags: c_int,
    reserved: c_int,
    invoke: unsafe extern "C" fn(*mut EventBlock, Xpc),
    descriptor: *const BlockDescriptor,
    /// The captured variable. The stack block borrows the caller's `Arc` without a count of its own; every heap copy
    /// owns one count (taken by [`event_copy`], dropped by [`event_dispose`]).
    callback: *const Callback,
}

impl EventBlock {
    /// A stack block calling `callback`. It must not outlive `callback`'s `Arc`; heap copies may.
    fn on_stack(callback: &Arc<Callback>) -> Self {
        Self {
            // Only the address of the extern static is taken, never its contents.
            isa: (&raw const _NSConcreteStackBlock).cast(),
            flags: BLOCK_HAS_COPY_DISPOSE | BLOCK_HAS_SIGNATURE,
            reserved: 0,
            invoke: event_invoke,
            descriptor: &raw const DESCRIPTOR,
            callback: Arc::as_ptr(callback),
        }
    }
}

/// The block's body: runs the callback with the event.
///
/// # Safety
///
/// `block` must point to a live [`EventBlock`] whose callback is alive (true for every heap copy until disposed).
unsafe extern "C" fn event_invoke(block: *mut EventBlock, event: Xpc) {
    // SAFETY: guaranteed by the caller.
    let callback = unsafe { &*(*block).callback };
    // Unwinding out of an `extern "C"` function aborts; the callbacks catch their own panics, and this is a backstop.
    let _ = catch_unwind(AssertUnwindSafe(|| (callback.0)(event)));
}

/// The copy helper `_Block_copy` calls after copying the block's bytes to the heap: the copy takes its own count.
///
/// # Safety
///
/// `src` must point to a live [`EventBlock`] whose callback comes from a live `Arc`.
unsafe extern "C" fn event_copy(_dst: *mut EventBlock, src: *const EventBlock) {
    // SAFETY: `(*src).callback` came from `Arc::as_ptr` on an `Arc` that is alive.
    unsafe { Arc::increment_strong_count((*src).callback) };
}

/// The dispose helper `_Block_release` calls before freeing a heap copy: drops the count the copy owned.
///
/// # Safety
///
/// `block` must be a heap copy made by `_Block_copy`; called once per copy.
unsafe extern "C" fn event_dispose(block: *const EventBlock) {
    // SAFETY: the count being dropped is the one `event_copy` took for this copy.
    unsafe { Arc::decrement_strong_count((*block).callback) };
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;
    use crate::control::{BundleVersion, SigningIdentifier, TeamId, TrustedAuthority, peer_requirement};
    use crate::testing::FakeCodeSigning;

    // A null Core Foundation result is `None` and never released: `CFRelease(NULL)` traps.
    #[test]
    fn null_cf_is_none_and_never_released() {
        assert!(Cf::new(std::ptr::null()).is_none());
    }

    // Anonymous listeners and in-process clients: the real service needs launchd, these do not.
    unsafe extern "C" {
        static _xpc_error_connection_interrupted: u8;
        static _xpc_error_connection_invalid: u8;
        fn xpc_connection_create(name: *const c_char, queue: Queue) -> Xpc;
        fn xpc_endpoint_create(connection: Xpc) -> Xpc;
        fn xpc_connection_create_from_endpoint(endpoint: Xpc) -> Xpc;
        fn xpc_connection_send_message_with_reply_sync(connection: Xpc, message: Xpc) -> Xpc;
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecCodeCopySelf(flags: u32, code: *mut CfRef) -> i32;
    }

    /// Everything the handler saw.
    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        Opened,
        Message,
        Closed,
        Refused(PeerRejection),
    }

    struct Recording(Mutex<mpsc::Sender<Seen>>);

    impl Recording {
        fn new() -> (Arc<Self>, mpsc::Receiver<Seen>) {
            let (sender, receiver) = mpsc::channel();
            (Arc::new(Self(Mutex::new(sender))), receiver)
        }

        fn see(&self, seen: Seen) {
            let _ = self.0.lock().unwrap().send(seen);
        }
    }

    impl ControlHandler for Recording {
        fn opened(&self, _: ConnectionId, _: Arc<dyn ControlPeer>) {
            self.see(Seen::Opened);
        }

        fn message(&self, _: ConnectionId, _: &[u8], reply: &dyn ControlPeer) -> AfterMessage {
            self.see(Seen::Message);
            let _ = reply.send(b"{}", None);
            AfterMessage::KeepOpen
        }

        fn closed(&self, _: ConnectionId) {
            self.see(Seen::Closed);
        }

        fn refused(&self, reason: PeerRejection) {
            self.see(Seen::Refused(reason));
        }
    }

    fn trusted() -> TrustedAuthority {
        TrustedAuthority {
            team_id: TeamId::new("ABCDE12345").unwrap(),
            identifier: SigningIdentifier::new("com.example.authority").unwrap(),
            min_version: BundleVersion::parse("1.0").unwrap(),
        }
    }

    /// A service on an anonymous listener, and a client connection to it from this process.
    fn connect(gate: PeerGate, handler: Arc<dyn ControlHandler>) -> (XpcControlService, Xpc) {
        // SAFETY: a null name makes an anonymous listener on `queue`.
        let service = XpcControlService::start(gate, handler, |queue| unsafe {
            xpc_connection_create(std::ptr::null(), queue)
        })
        .unwrap();
        let client = client_of(&service);
        (service, client)
    }

    /// Like [`connect`], but XPC's peer requirement is `always` (which this ad-hoc test binary meets) and every
    /// message's sender is inspected by `signing`: the per-message gate (FR-AUTH-14) runs over real XPC.
    fn connect_checked(signing: Arc<FakeCodeSigning>, handler: Arc<dyn ControlHandler>) -> (XpcControlService, Xpc) {
        let signing: Arc<dyn CodeSigning<XpcMessage>> = signing;
        let gate = PeerGate::new(Some(trusted()));
        let trust = Trust::with(gate, Some("always"), Some(signing)).unwrap();
        // SAFETY: a null name makes an anonymous listener on `queue`.
        let service = XpcControlService::start_with(trust, handler, |queue| unsafe {
            xpc_connection_create(std::ptr::null(), queue)
        })
        .unwrap();
        let client = client_of(&service);
        (service, client)
    }

    /// A resumed client connection to `service`'s anonymous listener (+1, released by the test).
    fn client_of(service: &XpcControlService) -> Xpc {
        // SAFETY: the listener is live; the endpoint and client are +1 objects released by the test.
        unsafe {
            let endpoint = xpc_endpoint_create(service.listener);
            let client = xpc_connection_create_from_endpoint(endpoint);
            xpc_release(endpoint);
            let ignore = Callback::new(|_| {});
            set_event_handler(client, &ignore);
            xpc_connection_resume(client);
            client
        }
    }

    /// What KNSH-026 observed for an accepted Developer ID client: hardened runtime, valid, version 2.0.
    fn good_facts() -> SignatureFacts {
        SignatureFacts {
            requirement_met: true,
            signature_flags: 0x1_0000,
            status: 0x2201_1311,
            bundle_version: Some("2.0".to_owned()),
        }
    }

    /// The JSON of a reply dictionary, or `None` for an error object; releases the reply.
    fn reply_json(reply: Xpc) -> Option<Vec<u8>> {
        // SAFETY: `reply` is a live object returned by a synchronous send: a +1 dictionary, or a static error.
        unsafe {
            if !is_type(reply, &raw const _xpc_type_dictionary) {
                return None;
            }
            let json = request_payload(reply);
            xpc_release(reply);
            json
        }
    }

    /// Sends one well-formed control request and returns the reply object (+1; an error object is static).
    fn request(client: Xpc) -> Xpc {
        // SAFETY: a new dictionary, filled, sent and released; `client` is live.
        unsafe {
            let message = xpc_dictionary_create(std::ptr::null(), std::ptr::null(), 0);
            fill(
                message,
                br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{}}"#,
                None,
            );
            let reply = xpc_connection_send_message_with_reply_sync(client, message);
            xpc_release(message);
            reply
        }
    }

    fn is_connection_error(reply: Xpc) -> bool {
        let reply = reply.cast_const().cast::<u8>();
        std::ptr::eq(reply, &raw const _xpc_error_connection_interrupted)
            || std::ptr::eq(reply, &raw const _xpc_error_connection_invalid)
    }

    fn drain(seen: &mpsc::Receiver<Seen>) -> Vec<Seen> {
        let mut all = Vec::new();
        while let Ok(one) = seen.recv_timeout(Duration::from_millis(300)) {
            all.push(one);
        }
        all
    }

    // FR-AUTH-12, AC "no trusted authority means every connection is refused": the connection is cancelled before
    // it is resumed, so the client sees the connection fail and the handler never sees a message.
    #[test]
    fn refuses_every_connection_without_a_trusted_authority() {
        let (handler, seen) = Recording::new();
        let (service, client) = connect(PeerGate::new(None), handler);
        let reply = request(client);
        assert!(is_connection_error(reply), "the client got an answer");
        assert_eq!(drain(&seen), [Seen::Refused(PeerRejection::NoTrustedAuthority)]);
        assert_eq!(service.open_connections(), 0);
        // SAFETY: the client this test created.
        unsafe { xpc_release(client) };
    }

    // FR-AUTH-13, AC "a connection that fails any check is dropped before any message is processed": this test binary
    // is ad hoc (linker) signed, so XPC refuses it against the requirement before the handler sees anything.
    #[test]
    fn drops_a_peer_that_fails_the_requirement_before_any_message() {
        let (handler, seen) = Recording::new();
        let (service, client) = connect(PeerGate::new(Some(trusted())), handler);
        let reply = request(client);
        assert!(is_connection_error(reply), "the client got an answer");
        let all = drain(&seen);
        assert!(!all.contains(&Seen::Message) && !all.contains(&Seen::Opened), "{all:?}");
        assert_eq!(all, [Seen::Refused(PeerRejection::RequirementNotMet)]);
        assert_eq!(service.open_connections(), 0);
        // SAFETY: the client this test created.
        unsafe { xpc_release(client) };
    }

    // FR-AUTH-14, AC "a connection that fails any check is dropped before any message is processed": a sender that
    // meets XPC's requirement but fails the per-message checks is cancelled before its message is read.
    #[test]
    fn drops_a_sender_that_fails_the_per_message_checks_before_reading() {
        let (handler, seen) = Recording::new();
        let no_runtime = SignatureFacts {
            signature_flags: 0,
            ..good_facts()
        };
        let signing = Arc::new(FakeCodeSigning::answering(Ok(no_runtime)));
        let (service, client) = connect_checked(Arc::clone(&signing), handler);
        assert_eq!(reply_json(request(client)), None, "the client got an answer");
        assert_eq!(drain(&seen), [Seen::Refused(PeerRejection::NoHardenedRuntime)]);
        assert_eq!(signing.calls(), 1);
        assert_eq!(service.open_connections(), 0);
        // SAFETY: the client this test created.
        unsafe { xpc_release(client) };
    }

    // FR-AUTH-14: a verified sender is served over XPC (the answer is the XPC reply, in `json`), and every later
    // message is checked again: once the sender no longer verifies (it exec'd), the connection is closed unanswered.
    #[test]
    fn serves_a_verified_sender_and_rechecks_every_message() {
        let (handler, seen) = Recording::new();
        let signing = Arc::new(FakeCodeSigning::answering(Ok(good_facts())));
        let (service, client) = connect_checked(Arc::clone(&signing), handler);
        assert_eq!(reply_json(request(client)).as_deref(), Some(&b"{}"[..]));
        assert_eq!(drain(&seen), [Seen::Opened, Seen::Message]);
        assert_eq!(service.open_connections(), 1);
        signing.set(Err(PlatformError::Security {
            operation: Operation::CodeSigning,
            status: -67065,
        }));
        assert_eq!(reply_json(request(client)), None, "the client got an answer");
        assert_eq!(drain(&seen), [Seen::Refused(PeerRejection::Unverifiable), Seen::Closed]);
        assert_eq!(signing.calls(), 2);
        assert_eq!(service.open_connections(), 0);
        // SAFETY: the client this test created.
        unsafe { xpc_release(client) };
    }

    // KNSH-068: trusting another authority ends every connection verified under the previous trust record, and its
    // later messages are never read; new connections are checked against the new record.
    #[test]
    fn a_new_trust_record_ends_connections_verified_under_the_old_one() {
        let (handler, seen) = Recording::new();
        let signing = Arc::new(FakeCodeSigning::answering(Ok(good_facts())));
        let (service, client) = connect_checked(Arc::clone(&signing), handler);
        assert_eq!(reply_json(request(client)).as_deref(), Some(&b"{}"[..]));
        assert_eq!(drain(&seen), [Seen::Opened, Seen::Message]);

        let replacement: Arc<dyn CodeSigning<XpcMessage>> = Arc::new(FakeCodeSigning::answering(Ok(good_facts())));
        let trust = Trust::with(PeerGate::new(Some(trusted())), Some("always"), Some(replacement)).unwrap();
        service.service.replace_trust(trust);
        assert_eq!(drain(&seen), [Seen::Closed]);
        assert_eq!(service.open_connections(), 0);
        // The client's next message reaches the service as a new peer connection (XPC reconnects an interrupted
        // client), opened and checked under the new record only.
        assert_eq!(reply_json(request(client)).as_deref(), Some(&b"{}"[..]));
        assert_eq!(drain(&seen), [Seen::Opened, Seen::Message]);
        assert_eq!(signing.calls(), 1, "nothing more was checked under the old record");
        // SAFETY: the client this test created.
        unsafe { xpc_release(client) };
    }

    // FR-AUTH-12, KNSH-068: trusting a first authority opens the service; until then every connection was refused.
    #[test]
    fn set_gate_compiles_and_rejects_nothing_new_without_trust() {
        let (handler, seen) = Recording::new();
        let (service, client) = connect(PeerGate::new(None), handler);
        assert!(is_connection_error(request(client)));
        assert_eq!(drain(&seen), [Seen::Refused(PeerRejection::NoTrustedAuthority)]);
        service.set_gate(PeerGate::new(Some(trusted()))).unwrap();
        // This ad-hoc test binary does not meet the real requirement: XPC now refuses it on that ground instead.
        let again = client_of(&service);
        assert!(is_connection_error(request(again)));
        assert_eq!(drain(&seen), [Seen::Refused(PeerRejection::RequirementNotMet)]);
        // SAFETY: the clients this test created.
        unsafe {
            xpc_release(client);
            xpc_release(again);
        }
    }

    // FR-AUTH-13: the built requirement is valid requirement language.
    #[test]
    fn compiles_the_peer_requirement() {
        assert!(SecCodeSigning::new(&peer_requirement(&trusted())).is_ok());
        assert!(matches!(
            SecCodeSigning::new("anchor apple generic and"),
            Err(PlatformError::Security {
                operation: Operation::CodeRequirement,
                ..
            })
        ));
    }

    // FR-AUTH-14: the facts read from a live code object. This test binary is ad hoc signed without the hardened
    // runtime and has no Info.plist: it fails the requirement, and the gate would refuse it for each reason.
    #[test]
    fn reads_signature_facts_of_live_code() {
        let mut code: CfRef = std::ptr::null();
        // SAFETY: `code` is a valid place for the +1 result.
        assert_eq!(
            unsafe { SecCodeCopySelf(SEC_CS_DEFAULT, &raw mut code) },
            ERR_SEC_SUCCESS
        );
        let code = Cf::new(code).unwrap();
        let signing = SecCodeSigning::new(&peer_requirement(&trusted())).unwrap();
        let facts = signing.facts_of(&code).unwrap();
        assert!(!facts.requirement_met);
        assert_eq!(facts.signature_flags & 0x2, 0x2, "ad hoc: {:#x}", facts.signature_flags);
        assert_eq!(facts.signature_flags & 0x1_0000, 0, "no hardened runtime");
        assert_eq!(
            facts.status & 0x1,
            0x1,
            "the live signature is valid: {:#x}",
            facts.status
        );
        assert_eq!(facts.bundle_version, None);
    }

    // The block layout matches the runtime's: `_Block_copy` takes a count, `_Block_release` drops it.
    #[test]
    fn event_block_survives_copy() {
        unsafe extern "C" {
            fn _Block_copy(block: *const c_void) -> *mut c_void;
            fn _Block_release(block: *const c_void);
        }
        let (sender, receiver) = mpsc::channel();
        let sender = Mutex::new(sender);
        let callback = Callback::new(move |event| sender.lock().unwrap().send(event as usize).unwrap());
        let copy = {
            let block = EventBlock::on_stack(&callback);
            // SAFETY: `block` is a valid stack block; the result is a heap copy owned by this test.
            unsafe { _Block_copy((&raw const block).cast()) }.cast::<EventBlock>()
        };
        assert_eq!(Arc::strong_count(&callback), 2);
        // SAFETY: `copy` is live until released below.
        unsafe { ((*copy).invoke)(copy, 42 as Xpc) };
        assert_eq!(receiver.recv().unwrap(), 42);
        // SAFETY: releases the only reference to the heap copy.
        unsafe { _Block_release(copy.cast()) };
        assert_eq!(Arc::strong_count(&callback), 1);
    }
}
