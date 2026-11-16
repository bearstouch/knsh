//! Touch ID or password through `LocalAuthentication`, from `knshd` itself (KNSH-064, NFR-SEC-04, FR-AUTH-41).
//!
//! Hand-written Objective-C runtime calls, no third-party crate and no Swift helper: per prompt, a new `LAContext`
//! evaluates `LAPolicyDeviceOwnerAuthentication` (Touch ID, with the user's password as fallback) with the reason
//! text, and its reply block reports the answer to the waiting thread.
//!
//! Observed in KNSH-026 (claim C6, decision 12): a launchd agent shows the prompt, titled with the process name, and
//! the dialog reached the console even from a job without graphics access. So "no usable session" cannot be learnt
//! from an error, and every outcome other than success refuses, including no answer within the timeout, at which
//! point the context is invalidated so the prompt is withdrawn.
//!
//! Nothing can skip the prompt (FR-AUTH-42): the context is new for every call (no earlier success is reused),
//! `touchIDAuthenticationAllowableReuseDuration` is left at its default of zero, and `interactionNotAllowed` is never
//! set, so the system always asks.
//!
//! # The reply block
//!
//! `evaluatePolicy:localizedReason:reply:` takes an Objective-C block. [`ReplyBlock`] lays one out as clang does (the
//! block ABI in `Block_private.h`): it starts on the stack, the framework copies it to the heap (`_Block_copy`)
//! before returning, and calls the copy once, on a queue of its own, after the user answers. The block captures a
//! pointer to the shared [`Reply`]; its copy and dispose helpers take and drop one `Arc` count for each heap copy, so
//! the `Reply` lives exactly as long as anyone can still call the block, even after this thread stopped waiting.

use std::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use crate::presence::{Authenticated, NotAuthenticated, PromptReason, UserPresence};

/// An Objective-C object pointer (`id`).
type Id = *mut c_void;
/// A selector (`SEL`).
type Sel = *const c_void;

/// `LAPolicyDeviceOwnerAuthentication`: biometrics, with the account password as fallback.
const LA_POLICY_DEVICE_OWNER_AUTHENTICATION: isize = 2;

// `LAError` codes from `<LocalAuthentication/LAError.h>`.
const LA_ERROR_AUTHENTICATION_FAILED: isize = -1;
const LA_ERROR_USER_CANCEL: isize = -2;
const LA_ERROR_USER_FALLBACK: isize = -3;
const LA_ERROR_SYSTEM_CANCEL: isize = -4;
const LA_ERROR_PASSCODE_NOT_SET: isize = -5;
const LA_ERROR_BIOMETRY_NOT_AVAILABLE: isize = -6;
const LA_ERROR_BIOMETRY_NOT_ENROLLED: isize = -7;
const LA_ERROR_BIOMETRY_LOCKOUT: isize = -8;
const LA_ERROR_APP_CANCEL: isize = -9;
const LA_ERROR_INVALID_CONTEXT: isize = -10;
const LA_ERROR_NOT_INTERACTIVE: isize = -1004;

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    /// Declared without a signature: every call site casts it to the method's real C signature first.
    fn objc_msgSend();
    fn objc_autoreleasePoolPush() -> *mut c_void;
    fn objc_autoreleasePoolPop(pool: *mut c_void);
}

#[link(name = "LocalAuthentication", kind = "framework")]
unsafe extern "C" {
    /// `NSString *const LAErrorDomain`. Referencing it also makes sure the framework is linked, so `LAContext` is
    /// registered with the runtime.
    static LAErrorDomain: Id;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        is_external: u8,
    ) -> Id;
}

// The block runtime (libclosure) is part of libSystem.
unsafe extern "C" {
    /// The class of blocks that live on the stack. Declared as `void *[32]` in `<Block.h>`; only its address is used.
    static _NSConcreteStackBlock: [*const c_void; 32];
}

/// Shows the system authentication prompt through `LocalAuthentication`. Stateless: every call creates its own
/// context, so prompts never share state and calls from several threads are independent.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalAuthentication;

impl LocalAuthentication {
    /// The backend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl UserPresence for LocalAuthentication {
    fn authenticate(&self, reason: &PromptReason, timeout: Duration) -> Result<Authenticated, NotAuthenticated> {
        // No time to answer: refuse without flashing a prompt that is withdrawn at once.
        if timeout.is_zero() {
            return Err(NotAuthenticated::TimedOut);
        }
        // Objects the framework autoreleases on this thread are freed when the pool drops, after everything below.
        let _pool = AutoreleasePool::push();
        let context = new_context().ok_or(NotAuthenticated::Unavailable)?;
        let text = ns_string(reason.as_str()).ok_or(NotAuthenticated::Unavailable)?;

        let reply = Arc::new(Reply::default());
        let block = ReplyBlock::on_stack(&reply);
        // SAFETY: `context` is a live `LAContext` and `text` a live `NSString`. The method's C signature is
        // `void (id, SEL, NSInteger, NSString *, void (^)(BOOL, NSError *))`. `block` is a valid stack block that
        // outlives the call; the framework copies it (taking an `Arc` count through `reply_copy`) before relying on
        // it after returning.
        unsafe {
            let send: unsafe extern "C" fn(Id, Sel, isize, Id, *const ReplyBlock) = msg_send_fn();
            send(
                context.0,
                selector(c"evaluatePolicy:localizedReason:reply:"),
                LA_POLICY_DEVICE_OWNER_AUTHENTICATION,
                text.0,
                &raw const block,
            );
        }

        if let Some(outcome) = reply.wait(timeout) {
            return outcome.map(|()| Authenticated::new());
        }
        // Decision 12: no answer by the timeout refuses, and the prompt is withdrawn. An answer racing with this call
        // lands in `reply` after the decision was made and is ignored.
        // SAFETY: `context` is a live `LAContext`; `invalidate` takes no arguments and returns nothing.
        unsafe { send_void(context.0, selector(c"invalidate")) };
        Err(NotAuthenticated::TimedOut)
    }
}

/// The answer the reply block reports: success, or why not.
type Outcome = Result<(), NotAuthenticated>;

/// The answer, shared between the waiting thread and the reply block.
#[derive(Debug, Default)]
struct Reply {
    /// The first answer reported. Later reports are ignored, so a misbehaving framework cannot turn a refusal into a
    /// success.
    outcome: Mutex<Option<Outcome>>,
    answered: Condvar,
}

impl Reply {
    /// Records `outcome` unless an answer is already in, and wakes the waiting thread.
    fn answer(&self, outcome: Outcome) {
        let mut slot = self.outcome.lock().unwrap_or_else(PoisonError::into_inner);
        slot.get_or_insert(outcome);
        self.answered.notify_all();
    }

    /// The answer, waiting up to `timeout` for it. `None` if nobody answered in time.
    fn wait(&self, timeout: Duration) -> Option<Outcome> {
        let slot = self.outcome.lock().unwrap_or_else(PoisonError::into_inner);
        // `wait_timeout_while` copes with spurious wake-ups and with very long timeouts (it clamps them).
        let (slot, _) = self
            .answered
            .wait_timeout_while(slot, timeout, |outcome| outcome.is_none())
            .unwrap_or_else(PoisonError::into_inner);
        *slot
    }
}

// Block flags from `Block_private.h`.
/// The descriptor has copy and dispose helpers.
const BLOCK_HAS_COPY_DISPOSE: c_int = 1 << 25;
/// The descriptor has a type signature.
const BLOCK_HAS_SIGNATURE: c_int = 1 << 30;

/// The block's type encoding, `void (^)(BOOL, NSError *)`, as clang writes it. `BOOL` is `bool` (`B`) on Apple
/// silicon and `signed char` (`c`) on Intel.
#[cfg(target_arch = "aarch64")]
const SIGNATURE: &CStr = c"v20@?0B8@\"NSError\"12";
#[cfg(not(target_arch = "aarch64"))]
const SIGNATURE: &CStr = c"v20@?0c8@\"NSError\"12";

/// The block descriptor: `Block_descriptor_1`, `_2` (copy and dispose) and `_3` (signature and layout) in a row.
#[repr(C)]
struct BlockDescriptor {
    reserved: c_ulong,
    size: c_ulong,
    copy: unsafe extern "C" fn(*mut ReplyBlock, *const ReplyBlock),
    dispose: unsafe extern "C" fn(*const ReplyBlock),
    signature: *const c_char,
    /// Extended layout; unused because `BLOCK_HAS_EXTENDED_LAYOUT` is not set.
    layout: *const c_char,
}

// SAFETY: the descriptor is immutable and its pointers are to `'static` data, so sharing it between threads is sound.
unsafe impl Sync for BlockDescriptor {}

static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
    reserved: 0,
    size: size_of::<ReplyBlock>() as c_ulong,
    copy: reply_copy,
    dispose: reply_dispose,
    signature: SIGNATURE.as_ptr(),
    layout: std::ptr::null(),
};

/// A block literal of type `void (^)(BOOL, NSError *)` that captures one pointer to a [`Reply`].
#[repr(C)]
struct ReplyBlock {
    isa: *const c_void,
    flags: c_int,
    reserved: c_int,
    invoke: unsafe extern "C" fn(*mut ReplyBlock, u8, Id),
    descriptor: *const BlockDescriptor,
    /// The captured variable. The stack block borrows the caller's `Arc` without a count of its own; every heap copy
    /// owns one count (taken by [`reply_copy`], dropped by [`reply_dispose`]).
    reply: *const Reply,
}

impl ReplyBlock {
    /// A stack block reporting to `reply`. It must not outlive `reply`'s `Arc`; copies made with `_Block_copy` may.
    fn on_stack(reply: &Arc<Reply>) -> Self {
        Self {
            // Only the address of the extern static is taken (safe), never its contents.
            isa: (&raw const _NSConcreteStackBlock).cast(),
            flags: BLOCK_HAS_COPY_DISPOSE | BLOCK_HAS_SIGNATURE,
            reserved: 0,
            invoke: reply_invoke,
            descriptor: &raw const DESCRIPTOR,
            reply: Arc::as_ptr(reply),
        }
    }
}

/// The block's body: records success, or the refusal the error names.
///
/// # Safety
///
/// `block` must point to a live [`ReplyBlock`] whose `reply` is alive (true for the stack block while its `Arc` lives
/// and for every heap copy until it is disposed). `error` must be null or a live `NSError`.
unsafe extern "C" fn reply_invoke(block: *mut ReplyBlock, success: u8, error: Id) {
    // SAFETY: guaranteed by the caller, as documented above.
    let reply = unsafe { &*(*block).reply };
    let outcome = if success == 0 {
        // SAFETY: `error` is null or a live `NSError`, as the caller guarantees.
        Err(unsafe { refusal_from(error) })
    } else {
        Ok(())
    };
    reply.answer(outcome);
}

/// The copy helper `_Block_copy` calls after copying the block's bytes to the heap: the copy takes its own count.
///
/// # Safety
///
/// `src` must point to a live [`ReplyBlock`] whose `reply` comes from a live `Arc`.
unsafe extern "C" fn reply_copy(_dst: *mut ReplyBlock, src: *const ReplyBlock) {
    // SAFETY: `(*src).reply` came from `Arc::as_ptr` on an `Arc` that is alive (the caller's, or the count owned by
    // the heap block being copied).
    unsafe { Arc::increment_strong_count((*src).reply) };
}

/// The dispose helper `_Block_release` calls before freeing a heap copy: drops the count the copy owned.
///
/// # Safety
///
/// `block` must be a heap copy made by `_Block_copy`, which took a count in [`reply_copy`]; called once per copy.
unsafe extern "C" fn reply_dispose(block: *const ReplyBlock) {
    // SAFETY: the count being dropped is the one `reply_copy` took for this copy.
    unsafe { Arc::decrement_strong_count((*block).reply) };
}

/// The refusal an `NSError` from `evaluatePolicy` stands for. Unknown codes, other domains and a missing error all
/// refuse (fail closed).
///
/// # Safety
///
/// `error` must be null or a live `NSError`.
unsafe fn refusal_from(error: Id) -> NotAuthenticated {
    if error.is_null() {
        return NotAuthenticated::Error { code: 0 };
    }
    // SAFETY: `error` is a live `NSError`; `code` returns an `NSInteger` and `domain` an `NSString` that `error`
    // keeps alive for this call. `LAErrorDomain` is a constant string, and `isEqualToString:` returns a `BOOL`.
    let (code, in_la_domain) = unsafe {
        let send_code: unsafe extern "C" fn(Id, Sel) -> isize = msg_send_fn();
        let send_domain: unsafe extern "C" fn(Id, Sel) -> Id = msg_send_fn();
        let send_is_equal: unsafe extern "C" fn(Id, Sel, Id) -> u8 = msg_send_fn();
        let code = send_code(error, selector(c"code"));
        let domain = send_domain(error, selector(c"domain"));
        let in_la_domain =
            !domain.is_null() && send_is_equal(domain, selector(c"isEqualToString:"), LAErrorDomain) != 0;
        (code, in_la_domain)
    };
    if in_la_domain {
        refusal_for(code)
    } else {
        NotAuthenticated::Error { code: code as i64 }
    }
}

/// The refusal an `LAError` code stands for.
fn refusal_for(code: isize) -> NotAuthenticated {
    match code {
        // The fallback button is not offered for this policy (the password is the fallback); treat it as a cancel.
        LA_ERROR_USER_CANCEL | LA_ERROR_SYSTEM_CANCEL | LA_ERROR_APP_CANCEL | LA_ERROR_USER_FALLBACK => {
            NotAuthenticated::Cancelled
        }
        LA_ERROR_AUTHENTICATION_FAILED => NotAuthenticated::Failed,
        LA_ERROR_BIOMETRY_LOCKOUT => NotAuthenticated::Lockout,
        LA_ERROR_PASSCODE_NOT_SET
        | LA_ERROR_BIOMETRY_NOT_AVAILABLE
        | LA_ERROR_BIOMETRY_NOT_ENROLLED
        | LA_ERROR_INVALID_CONTEXT
        | LA_ERROR_NOT_INTERACTIVE => NotAuthenticated::Unavailable,
        other => NotAuthenticated::Error { code: other as i64 },
    }
}

/// An owned (+1) Objective-C object, released on drop.
struct Owned(Id);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live object this value owns one reference to; `release` gives it back.
        unsafe { send_void(self.0, selector(c"release")) };
    }
}

/// A new `LAContext`, or `None` if the class is missing or `init` fails.
fn new_context() -> Option<Owned> {
    // SAFETY: `objc_getClass` takes a NUL-terminated name and returns the class or null.
    let class = unsafe { objc_getClass(c"LAContext".as_ptr()) };
    if class.is_null() {
        return None;
    }
    // SAFETY: `class` is the `LAContext` class; `alloc` returns a +1 uninitialised instance and `init` consumes it,
    // returning an initialised +1 instance or nil. Both have the signature `id (id, SEL)`.
    let context = unsafe {
        let send: unsafe extern "C" fn(Id, Sel) -> Id = msg_send_fn();
        let allocated = send(class, selector(c"alloc"));
        if allocated.is_null() {
            return None;
        }
        send(allocated, selector(c"init"))
    };
    (!context.is_null()).then_some(Owned(context))
}

/// A new (+1) `NSString` holding `text`, or `None` if it cannot be made.
fn ns_string(text: &str) -> Option<Owned> {
    let length = isize::try_from(text.len()).ok()?;
    // SAFETY: `text` is valid UTF-8 of `length` bytes for the duration of the call, which copies it
    // (`is_external` false). A `CFString` is toll-free bridged with `NSString`, so `release` frees it.
    let string =
        unsafe { CFStringCreateWithBytes(std::ptr::null(), text.as_ptr(), length, K_CF_STRING_ENCODING_UTF8, 0) };
    (!string.is_null()).then_some(Owned(string))
}

/// An autorelease pool for the duration of one prompt, popped on drop.
struct AutoreleasePool(*mut c_void);

impl AutoreleasePool {
    fn push() -> Self {
        // SAFETY: no preconditions; the token is passed back to `objc_autoreleasePoolPop` exactly once, on drop.
        Self(unsafe { objc_autoreleasePoolPush() })
    }
}

impl Drop for AutoreleasePool {
    fn drop(&mut self) {
        // SAFETY: the token came from `objc_autoreleasePoolPush` on this thread (the guard is not `Send`), and pools
        // pushed after it were popped first, because guards drop in reverse order.
        unsafe { objc_autoreleasePoolPop(self.0) };
    }
}

/// The selector named `name`.
fn selector(name: &CStr) -> Sel {
    // SAFETY: `name` is NUL-terminated; `sel_registerName` returns the unique, never-freed selector for it.
    unsafe { sel_registerName(name.as_ptr()) }
}

/// `objc_msgSend` as a function of type `F`.
///
/// # Safety
///
/// `F` must be an `unsafe extern "C" fn` pointer type matching the C signature of the method it will send, with the
/// receiver and selector first. Calling it with the wrong signature is undefined behaviour.
unsafe fn msg_send_fn<F: Copy>() -> F {
    const { assert!(size_of::<F>() == size_of::<unsafe extern "C" fn()>()) };
    // SAFETY: `F` is a function pointer type of the same size (checked above); `objc_msgSend` is a trampoline that
    // forwards whatever arguments it is called with, so it may be called through any method's signature.
    unsafe { std::mem::transmute_copy::<unsafe extern "C" fn(), F>(&(objc_msgSend as unsafe extern "C" fn())) }
}

/// Sends a message with no arguments and no result.
///
/// # Safety
///
/// `receiver` must be a live object that responds to `selector` with the signature `void (id, SEL)`.
unsafe fn send_void(receiver: Id, selector: Sel) {
    // SAFETY: guaranteed by the caller.
    unsafe {
        let send: unsafe extern "C" fn(Id, Sel) = msg_send_fn();
        send(receiver, selector);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    // The block runtime's copy and release, as the framework calls them.
    unsafe extern "C" {
        fn _Block_copy(block: *const c_void) -> *mut c_void;
        fn _Block_release(block: *const c_void);
    }

    /// Calls `block`'s body as the framework does.
    unsafe fn call(block: *mut ReplyBlock, success: bool, error: Id) {
        // SAFETY: the caller passes a live block and a null or live error.
        unsafe { ((*block).invoke)(block, u8::from(success), error) };
    }

    /// An autoreleased `NSError` in `domain` with `code`.
    unsafe fn ns_error(domain: Id, code: isize) -> Id {
        // SAFETY: `+[NSError errorWithDomain:code:userInfo:]` has the signature `id (id, SEL, NSString *, NSInteger,
        // NSDictionary *)`; `domain` is a live string and the user info may be nil.
        unsafe {
            let class = objc_getClass(c"NSError".as_ptr());
            let send: unsafe extern "C" fn(Id, Sel, Id, isize, Id) -> Id = msg_send_fn();
            send(
                class,
                selector(c"errorWithDomain:code:userInfo:"),
                domain,
                code,
                std::ptr::null_mut(),
            )
        }
    }

    // The block layout matches the runtime's: `_Block_copy` copies it whole and takes a count through the copy
    // helper, the copy reports the answer, and `_Block_release` drops the count again.
    #[test]
    fn reply_block_survives_copy_and_reports_first_answer() {
        let reply = Arc::new(Reply::default());
        // The stack block goes out of scope straight after the copy, as it does in `authenticate`.
        let copy = {
            let block = ReplyBlock::on_stack(&reply);
            // SAFETY: `block` is a valid stack block; the result is a heap copy owned by this test.
            unsafe { _Block_copy((&raw const block).cast()) }.cast::<ReplyBlock>()
        };
        assert!(!copy.is_null());
        assert_eq!(Arc::strong_count(&reply), 2, "the heap copy owns a count");

        // SAFETY: `copy` is live until released below.
        unsafe {
            call(copy, true, std::ptr::null_mut());
            // A second call cannot change the first answer.
            call(copy, false, std::ptr::null_mut());
        }
        assert_eq!(reply.wait(Duration::ZERO), Some(Ok(())));

        // SAFETY: releases the only reference to the heap copy.
        unsafe { _Block_release(copy.cast()) };
        assert_eq!(Arc::strong_count(&reply), 1, "dispose dropped the copy's count");
    }

    // NFR-SEC-04: a cancelled prompt, reported by the framework as `LAErrorUserCancel`, refuses the action.
    #[test]
    fn refuses_action_when_authentication_cancelled() {
        let _pool = AutoreleasePool::push();
        let reply = Arc::new(Reply::default());
        let mut block = ReplyBlock::on_stack(&reply);
        // SAFETY: `LAErrorDomain` is a constant string; `block` is live and the error is autoreleased into `_pool`.
        unsafe { call(&raw mut block, false, ns_error(LAErrorDomain, LA_ERROR_USER_CANCEL)) };

        let mut performed = false;
        let outcome = reply.wait(Duration::ZERO).unwrap().map(|()| performed = true);
        assert_eq!(outcome, Err(NotAuthenticated::Cancelled));
        assert!(!performed, "the action ran without authentication");
    }

    // NFR-SEC-04, decision 12: every failure refuses; unknown codes and other domains keep their code.
    #[test]
    fn maps_every_error_to_a_refusal() {
        assert_eq!(refusal_for(LA_ERROR_SYSTEM_CANCEL), NotAuthenticated::Cancelled);
        assert_eq!(refusal_for(LA_ERROR_APP_CANCEL), NotAuthenticated::Cancelled);
        assert_eq!(refusal_for(LA_ERROR_USER_FALLBACK), NotAuthenticated::Cancelled);
        assert_eq!(refusal_for(LA_ERROR_AUTHENTICATION_FAILED), NotAuthenticated::Failed);
        assert_eq!(refusal_for(LA_ERROR_BIOMETRY_LOCKOUT), NotAuthenticated::Lockout);
        assert_eq!(refusal_for(LA_ERROR_NOT_INTERACTIVE), NotAuthenticated::Unavailable);
        assert_eq!(refusal_for(LA_ERROR_PASSCODE_NOT_SET), NotAuthenticated::Unavailable);
        assert_eq!(refusal_for(-42), NotAuthenticated::Error { code: -42 });

        let _pool = AutoreleasePool::push();
        let other_domain = ns_string("NSOSStatusErrorDomain").unwrap();
        // SAFETY: both errors are live (autoreleased into `_pool`); a null error is allowed.
        unsafe {
            assert_eq!(
                refusal_from(ns_error(LAErrorDomain, LA_ERROR_BIOMETRY_LOCKOUT)),
                NotAuthenticated::Lockout
            );
            assert_eq!(
                refusal_from(ns_error(other_domain.0, -2)),
                NotAuthenticated::Error { code: -2 }
            );
            assert_eq!(refusal_from(std::ptr::null_mut()), NotAuthenticated::Error { code: 0 });
        }
    }

    // Decision 12: nobody answered in time.
    #[test]
    fn unanswered_reply_times_out() {
        let reply = Reply::default();
        let started = Instant::now();
        assert_eq!(reply.wait(Duration::from_millis(20)), None);
        assert!(started.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    fn zero_timeout_refuses_without_a_prompt() {
        let reason = PromptReason::change("change the policy", "nothing");
        assert_eq!(
            LocalAuthentication::new().authenticate(&reason, Duration::ZERO),
            Err(NotAuthenticated::TimedOut)
        );
    }

    // The framework links and an `LAContext` can be made and released, without showing anything.
    #[test]
    fn creates_a_local_authentication_context() {
        let _pool = AutoreleasePool::push();
        assert!(new_context().is_some());
        assert!(ns_string("knshd is trying to approve").is_some());
    }

    // KNSH-064 integration check, pending (manual): needs a person at the Mac. Run with
    // `cargo test -p knsh-platform -- --ignored --nocapture shows_the_system_prompt`, then cancel, answer, or let it
    // time out, and compare the printed outcome with what you did.
    #[test]
    #[ignore = "manual: shows a Touch ID or password prompt and waits for a person"]
    fn shows_the_system_prompt() {
        let reason = PromptReason::change("approve a test prompt from knsh-platform", "echo \"hello\" (KNSH-064)");
        let outcome = LocalAuthentication::new().authenticate(&reason, Duration::from_secs(30));
        println!("outcome: {outcome:?}");
    }
}
