//! Who an `agent.sock` caller is: session tokens, the envelope registry and the audit-token fallback (KNSH-048).
//!
//! Every `agent.sock` connection is bound, at `hello`, to exactly one agent session, and every later call on it is
//! evaluated against that session only (`specs/02-architecture/endpoints.md`, FR-AGT-23). The binding is found in
//! this order:
//!
//! 1. **Session token.** Each agent session gets a token when it is opened; the supervisor puts it in the envelope's
//!    environment and clients send it in `hello` (`specs/05-models/session.md#session-token`). A token is
//!    [`TOKEN_BYTES`] bytes from the platform random source (at least 128 bits, NFR-SEC-02), sent as lowercase hex.
//!    It is compared in constant time ([`constant_time_eq`]) against every live token, and it is never logged,
//!    stored or recorded: [`SessionToken`] has no `Display`, its `Debug` is redacted, and the store never sees it.
//! 2. **Audit token.** Without a valid token, the caller is matched by the kernel's audit token for the connection:
//!    if its process descends from the root process of a registered envelope, it is bound to that envelope's
//!    session ([`envelope_of`]). The peer is named by pid *and* pid version ([`ProcessIdentity`]), never by a bare
//!    pid, and envelope roots and ancestors by pid and unique id ([`ProcessKey`]), which survives the `exec`s every
//!    root goes through (the pid version does not). A process that took over a dead envelope's pid is not inside
//!    it. The nearest envelope wins, so a nested envelope binds to its own session.
//! 3. **Neither:** `-32009`, and the connection is closed.
//!
//! When a session ends its token and envelopes are revoked at once ([`AgentAccess::revoke`]): a later `hello` with
//! the token falls back to the audit token (and, with the envelope gone, is refused), and a connection already
//! bound to it gets `-32009` on its next call.
//!
//! Nothing here creates sessions; `session.start_agent` (KNSH-056) and the supervisor (KNSH-050) open agent sessions
//! and register their envelopes through [`crate::sessions::Sessions`].
//!
//! # Locks
//!
//! One lock, [`AgentAccess`]'s table. It is never held while reading the process table: the envelope roots are
//! copied out first, so a slow `proc_pidinfo` never blocks another connection's `hello`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{Redacted, SessionId};
use knsh_platform::{AuditToken, PlatformError, ProcessIdentity, ProcessKey, ProcessTree, Random};
use knsh_proto::{ErrorCode, RpcError};

/// Bytes of randomness in a session token: 256 bits, twice the 128 the specification requires.
pub(crate) const TOKEN_BYTES: usize = 32;

// NFR-SEC-02: tokens are at least 128 bits. Checked when the crate is compiled, so it cannot be lowered silently.
const _: () = assert!(TOKEN_BYTES * 8 >= 128, "session tokens must carry at least 128 bits");

/// Most parents followed from a caller looking for its envelope. Real process trees are a few dozen deep; the
/// bound only keeps a corrupt or cyclic answer from looping.
const MAX_ANCESTRY_DEPTH: usize = 512;

/// An agent session's token. Only its holder and [`AgentAccess`] know it: it has no `Display`, its `Debug` prints
/// nothing of it, and it is compared only in constant time ([`SessionToken::matches`]).
#[derive(Clone)]
pub(crate) struct SessionToken([u8; TOKEN_BYTES]);

impl SessionToken {
    /// A fresh token from `random`, which must be the platform's secure generator outside tests.
    ///
    /// # Errors
    ///
    /// The [`PlatformError`] of a generator that failed: no token is better than a guessable one.
    pub(crate) fn generate(random: &dyn Random) -> Result<Self, PlatformError> {
        let mut bytes = [0; TOKEN_BYTES];
        random.fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// The token as it travels: lowercase hex, [`TOKEN_BYTES`] × 2 characters. Kept redacted, so the only way to
    /// print it is to [`Redacted::expose`] it, which only the code that writes the envelope's environment does.
    // The envelope's environment is written by `session.start_agent` (KNSH-056); until then only tests encode.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn encode(&self) -> Redacted<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(TOKEN_BYTES * 2);
        for byte in self.0 {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Redacted::new(text)
    }

    /// Reads a token sent by a client. Anything that is not exactly [`TOKEN_BYTES`] bytes of lowercase hex is not a
    /// token. Parsing looks only at the candidate, never at a live token, so its timing reveals nothing secret.
    pub(crate) fn decode(text: &str) -> Option<Self> {
        let text = text.as_bytes();
        if text.len() != TOKEN_BYTES * 2 {
            return None;
        }
        let mut bytes = [0; TOKEN_BYTES];
        let (pairs, _) = text.as_chunks::<2>();
        for (byte, pair) in bytes.iter_mut().zip(pairs) {
            *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Some(Self(bytes))
    }

    /// Whether `candidate` is this token, in time independent of where they differ (NFR-SEC-02).
    pub(crate) fn matches(&self, candidate: &Self) -> bool {
        constant_time_eq(&self.0, &candidate.0)
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

/// The value of one lowercase hex digit.
fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Whether `a` and `b` are equal, looking at every byte whatever the first difference, so the time taken says
/// nothing about how much of a guess was right. Lengths are compared first: they are not secret (tokens have one
/// fixed length).
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    differences(a.iter().copied().zip(b.iter().copied())) == 0
}

/// The OR of the XOR of every pair: zero exactly when all pairs are equal. It never stops early, and the result goes
/// through [`std::hint::black_box`] so the optimiser cannot turn the loop into an early-exit comparison.
fn differences(pairs: impl Iterator<Item = (u8, u8)>) -> u8 {
    let mut accumulated = 0u8;
    for (x, y) in pairs {
        accumulated |= std::hint::black_box(x ^ y);
    }
    std::hint::black_box(accumulated)
}

/// The right of one agent session to be served on `agent.sock`. Shared by the session's table entry and every
/// connection bound to it; revoked once, when the session ends.
#[derive(Debug)]
pub(crate) struct Grant {
    session_id: SessionId,
    revoked: AtomicBool,
}

impl Grant {
    fn new(session_id: SessionId) -> Arc<Self> {
        Arc::new(Self {
            session_id,
            revoked: AtomicBool::new(false),
        })
    }

    /// The session, while it is live; `-32009` once it has ended (FR-AGT-23: an expired token).
    pub(crate) fn session_id(&self) -> Result<SessionId, RpcError> {
        if self.revoked.load(Ordering::SeqCst) {
            return Err(invalid_session_token());
        }
        Ok(self.session_id)
    }
}

/// One live agent session's credentials.
struct Entry {
    token: SessionToken,
    grant: Arc<Grant>,
    /// Root processes of the session's envelopes, by unique id: a root stays the root across its `exec`s.
    envelopes: BTreeSet<ProcessKey>,
}

/// Every live agent session's token and envelopes. One per `knshd`, owned by [`crate::sessions::Sessions`].
pub(crate) struct AgentAccess {
    entries: Mutex<BTreeMap<SessionId, Entry>>,
    tree: Arc<dyn ProcessTree>,
}

impl AgentAccess {
    /// An empty table, matching callers to envelopes through `tree`.
    pub(crate) fn new(tree: Arc<dyn ProcessTree>) -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            tree,
        }
    }

    fn entries(&self) -> MutexGuard<'_, BTreeMap<SessionId, Entry>> {
        // Every update under this lock is one map operation that a panic cannot leave half done.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Issues the token of `session_id`, a newly opened agent session, replacing any earlier one.
    ///
    /// # Errors
    ///
    /// The [`PlatformError`] of a failed random source; nothing is registered then.
    pub(crate) fn issue(&self, session_id: SessionId, random: &dyn Random) -> Result<SessionToken, PlatformError> {
        let token = SessionToken::generate(random)?;
        let entry = Entry {
            token: token.clone(),
            grant: Grant::new(session_id),
            envelopes: BTreeSet::new(),
        };
        if let Some(earlier) = self.entries().insert(session_id, entry) {
            earlier.grant.revoked.store(true, Ordering::SeqCst);
        }
        Ok(token)
    }

    /// Registers `root`, the first process of an envelope of `session_id`: it and every process descending from it
    /// are bound to the session, even after `root` execs. Returns `false` if the session has no token (it is not a
    /// live agent session), or if `root` is no longer the live process at that pid version.
    pub(crate) fn register_envelope(&self, session_id: SessionId, root: ProcessIdentity) -> bool {
        // Resolved now, while the identity still names the process, and before the lock: the process table is
        // never read under it.
        let Ok(root) = self.tree.resolve(root) else {
            return false;
        };
        match self.entries().get_mut(&session_id) {
            Some(entry) => {
                entry.envelopes.insert(root);
                true
            }
            None => false,
        }
    }

    /// Revokes everything of `session_id`: it ended. Its token stops matching, its envelopes stop binding, and
    /// connections already bound to it get `-32009` from then on.
    pub(crate) fn revoke(&self, session_id: SessionId) {
        if let Some(entry) = self.entries().remove(&session_id) {
            entry.grant.revoked.store(true, Ordering::SeqCst);
        }
    }

    /// The session a `hello` on `agent.sock` binds to: by `token` if it is a live one, else by the `peer`'s audit
    /// token if the peer is inside an envelope.
    ///
    /// # Errors
    ///
    /// `-32009` if neither identifies a live agent session, including when the peer's audit token could not be read
    /// (`peer` is `None`) or its ancestry could not be followed.
    pub(crate) fn bind(
        &self,
        token: Option<&Redacted<String>>,
        peer: Option<AuditToken>,
    ) -> Result<Arc<Grant>, RpcError> {
        let grant = token
            .and_then(|token| self.by_token(token.expose()))
            .or_else(|| peer.and_then(|peer| self.by_ancestry(peer.process())))
            .ok_or_else(invalid_session_token)?;
        // Ended while it was being looked up: refused like any expired token.
        grant.session_id()?;
        Ok(grant)
    }

    /// The live session whose token is `candidate`. Every live token is compared, each in constant time, so the
    /// time taken does not depend on the candidate's bytes or on which token (if any) it matches.
    fn by_token(&self, candidate: &str) -> Option<Arc<Grant>> {
        let candidate = SessionToken::decode(candidate)?;
        let mut found = None;
        // No `find` or `break`: stopping at the match would make the time taken reveal which entry matched.
        for entry in self.entries().values() {
            if entry.token.matches(&candidate) {
                found = Some(Arc::clone(&entry.grant));
            }
        }
        found
    }

    /// The session of the nearest envelope `peer` runs in, if any.
    fn by_ancestry(&self, peer: ProcessIdentity) -> Option<Arc<Grant>> {
        // Copied out so the lock is not held while the process table is read.
        let roots: BTreeMap<ProcessKey, Arc<Grant>> = self
            .entries()
            .values()
            .flat_map(|entry| entry.envelopes.iter().map(|root| (*root, Arc::clone(&entry.grant))))
            .collect();
        if roots.is_empty() {
            return None;
        }
        envelope_of(self.tree.as_ref(), peer, &roots).cloned()
    }
}

/// The value of the nearest root in `roots` that `peer` is, or descends from, walking up `tree` one parent at a
/// time. Pure apart from `tree`.
///
/// Fails closed: a peer that is no longer the process its audit token named (it exited, or exec'd since it
/// connected), a process that cannot be read, a parent that changed during the walk, or a walk longer than
/// [`MAX_ANCESTRY_DEPTH`] all mean "not in an envelope". A process re-parented to `launchd` (its parent exited) is
/// outside its envelope from then on.
pub(crate) fn envelope_of<'a, T>(
    tree: &dyn ProcessTree,
    peer: ProcessIdentity,
    roots: &'a BTreeMap<ProcessKey, T>,
) -> Option<&'a T> {
    // The peer's version is checked here, against the live process, in the same read as its unique id.
    let mut current = tree.resolve(peer).ok()?;
    for _ in 0..MAX_ANCESTRY_DEPTH {
        // Matched on pid and unique id together: a reused pid has another unique id and never matches.
        if let Some(found) = roots.get(&current) {
            return Some(found);
        }
        match tree.parent(current) {
            Ok(Some(parent)) => current = parent,
            Ok(None) | Err(_) => return None,
        }
    }
    None
}

/// `-32009`: no live session for this caller (`specs/06-api/errors.md`). No `data`: a caller learns nothing about
/// which check failed.
pub(crate) fn invalid_session_token() -> RpcError {
    RpcError::new(ErrorCode::InvalidSessionToken)
}

#[cfg(test)]
pub(crate) mod endpoint_tests;
#[cfg(test)]
mod platform_tests;

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use knsh_core::Ulid;
    use knsh_platform::testing::{FakeProcessTree, SeededRandom};

    use super::*;

    fn sid(n: u8) -> SessionId {
        let mut random = [0; 10];
        random[9] = n;
        SessionId::from_ulid(Ulid::new(1, random).unwrap())
    }

    fn pid(pid: i32) -> ProcessIdentity {
        ProcessIdentity::new(pid, 1)
    }

    /// launchd (1) → terminal (100) → envelope root (200) → agent (201) → tool (202); and an outsider (300).
    fn tree() -> Arc<FakeProcessTree> {
        let tree = Arc::new(FakeProcessTree::new());
        tree.spawn(pid(1), None);
        tree.spawn(pid(100), Some(pid(1)));
        tree.spawn(pid(200), Some(pid(100)));
        tree.spawn(pid(201), Some(pid(200)));
        tree.spawn(pid(202), Some(pid(201)));
        tree.spawn(pid(300), Some(pid(100)));
        tree
    }

    // Always `Some`: the shape `AgentAccess::bind` takes, so call sites read as a peer the kernel reported.
    #[allow(clippy::unnecessary_wraps)]
    fn peer(process: ProcessIdentity) -> Option<AuditToken> {
        Some(AuditToken::for_process(process, 501))
    }

    // NFR-SEC-02: the comparison looks at every byte whatever the first difference: a structural test on the
    // helper, counting the pairs it consumes.
    #[test]
    fn token_comparison_is_constant_time() {
        struct Counting<I> {
            inner: I,
            taken: Rc<Cell<usize>>,
        }
        impl<I: Iterator> Iterator for Counting<I> {
            type Item = I::Item;
            fn next(&mut self) -> Option<I::Item> {
                let next = self.inner.next();
                if next.is_some() {
                    self.taken.set(self.taken.get() + 1);
                }
                next
            }
        }
        let secret = [7u8; TOKEN_BYTES];
        let mut first_differs = secret;
        first_differs[0] ^= 1;
        let mut last_differs = secret;
        last_differs[TOKEN_BYTES - 1] ^= 0x80;
        for (guess, equal) in [(secret, true), (first_differs, false), (last_differs, false)] {
            let taken = Rc::new(Cell::new(0));
            let pairs = Counting {
                inner: secret.iter().copied().zip(guess.iter().copied()),
                taken: Rc::clone(&taken),
            };
            assert_eq!(differences(pairs) == 0, equal);
            assert_eq!(
                taken.get(),
                TOKEN_BYTES,
                "every byte is compared, wherever the first difference is"
            );
            assert_eq!(constant_time_eq(&secret, &guess), equal);
        }
        assert!(!constant_time_eq(&secret, &secret[..TOKEN_BYTES - 1]));
    }

    // NFR-SEC-02: at least 128 bits from the random source, carried as hex that round-trips, and never printed.
    #[test]
    fn tokens_are_random_hex_and_never_printed() {
        let random = SeededRandom::new(9);
        let one = SessionToken::generate(&random).unwrap();
        let two = SessionToken::generate(&random).unwrap();
        assert!(!one.matches(&two));
        let text = one.encode();
        assert_eq!(text.expose().len(), TOKEN_BYTES * 2);
        assert!(
            text.expose()
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert!(SessionToken::decode(text.expose()).unwrap().matches(&one));
        assert_eq!(format!("{one:?}"), "SessionToken(<redacted>)");
        assert!(!format!("{text:?} {text}").contains(text.expose().as_str()));
        for bad in ["", "00", &text.expose().to_uppercase(), &format!("{}0", text.expose())] {
            assert!(SessionToken::decode(bad).is_none(), "{bad}");
        }
    }

    // FR-AGT-23: a live token binds to its session, whatever the peer.
    #[test]
    fn binds_by_valid_token() {
        let access = AgentAccess::new(tree());
        let token = access.issue(sid(1), &SeededRandom::new(1)).unwrap();
        access.issue(sid(2), &SeededRandom::new(2)).unwrap();
        let grant = access.bind(Some(&token.encode()), None).unwrap();
        assert_eq!(grant.session_id().unwrap(), sid(1));
        // The outsider holds the token: the token decides.
        let grant = access.bind(Some(&token.encode()), peer(pid(300))).unwrap();
        assert_eq!(grant.session_id().unwrap(), sid(1));
    }

    // FR-AGT-23: without a valid token, a descendant of a registered envelope (or its root) is bound by audit token;
    // anything else is -32009.
    #[test]
    fn falls_back_to_the_envelope_of_the_audit_token() {
        let access = AgentAccess::new(tree());
        access.issue(sid(1), &SeededRandom::new(1)).unwrap();
        assert!(access.register_envelope(sid(1), pid(200)));
        let wrong = Redacted::new("0".repeat(TOKEN_BYTES * 2));
        for (token, process) in [(None, pid(202)), (Some(&wrong), pid(201)), (None, pid(200))] {
            let grant = access.bind(token, peer(process)).unwrap();
            assert_eq!(grant.session_id().unwrap(), sid(1), "{process}");
        }
        for process in [pid(300), pid(100), pid(1), pid(999)] {
            let error = access.bind(None, peer(process)).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidSessionToken, "{process}");
        }
        // No audit token at all: only a token can bind.
        assert_eq!(
            access.bind(None, None).unwrap_err().code,
            ErrorCode::InvalidSessionToken
        );
        // A session that is not live cannot have envelopes.
        assert!(!access.register_envelope(sid(7), pid(300)));
    }

    // PID reuse: the envelope root exits and its pid goes to an unrelated process, which is not inside the envelope;
    // nor is a child of the dead root, whose walk can no longer pass through it.
    #[test]
    fn reused_pid_is_not_in_the_envelope() {
        let tree = tree();
        let access = AgentAccess::new(tree.clone());
        access.issue(sid(1), &SeededRandom::new(1)).unwrap();
        access.register_envelope(sid(1), pid(200));
        tree.exit(pid(200));
        let impostor = ProcessIdentity::new(200, 2);
        tree.spawn(impostor, Some(pid(100)));
        assert!(access.bind(None, peer(impostor)).is_err());
        assert!(access.bind(None, peer(pid(202))).is_err());
    }

    // KNSH-048: `exec` gives a process a new pid version. A root that execs after it was registered (every root does,
    // through `knsh-exec`) is still its envelope's root, and a descendant that execs is still inside; an audit token
    // taken before the peer exec'd names an image that is gone, and is refused.
    #[test]
    fn envelope_survives_exec_of_root_and_peer() {
        let tree = tree();
        let access = AgentAccess::new(tree.clone());
        access.issue(sid(1), &SeededRandom::new(1)).unwrap();
        assert!(access.register_envelope(sid(1), pid(200)));
        let root = tree.exec(pid(200)).unwrap();
        let root = tree.exec(root).unwrap();
        assert_eq!(access.bind(None, peer(root)).unwrap().session_id().unwrap(), sid(1));
        assert_eq!(access.bind(None, peer(pid(202))).unwrap().session_id().unwrap(), sid(1));
        let tool = tree.exec(pid(202)).unwrap();
        assert_eq!(access.bind(None, peer(tool)).unwrap().session_id().unwrap(), sid(1));
        assert!(access.bind(None, peer(pid(202))).is_err(), "stale audit token");
        // A stale identity cannot be registered as a root.
        access.issue(sid(2), &SeededRandom::new(2)).unwrap();
        assert!(!access.register_envelope(sid(2), pid(202)));
    }

    // Nested envelopes: the nearest one decides.
    #[test]
    fn nearest_envelope_wins() {
        let access = AgentAccess::new(tree());
        access.issue(sid(1), &SeededRandom::new(1)).unwrap();
        access.issue(sid(2), &SeededRandom::new(2)).unwrap();
        access.register_envelope(sid(1), pid(200));
        access.register_envelope(sid(2), pid(201));
        assert_eq!(access.bind(None, peer(pid(202))).unwrap().session_id().unwrap(), sid(2));
        assert_eq!(access.bind(None, peer(pid(200))).unwrap().session_id().unwrap(), sid(1));
    }

    // FR-AGT-23: once its session ends a token yields -32009, its envelope binds nothing, and a grant already held by
    // a connection is revoked.
    #[test]
    fn revoked_session_binds_nothing() {
        let access = AgentAccess::new(tree());
        let token = access.issue(sid(1), &SeededRandom::new(1)).unwrap();
        access.register_envelope(sid(1), pid(200));
        let held = access.bind(Some(&token.encode()), None).unwrap();
        access.revoke(sid(1));
        assert_eq!(held.session_id().unwrap_err().code, ErrorCode::InvalidSessionToken);
        for peer in [None, peer(pid(201))] {
            let error = access.bind(Some(&token.encode()), peer).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidSessionToken);
        }
    }

    // A walk that cannot finish (a cycle the kernel would never report) is bounded and fails closed.
    #[test]
    fn cyclic_ancestry_is_bounded() {
        /// Processes 10 and 11, each the other's parent.
        struct Cycle;
        impl ProcessTree for Cycle {
            fn identity(&self, pid: i32) -> Result<ProcessIdentity, PlatformError> {
                Ok(ProcessIdentity::new(pid, 1))
            }
            fn resolve(&self, process: ProcessIdentity) -> Result<ProcessKey, PlatformError> {
                Ok(ProcessKey::new(process.pid(), 1))
            }
            fn parent(&self, child: ProcessKey) -> Result<Option<ProcessKey>, PlatformError> {
                Ok(Some(ProcessKey::new(21 - child.pid(), 1)))
            }
        }
        let roots: BTreeMap<ProcessKey, u8> = [(ProcessKey::new(99, 1), 1)].into_iter().collect();
        assert_eq!(envelope_of(&Cycle, pid(10), &roots), None);
    }
}
