//! The exec handler, its deadline and its launch chain, with a scripted policy and a fake clock (KNSH-094).

use std::ffi::OsString;
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use knsh_core::{Caller, CanonicalPath, SessionId, Timestamp, Ulid};
use knsh_platform::testing::{FakeClock, ScriptedDescendantClients};
use knsh_platform::{Clock, DescendantClients, ExecEvent, ExecHandler, ExecVerdict, Monotonic};

use super::*;

pub(crate) const TRAMPOLINE: &str = "/opt/knsh/bin/knsh-exec";
pub(crate) const KNSH: &str = "/opt/knsh/bin/knsh";
pub(crate) const SHIMS: &str = "/Users/u/.knsh/shims";
pub(crate) const BASH: &str = "/bin/bash";
pub(crate) const CLI: &str = "/opt/agent/bin/agent";
const LEADER: i32 = 500;

pub(crate) fn session() -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(42))
}

fn path(text: &str) -> CanonicalPath {
    CanonicalPath::new(text).unwrap()
}

fn clock() -> Arc<FakeClock> {
    Arc::new(FakeClock::new(Timestamp::UNIX_EPOCH))
}

/// An exec of `argv` (`argv[0]` is the executable) by `pid` in group `group`, from `/Users/u/app`, due in 5 s.
pub(crate) fn event(clock: &dyn Clock, pid: i32, group: i32, argv: &[&str]) -> ExecEvent {
    ExecEvent {
        pid,
        group,
        executable: argv[0].into(),
        argv: argv.iter().map(OsString::from).collect(),
        cwd: Some("/Users/u/app".into()),
        path: Some(format!("{SHIMS}:/usr/bin:/bin").into()),
        deadline: clock.monotonic().checked_add(Duration::from_secs(5)).unwrap(),
    }
}

/// A policy that answers from a script and keeps every request it was asked.
#[derive(Default)]
struct ScriptedPolicy {
    asked: Mutex<Vec<ExecRequest>>,
    /// Claim and allow (`true`) or deny (`false`); allow once the script runs out.
    script: Mutex<Vec<bool>>,
}

impl ExecPolicy for ScriptedPolicy {
    fn decide_exec(&self, request: &ExecRequest, gate: &ExecGate) -> ExecVerdict {
        self.asked.lock().unwrap().push(request.clone());
        let allow = {
            let mut script = self.script.lock().unwrap();
            if script.is_empty() { true } else { script.remove(0) }
        };
        if allow && gate.claim_allow() {
            ExecVerdict::Allow
        } else {
            ExecVerdict::Deny
        }
    }
}

/// A policy that moves the clock past every deadline, then waits until the test releases it and allows if it still
/// can; it reports what its caller and its claim looked like at that point.
struct LatePolicy {
    clock: Arc<FakeClock>,
    release: Mutex<Receiver<()>>,
    seen: Mutex<Option<(bool, bool)>>,
}

impl ExecPolicy for LatePolicy {
    fn decide_exec(&self, _request: &ExecRequest, gate: &ExecGate) -> ExecVerdict {
        self.clock.advance(Duration::from_secs(60));
        let _ = self.release.lock().unwrap().recv();
        let gone = gate.gone();
        let claimed = gate.claim_allow();
        *self.seen.lock().unwrap() = Some((gone, claimed));
        if claimed { ExecVerdict::Allow } else { ExecVerdict::Deny }
    }
}

/// A policy that answers allow without claiming it.
struct UnclaimedAllow;

impl ExecPolicy for UnclaimedAllow {
    fn decide_exec(&self, _request: &ExecRequest, _gate: &ExecGate) -> ExecVerdict {
        ExecVerdict::Allow
    }
}

fn request() -> ExecRequest {
    ExecRequest {
        session_id: session(),
        command: "/usr/bin/git status".to_owned(),
        cwd: path("/Users/u/app"),
        path: "/usr/bin:/bin".to_owned(),
    }
}

fn due_in(clock: &dyn Clock, after: Duration) -> Monotonic {
    clock.monotonic().checked_add(after).unwrap()
}

/// The handler of one envelope over `policy`.
fn envelope(policy: Arc<dyn ExecPolicy>, clock: &Arc<FakeClock>) -> EnvelopeExecs {
    let authoriser = Arc::new(ExecAuthoriser::new(policy, Arc::clone(clock) as Arc<dyn Clock>));
    EnvelopeExecs::new(
        session(),
        authoriser,
        LaunchChain::new(path(TRAMPOLINE), path(SANDBOX_EXEC), path(BASH), path(CLI)),
        path(KNSH),
        SHIMS.into(),
    )
}

// KNSH-094: an allow claimed in time is the answer; a deny is a deny.
#[test]
fn answers_the_policy_verdict_in_time() {
    let clock = clock();
    let policy = Arc::new(ScriptedPolicy {
        script: Mutex::new(vec![true, false]),
        ..ScriptedPolicy::default()
    });
    let authoriser = ExecAuthoriser::new(policy.clone(), clock.clone());
    let deadline = due_in(clock.as_ref(), Duration::from_secs(5));
    assert_eq!(authoriser.authorise(request(), deadline), ExecVerdict::Allow);
    assert_eq!(authoriser.authorise(request(), deadline), ExecVerdict::Deny);
    assert_eq!(policy.asked.lock().unwrap().len(), 2);
}

// KNSH-094 (fail closed): a decision still running at the deadline is denied, and it sees its caller gone, so a late
// allow cannot be claimed and is recorded as the deny the kernel was given.
#[test]
fn exec_decision_timeout_denies() {
    let clock = clock();
    let (release, blocked) = channel();
    let policy = Arc::new(LatePolicy {
        clock: Arc::clone(&clock),
        release: Mutex::new(blocked),
        seen: Mutex::new(None),
    });
    let authoriser = ExecAuthoriser::new(policy.clone(), clock.clone());
    let deadline = due_in(clock.as_ref(), Duration::from_secs(5));
    assert_eq!(authoriser.authorise(request(), deadline), ExecVerdict::Deny);
    release.send(()).unwrap();
    // The abandoned decision finishes on its own thread: it found its caller gone and could not claim the allow.
    let seen = loop {
        if let Some(seen) = *policy.seen.lock().unwrap() {
            break seen;
        }
        std::thread::yield_now();
    };
    assert_eq!(seen, (true, false));
}

// KNSH-094: no time left (or less than the margin) is a deny without asking the policy at all.
#[test]
fn deadline_already_passed_denies_without_deciding() {
    let clock = clock();
    let policy = Arc::new(ScriptedPolicy::default());
    let authoriser = ExecAuthoriser::new(policy.clone(), clock.clone());
    let now = clock.monotonic();
    assert_eq!(authoriser.authorise(request(), now), ExecVerdict::Deny);
    let inside_margin = due_in(clock.as_ref(), DEADLINE_MARGIN);
    assert_eq!(authoriser.authorise(request(), inside_margin), ExecVerdict::Deny);
    assert!(policy.asked.lock().unwrap().is_empty());
}

// KNSH-094: an allow that was never claimed on the gate is not trusted.
#[test]
fn unclaimed_allow_is_denied() {
    let clock = clock();
    let authoriser = ExecAuthoriser::new(Arc::new(UnclaimedAllow), clock.clone());
    let deadline = due_in(clock.as_ref(), Duration::from_secs(5));
    assert_eq!(authoriser.authorise(request(), deadline), ExecVerdict::Deny);
}

// KNSH-094: the gate's claim and expiry are exclusive: whichever comes first decides.
#[test]
fn gate_claim_and_expiry_are_exclusive() {
    let clock = clock();
    let answer_by = due_in(clock.as_ref(), Duration::from_secs(1));
    let claimed = ExecGate::new(clock.clone(), answer_by);
    assert!(!claimed.gone());
    assert!(claimed.claim_allow());
    assert!(claimed.expire(), "an allow claimed first stands");

    let expired = ExecGate::new(clock.clone(), answer_by);
    assert!(!expired.expire());
    assert!(expired.gone());
    assert!(!expired.claim_allow(), "nothing can be claimed after the expiry");

    let late = ExecGate::new(clock.clone(), answer_by);
    clock.advance(Duration::from_secs(1));
    assert!(late.gone());
    assert!(!late.claim_allow(), "nor after the deadline");
}

// KNSH-094: the envelope's own four launch execs, by its leader and in order, are not decided; the same binaries later,
// or from another process, are.
#[test]
fn launch_chain_is_exempt_once_and_only_from_the_leader() {
    let clock = clock();
    let policy = Arc::new(ScriptedPolicy {
        script: Mutex::new(vec![false; 8]),
        ..ScriptedPolicy::default()
    });
    let handler = envelope(policy.clone(), &clock);
    // Another process running bash before the chain is complete is decided (and denied here).
    let child = event(clock.as_ref(), LEADER + 1, LEADER, &[BASH, "-c", "true"]);
    assert_eq!(handler.exec(child), ExecVerdict::Deny);
    for step in [TRAMPOLINE, SANDBOX_EXEC, BASH, CLI] {
        let launch = event(clock.as_ref(), LEADER, LEADER, &[step]);
        assert_eq!(handler.exec(launch), ExecVerdict::Allow, "{step}");
    }
    // The chain is over: the leader running bash again is decided like any other exec.
    let again = event(clock.as_ref(), LEADER, LEADER, &[BASH, "-c", "git push"]);
    assert_eq!(handler.exec(again), ExecVerdict::Deny);
    let asked = policy.asked.lock().unwrap();
    assert_eq!(asked.len(), 2);
    assert_eq!(asked[1].command, "/bin/bash -c 'git push'");
}

// KNSH-094: a launch step the backend did not report is skipped, never revisited.
#[test]
fn launch_chain_skips_unreported_steps_without_going_back() {
    let mut chain = LaunchChain::new(path(TRAMPOLINE), path(SANDBOX_EXEC), path(BASH), path(CLI));
    let clock = clock();
    let leader = |exe: &str| event(clock.as_ref(), LEADER, LEADER, &[exe]);
    assert!(chain.admits(&leader(SANDBOX_EXEC), &path(SANDBOX_EXEC)));
    assert!(!chain.admits(&leader(TRAMPOLINE), &path(TRAMPOLINE)), "never back");
    assert!(chain.admits(&leader(CLI), &path(CLI)));
    assert!(
        !chain.admits(&leader(BASH), &path(BASH)),
        "over once the CLI is reached"
    );
}

// KNSH-094: once the chain has started, its steps are admitted only from the same leader: another process that made
// itself a group leader (`setpgid`, job control) cannot take over the rest of the chain.
#[test]
fn launch_chain_is_pinned_to_its_first_leader() {
    let mut chain = LaunchChain::new(path(TRAMPOLINE), path(SANDBOX_EXEC), path(BASH), path(CLI));
    let clock = clock();
    let other = LEADER + 7;
    assert!(chain.admits(&event(clock.as_ref(), LEADER, LEADER, &[TRAMPOLINE]), &path(TRAMPOLINE)));
    assert!(
        !chain.admits(&event(clock.as_ref(), other, other, &[BASH]), &path(BASH)),
        "another group leader"
    );
    assert!(chain.admits(
        &event(clock.as_ref(), LEADER, LEADER, &[SANDBOX_EXEC]),
        &path(SANDBOX_EXEC)
    ));
    assert!(chain.admits(&event(clock.as_ref(), LEADER, LEADER, &[BASH]), &path(BASH)));
}

// FR-AGT-10: `knsh` (the shims' target) is never decided here: its lines are forwarded and decided by the supervisor.
#[test]
fn knsh_is_not_decided_twice() {
    let clock = clock();
    let policy = Arc::new(ScriptedPolicy {
        script: Mutex::new(vec![false]),
        ..ScriptedPolicy::default()
    });
    let handler = envelope(policy.clone(), &clock);
    let shim = event(clock.as_ref(), LEADER + 3, LEADER, &[KNSH, "-c", "git push"]);
    assert_eq!(handler.exec(shim), ExecVerdict::Allow);
    assert!(policy.asked.lock().unwrap().is_empty());
}

// KNSH-094: the exec becomes a line of the executable's canonical path and `argv[1..]`, each one quoted word, with the
// shims removed from its `PATH`; `argv[0]` is never trusted.
#[test]
fn exec_becomes_a_quoted_line() {
    let clock = clock();
    let mut exec = event(
        clock.as_ref(),
        7,
        7,
        &["/bin/bash", "-c", "git push origin 'main'", "", "a b"],
    );
    exec.argv[0] = "innocent".into();
    let request = exec_request(session(), &path("/bin/bash"), &exec, SHIMS.as_ref()).unwrap();
    assert_eq!(request.command, r"/bin/bash -c 'git push origin '\''main'\''' '' 'a b'");
    assert_eq!(request.cwd, path("/Users/u/app"));
    assert_eq!(request.path, "/usr/bin:/bin");
    assert_eq!(request.session_id, session());

    // No `PATH`: the system default.
    exec.path = None;
    let request = exec_request(session(), &path("/bin/bash"), &exec, SHIMS.as_ref()).unwrap();
    assert_eq!(request.path, knsh_proto::DEFAULT_POLICY_CHECK_PATH);
    assert_eq!(shell_word("--flag=a:b,c@d%e"), "--flag=a:b,c@d%e");
    assert_eq!(shell_word("$(id)"), "'$(id)'");
}

// KNSH-094 (fail closed): an exec that cannot be read as a line is denied without asking the policy.
#[test]
fn unreadable_exec_is_denied() {
    use std::os::unix::ffi::OsStringExt;

    let clock = clock();
    let policy = Arc::new(ScriptedPolicy::default());
    let handler = envelope(policy.clone(), &clock);
    let mut no_cwd = event(clock.as_ref(), 9, LEADER, &["/usr/bin/git", "status"]);
    no_cwd.cwd = None;
    let mut not_utf8 = event(clock.as_ref(), 9, LEADER, &["/usr/bin/git", "status"]);
    not_utf8.argv[1] = OsString::from_vec(vec![0xff, 0xfe]);
    let mut relative = event(clock.as_ref(), 9, LEADER, &["/usr/bin/git", "status"]);
    relative.executable = "git".into();
    let long_arg = "x".repeat(knsh_core::MAX_LINE_LEN);
    let too_long = event(clock.as_ref(), 9, LEADER, &["/usr/bin/git", "commit", "-m", &long_arg]);
    for exec in [no_cwd, not_utf8, relative, too_long] {
        assert_eq!(handler.exec(exec), ExecVerdict::Deny);
    }
    assert!(policy.asked.lock().unwrap().is_empty());
}

// KNSH-094: the layer creates one client per envelope, deciding with that envelope's handler, and deletes it when the
// returned value is dropped; a dropped client decides nothing more.
#[test]
fn layer_watches_each_envelope_with_its_own_client() {
    let clock = clock();
    let clients = Arc::new(ScriptedDescendantClients::new());
    let policy = Arc::new(ScriptedPolicy {
        script: Mutex::new(vec![true]),
        ..ScriptedPolicy::default()
    });
    let authoriser = Arc::new(ExecAuthoriser::new(policy.clone(), clock.clone()));
    let layer = ExecLayer::new(
        clients.clone() as Arc<dyn DescendantClients>,
        authoriser,
        path(TRAMPOLINE),
        path(KNSH),
        SHIMS.into(),
    );
    let client = layer.watch(session(), &path(BASH), &path(CLI)).unwrap();
    assert_eq!((clients.watched(), clients.live()), (1, 1));
    let exec = event(clock.as_ref(), 9, LEADER, &["/usr/bin/git", "status"]);
    assert_eq!(clients.deliver(0, exec.clone()), ExecVerdict::Allow);
    assert_eq!(policy.asked.lock().unwrap()[0].session_id, session());
    drop(client);
    assert_eq!(clients.live(), 0);
    assert_eq!(clients.deliver(0, exec), ExecVerdict::Deny);
}
