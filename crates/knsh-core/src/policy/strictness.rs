//! Whether one resolved profile is equal to or stricter than another: the rule a nested agent session's profile is
//! checked by (FR-SES-03, KNSH-056, `specs/05-models/session.md#profile-strictness`).
//!
//! A child profile is at least as strict as its parent when **everything the child allows, the parent allows too,
//! and everything the parent denies, the child still denies**. The comparison is key by key over the resolved
//! [`Profile`] (after `extends`, the preset and defaults), and it is conservative: where two values cannot be
//! compared exactly (command patterns, the interpreter table, the bash that runs lines), only the same value counts
//! as "no looser". A `false` therefore means "looser, or not provably not looser"; the caller refuses the child
//! either way, so an agent can never reach a looser profile through a value this module could not reason about
//! (the [`ProfileOrder`](crate::ProfileOrder) contract).
//!
//! | Key | The child is no looser when |
//! | --- | --- |
//! | `fs.read` | the parent reads `all`, or every child read path is at or below a parent read path |
//! | `fs.write` | every child write root is at or below a parent write root |
//! | `fs.deny` | every parent deny is at or below a child deny |
//! | `exec.allow` | every child pattern is a parent `exec.allow` pattern |
//! | `exec.ask` | every child pattern is a parent `exec.allow` or `exec.ask` pattern, and every parent pattern a child `exec.ask` or `exec.deny` one |
//! | `exec.deny` | every parent pattern is a child `exec.deny` pattern |
//! | `exec.default`, `exec.project_executables`, `approvals.irreversible` | the child's action is the parent's or stricter (`allow` < `ask` < `deny`) |
//! | `exec.trusted_folders`, `exec.trusted_tools` | the child's are a subset of the parent's |
//! | `exec.interpreters`, `exec.bash` | equal |
//! | `network.mode` | `none`, or both `allowlist` |
//! | `network.hosts`, `network.loopback`, `network.non_tls_hosts` | a subset of the parent's |
//! | `network.approval_hosts` | a subset of the parent's hosts and approval hosts |
//! | `network.class_hosts` | per class, a subset of the parent's hosts and of the parent's hosts for that class |
//! | `approvals.irreversible_commands` | a superset of the parent's |
//! | `checkpoints` | `required` kept, every parent root kept, excludes a subset of the parent's |
//! | `recording` | commands and output recorded where the parent records them, kept at least as long |
//! | `secrets.env` | every child injection is the parent's, unchanged |
//!
//! `name`, `extends`, `preset` and `output.mode` are not compared: the first three only say where the values came
//! from (their effect is already in the resolved keys), and the output mode shapes what the agent reads back, not
//! what it may do.

use std::path::Path;

use knsh_bash::NetworkClass;

use crate::path::CanonicalPath;
use crate::policy::model::{
    ApprovalsPolicy, CheckpointPolicy, ExecPolicy, FsPolicy, NetworkMode, NetworkPolicy, Profile, ReadScope,
    RecordingPolicy,
};
use crate::registry::ProfileOrder;
use crate::session::ProfileName;

/// Whether `child` allows nothing `parent` does not and still denies everything `parent` denies (module
/// documentation). Pure, and `true` for any profile compared with itself.
#[must_use]
pub fn at_least_as_strict(child: &Profile, parent: &Profile) -> bool {
    fs_no_looser(&child.fs, &parent.fs)
        && exec_no_looser(&child.exec, &parent.exec)
        && network_no_looser(&child.network, &parent.network)
        && approvals_no_looser(&child.approvals, &parent.approvals)
        && checkpoints_no_looser(&child.checkpoints, &parent.checkpoints)
        && recording_no_looser(&child.recording, &parent.recording)
        // An injection gives a line a secret: the child may only keep the parent's, exactly as the parent has them.
        && child
            .secrets
            .iter()
            .all(|(var, injection)| parent.secrets.get(var) == Some(injection))
}

/// A [`ProfileOrder`] over two profiles already loaded: the child's and its parent's. It answers for exactly that
/// pair of names, and `false` for any other: a name it holds no profile for is never assumed comparable.
#[derive(Debug, Clone, Copy)]
pub struct LoadedProfiles<'a> {
    /// The profile the new session asks for.
    pub child: &'a Profile,
    /// The parent session's profile.
    pub parent: &'a Profile,
}

impl ProfileOrder for LoadedProfiles<'_> {
    fn at_least_as_strict(&self, child: &ProfileName, parent: &ProfileName) -> bool {
        *child == self.child.name && *parent == self.parent.name && at_least_as_strict(self.child, self.parent)
    }
}

/// `[fs]`: reads and writes only where the parent allows them, and every parent deny still covered.
fn fs_no_looser(child: &FsPolicy, parent: &FsPolicy) -> bool {
    let reads = match (&child.read, &parent.read) {
        (_, ReadScope::All) => true,
        // `all` reads more than any list of paths can.
        (ReadScope::All, ReadScope::Paths(_)) => false,
        (ReadScope::Paths(child), ReadScope::Paths(parent)) => all_within(child, parent),
    };
    // A child deny at or above a parent deny covers it: the denied subtree only grows.
    reads && all_within(&child.write, &parent.write) && all_within(&parent.deny, &child.deny)
}

/// `[exec]`: command patterns compared as text (a pattern is only known to allow no more than itself), actions by
/// their order, and what decides how a line is read and run kept the same.
fn exec_no_looser(child: &ExecPolicy, parent: &ExecPolicy) -> bool {
    child.allow.iter().all(|pattern| parent.allow.contains(pattern))
        && child
            .ask
            .iter()
            .all(|pattern| parent.allow.contains(pattern) || parent.ask.contains(pattern))
        // Ask beats allow (FR-POL-17): a parent ask the child dropped would let a child allow (or the default) run
        // what the parent asked about, so every parent ask stays an ask or becomes a deny.
        && parent
            .ask
            .iter()
            .all(|pattern| child.ask.contains(pattern) || child.deny.contains(pattern))
        && parent.deny.iter().all(|pattern| child.deny.contains(pattern))
        // `RuleAction` orders `allow` < `ask` < `deny`: a larger action is stricter.
        && child.default >= parent.default
        && child.project_executables >= parent.project_executables
        && child
            .trusted_folders
            .folders()
            .iter()
            .all(|folder| parent.trusted_folders.folders().contains(folder))
        && child.trusted_tools.iter().all(|tool| parent.trusted_tools.contains(tool))
        // The interpreter table decides what is seen as dynamic code, and the bash runs every line: a different one
        // could read or run a line differently, so only the same one is known not to be looser.
        && child.interpreters == parent.interpreters
        && child.bash == parent.bash
}

/// `[network]`: no mode, host or port the parent does not have.
fn network_no_looser(child: &NetworkPolicy, parent: &NetworkPolicy) -> bool {
    let mode = match (child.mode, parent.mode) {
        (NetworkMode::None, _) | (NetworkMode::Allowlist, NetworkMode::Allowlist) => true,
        (NetworkMode::Allowlist, NetworkMode::None) => false,
    };
    mode && child.hosts.iter().all(|host| parent.hosts.contains(host))
        && child
            .approval_hosts
            .iter()
            .all(|host| parent.hosts.contains(host) || parent.approval_hosts.contains(host))
        && child.loopback.iter().all(|port| parent.loopback.contains(port))
        // A non-TLS host skips the server-name check (FR-NET-06): the parent must already skip it.
        && child.non_tls_hosts.iter().all(|host| parent.non_tls_hosts.contains(host))
        // A class rule opens an approval host without an approval (FR-NET-03): the parent must already open that
        // host to the class, or to every command.
        && [NetworkClass::Fetch, NetworkClass::Publish].into_iter().all(|class| {
            child.class_hosts.for_class(class).iter().all(|host| {
                parent.hosts.contains(host) || parent.class_hosts.for_class(class).contains(host)
            })
        })
}

/// `[approvals]`: irreversible lines treated at least as strictly, and every pattern the parent flags still flagged.
fn approvals_no_looser(child: &ApprovalsPolicy, parent: &ApprovalsPolicy) -> bool {
    child.irreversible >= parent.irreversible
        && parent
            .irreversible_commands
            .iter()
            .all(|pattern| child.irreversible_commands.contains(pattern))
}

/// `[checkpoints]`: at least the parent's protection. Fewer roots, more excludes or an optional checkpoint would
/// let a child change files the parent could undo without leaving a way back.
fn checkpoints_no_looser(child: &CheckpointPolicy, parent: &CheckpointPolicy) -> bool {
    (child.required || !parent.required)
        && parent.roots.iter().all(|root| child.roots.contains(root))
        && child.exclude.iter().all(|name| parent.exclude.contains(name))
}

/// `[recording]`: the child leaves at least the trail the parent leaves (NFR-PRIV): it may record more, never less.
fn recording_no_looser(child: &RecordingPolicy, parent: &RecordingPolicy) -> bool {
    (child.commands || !parent.commands)
        && (child.output || !parent.output)
        && child.retention_days >= parent.retention_days
}

/// Whether every path in `inner` is at or below some path in `outer`. Paths are canonical, so comparing components
/// is enough (`/a/bc` is not below `/a/b`).
fn all_within(inner: &[CanonicalPath], outer: &[CanonicalPath]) -> bool {
    inner.iter().all(|path| within(path.as_path(), outer))
}

fn within(path: &Path, outer: &[CanonicalPath]) -> bool {
    outer.iter().any(|root| path.starts_with(root.as_path()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::policy::model::RuleAction;
    use crate::policy::paths::testing::FakeFs;
    use crate::policy::{LookupError, PathContext, ProfileSource, load_profile_text};

    struct NoParents;

    impl ProfileSource for NoParents {
        fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
            Err(LookupError::NotFound)
        }
    }

    fn path(text: &str) -> CanonicalPath {
        CanonicalPath::new(text).unwrap()
    }

    /// A resolved profile from `text` (which must set `name`), on a small fake Mac.
    fn profile(text: &str) -> Profile {
        let mut fs = FakeFs::new();
        fs.add("/Users/u/app/.git").add("/bin/bash").add("/tmp");
        let context = PathContext {
            home: PathBuf::from("/Users/u"),
            tmpdir: PathBuf::from("/tmp"),
            start_dir: PathBuf::from("/Users/u/app"),
        };
        load_profile_text(text.as_bytes(), &NoParents, &context, &fs).unwrap()
    }

    fn parent() -> Profile {
        profile(
            r#"
name = "parent"
[fs]
write = ["${PROJECT}"]
deny = ["~/.ssh"]
[exec]
allow = ["git status", "ls *"]
ask = ["git push *"]
deny = ["rm -rf *"]
default = "ask"
[network]
mode = "allowlist"
hosts = ["github.com"]
approval_hosts = ["registry.npmjs.org"]
loopback = [3000]
"#,
        )
    }

    // FR-SES-03: equality always satisfies "equal or stricter", whatever the name.
    #[test]
    fn a_profile_is_as_strict_as_itself_and_its_copies() {
        let parent = parent();
        assert!(at_least_as_strict(&parent, &parent));
        let mut renamed = parent.clone();
        renamed.name = ProfileName::new("copy").unwrap();
        assert!(at_least_as_strict(&renamed, &parent));
    }

    // FR-SES-03: removing allows and adding denies is stricter.
    #[test]
    fn fewer_allows_and_more_denies_are_stricter() {
        let parent = parent();
        let mut child = parent.clone();
        child.exec.allow.retain(|pattern| pattern == "git status");
        child.exec.deny.push("curl *".to_owned());
        child.exec.default = RuleAction::Deny;
        child.fs.write = vec![path("/Users/u/app/src")];
        child.fs.deny.push(path("/Users/u/app/secrets"));
        child.network.hosts.clear();
        child.network.mode = NetworkMode::None;
        assert!(at_least_as_strict(&child, &parent));
        // …and the parent is looser than that child.
        assert!(!at_least_as_strict(&parent, &child));
    }

    // FR-SES-03, FR-NET-03: a class rule the parent does not have opens an approval host without an approval, so it
    // is looser; one for a host the parent opens to every command, or the parent's own rule, is not.
    #[test]
    fn class_hosts_never_widen() {
        let parent = parent();
        let mut child = parent.clone();
        child.network.class_hosts.fetch.push("registry.npmjs.org".to_owned());
        assert!(!at_least_as_strict(&child, &parent));
        assert!(at_least_as_strict(&parent, &child));
        // github.com is open to every command in the parent.
        let mut child = parent.clone();
        child.network.class_hosts.publish.push("github.com".to_owned());
        assert!(at_least_as_strict(&child, &parent));
        // A rule for one class does not cover another.
        let mut with_fetch = parent.clone();
        with_fetch
            .network
            .class_hosts
            .fetch
            .push("registry.npmjs.org".to_owned());
        let mut with_publish = parent;
        with_publish
            .network
            .class_hosts
            .publish
            .push("registry.npmjs.org".to_owned());
        assert!(!at_least_as_strict(&with_publish, &with_fetch));
    }

    // FR-SES-03: every way of allowing more than the parent is looser.
    #[test]
    fn any_extra_allowance_is_looser() {
        let parent = parent();
        let loosen: [fn(&mut Profile); 15] = [
            |p| p.exec.allow.push("curl *".to_owned()),
            |p| p.exec.ask.push("make *".to_owned()),
            |p| p.exec.deny.clear(),
            |p| p.exec.default = RuleAction::Allow,
            |p| p.exec.project_executables = RuleAction::Allow,
            |p| p.exec.trusted_tools.push("npm".to_owned()),
            |p| p.exec.trusted_folders.add(path("/Users/u/bin")),
            |p| p.exec.bash = path("/opt/homebrew/bin/bash"),
            |p| p.fs.write.push(path("/Users/u")),
            |p| p.fs.deny.clear(),
            |p| p.network.hosts.push("example.com".to_owned()),
            |p| p.network.loopback.push(8080),
            |p| p.network.non_tls_hosts.push("registry.npmjs.org".to_owned()),
            |p| p.approvals.irreversible = RuleAction::Allow,
            |p| p.recording.commands = false,
        ];
        for (index, change) in loosen.iter().enumerate() {
            let mut child = parent.clone();
            change(&mut child);
            assert!(!at_least_as_strict(&child, &parent), "change {index} must be looser");
        }
    }

    // A deny above the parent's covers it; a deny below it does not.
    #[test]
    fn a_parent_deny_is_covered_only_by_a_deny_at_or_above_it() {
        let parent = parent();
        let mut wider = parent.clone();
        wider.fs.deny = vec![path("/Users/u")];
        assert!(at_least_as_strict(&wider, &parent));
        let mut narrower = parent.clone();
        narrower.fs.deny = vec![path("/Users/u/.ssh/keys")];
        assert!(!at_least_as_strict(&narrower, &parent));
    }

    // `fs.read = "all"` is looser than any list; a list inside the parent's is not.
    #[test]
    fn read_scope_narrows_only() {
        let mut parent = parent();
        parent.fs.read = ReadScope::Paths(vec![path("/Users/u/app")]);
        let mut child = parent.clone();
        child.fs.read = ReadScope::All;
        assert!(!at_least_as_strict(&child, &parent));
        child.fs.read = ReadScope::Paths(vec![path("/Users/u/app/src")]);
        assert!(at_least_as_strict(&child, &parent));
        // A sibling whose name only starts with the parent's is outside it.
        child.fs.read = ReadScope::Paths(vec![path("/Users/u/application")]);
        assert!(!at_least_as_strict(&child, &parent));
    }

    // FR-SES-03, FR-POL-17: ask beats allow, so dropping a parent ask lets the child's allow run what the parent asked
    // about (`git push` under `allow = ["git"]`). Turning it into a deny is stricter.
    #[test]
    fn dropping_a_parent_ask_is_looser() {
        let mut parent = parent();
        parent.exec.allow.push("git".to_owned());
        let mut child = parent.clone();
        child.exec.ask.clear();
        assert!(!at_least_as_strict(&child, &parent));
        child.exec.deny.push("git push *".to_owned());
        assert!(at_least_as_strict(&child, &parent));
    }

    // An ask pattern the parent allows outright is no looser; a secret the parent does not inject is.
    #[test]
    fn asks_and_secrets_follow_the_parent() {
        let parent = parent();
        let mut child = parent.clone();
        child.exec.ask.push("git status".to_owned());
        assert!(at_least_as_strict(&child, &parent));
        child.secrets.insert(
            "TOKEN".to_owned(),
            crate::policy::model::SecretInjection {
                secret: "gh".to_owned(),
                inject_for: vec!["gh *".to_owned()],
                hosts: vec!["api.github.com".to_owned()],
            },
        );
        assert!(!at_least_as_strict(&child, &parent));
    }

    // The order answers only for the pair it was built from.
    #[test]
    fn loaded_profiles_answer_only_for_their_names() {
        let parent = parent();
        let mut child = parent.clone();
        child.name = ProfileName::new("child").unwrap();
        let order = LoadedProfiles {
            child: &child,
            parent: &parent,
        };
        assert!(order.at_least_as_strict(&child.name, &parent.name));
        assert!(!order.at_least_as_strict(&parent.name, &parent.name));
        assert!(!order.at_least_as_strict(&ProfileName::new("other").unwrap(), &parent.name));
    }
}
