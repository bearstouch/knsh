//! Irreversible actions: classification before a line runs and marking after it ran (KNSH-093; FR-IRR-01 to
//! FR-IRR-04; `specs/03-functional-requirements/irreversible-actions.md`).
//!
//! # Before running (FR-IRR-01, FR-IRR-02)
//!
//! [`classify_irreversible`] flags each command of a classified line that matches the built-in list
//! ([`BUILTIN_IRREVERSIBLE`]) or the profile's `approvals.irreversible_commands`, read like `exec.ask` patterns: over
//! normalised arguments (so `git -c x=y push` is `git push`, FR-POL-15), and matching when they **may** match, so an
//! expansion cannot step around a flag (`git $X` is flagged as `git push`). `curl` and `rsync` are read by their own
//! argument readers ([`curl_reason`], [`rsync_reason`]): `curl` with a write method, `rsync` to a remote host. Each
//! match is a reason: the pattern (`git push`), or the reader's reason (`curl POST`). The policy step turns a flagged
//! command into what `approvals.irreversible` says (FR-IRR-05, [`super::line`]).
//!
//! Dynamic code is not read here: `bash -c 'git push'` names no flagged program as written. It is decided by
//! `exec.default` and clamped (FR-POL-20, FR-POL-21), and what it did is still marked after it runs.
//!
//! # After running (FR-IRR-03)
//!
//! [`mark_observed`] adds what the line was seen doing:
//!
//! - every host the proxy let it contact that is one of `network.approval_hosts`, or upload-capable: in
//!   [`BUILTIN_UPLOAD_HOSTS`] or the profile's `approvals.upload_hosts` (KNSH-093 proposes both, closing the spec gap
//!   on how a host is known to be upload-capable). Each adds the reason `network` and the host;
//! - every path it wrote outside the profile's checkpoint roots: the path is the reason.
//!
//! Coverage: hosts come from the proxy's reports (every connection a line makes goes through it, FR-NET-01). Writes
//! come only from what file events report, and the engine watches only checkpoint roots today, so a write outside
//! them is not observed yet; the function takes whatever paths the caller observed.
//!
//! Like every classifier result, the flag is an intent filter and a report, never a security boundary.

use knsh_bash::{BUILTIN_IRREVERSIBLE, Classification, ClassifiedCommand, curl_reason, rsync_reason};

use super::model::Profile;
use super::network::host_matches;
use super::rules::{arguments_if_named, matches_possibly};
use crate::path::CanonicalPath;
use crate::record::{Irreversibility, NetworkEntry, NetworkResult};

/// Hosts that exist to receive data (file drops, paste and upload endpoints): a line that reached one is marked
/// irreversible after it runs (FR-IRR-03, KNSH-093). A profile adds more with `approvals.upload_hosts`. Registries and
/// git hosts accept uploads too; the spec's advice is to keep them in `network.approval_hosts`, which marks them as
/// well.
pub const BUILTIN_UPLOAD_HOSTS: &[&str] = &[
    "uploads.github.com",
    "upload.pypi.org",
    "transfer.sh",
    "0x0.st",
    "file.io",
    "pastebin.com",
    "paste.rs",
    "termbin.com",
    "webhook.site",
];

/// The reason a network contact is marked with, next to the host.
const NETWORK_REASON: &str = "network";

/// Whether the line `classification` describes is irreversible before it runs, and why (module documentation).
/// Pure and total.
#[must_use]
pub fn classify_irreversible(profile: &Profile, classification: &Classification) -> Irreversibility {
    let mut irreversible = Irreversibility::none();
    for command in classification.commands() {
        for reason in command_reasons(profile, command) {
            irreversible.add(reason);
        }
    }
    irreversible
}

/// A reader of one tool's arguments: why the command is irreversible, if it is.
type ArgumentReader = fn(&[Option<&str>], bool) -> Option<String>;

/// Why one command is irreversible (module documentation, "Before running"); empty when it is not.
pub(crate) fn command_reasons(profile: &Profile, command: &ClassifiedCommand) -> Vec<String> {
    let patterns = BUILTIN_IRREVERSIBLE
        .iter()
        .copied()
        .chain(profile.approvals.irreversible_commands.iter().map(String::as_str));
    let mut reasons: Vec<String> = patterns
        .filter(|pattern| matches_possibly(pattern, command))
        .map(str::to_owned)
        .collect();
    let readers: [(&str, ArgumentReader); 2] = [("curl", curl_reason), ("rsync", rsync_reason)];
    for (name, reader) in readers {
        if let Some(reason) =
            arguments_if_named(name, command).and_then(|(arguments, complete)| reader(&arguments, complete))
        {
            reasons.push(reason);
        }
    }
    reasons
}

/// Adds to `irreversible` what the line was seen doing (module documentation, "After running"): `network` hosts it
/// contacted, from the proxy's reports, and `writes`, the paths it was seen writing.
pub fn mark_observed(
    profile: &Profile,
    irreversible: &mut Irreversibility,
    network: &[NetworkEntry],
    writes: &[CanonicalPath],
) {
    for entry in network {
        match entry.result {
            NetworkResult::Contacted => {}
            // A refused connection reached nothing.
            NetworkResult::Refused(_) => continue,
        }
        let host = entry.host.expose();
        let listed = |entries: &[String]| entries.iter().any(|listed| host_matches(listed, host));
        let upload = BUILTIN_UPLOAD_HOSTS.iter().any(|listed| host_matches(listed, host))
            || listed(&profile.approvals.upload_hosts);
        if upload || listed(&profile.network.approval_hosts) {
            irreversible.add(NETWORK_REASON);
            irreversible.add(host.clone());
        }
    }
    let roots = &profile.checkpoints.roots;
    for path in writes {
        if !roots.iter().any(|root| path.as_path().starts_with(root.as_path())) {
            irreversible.add(path.as_path().to_string_lossy().into_owned());
        }
    }
}

#[cfg(test)]
mod tests;
