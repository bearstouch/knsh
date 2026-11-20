//! Which case covers which threat row, how a case records that it passed or what is pending, and the report the
//! phase 2 release gate references (KNSH-075).
//!
//! A case calls [`Case::start`] first and [`Case::passed`] last: a case that fails an assertion never reaches
//! `passed`, so it leaves no result and [`write_report`] reports it as failed. What a case cannot observe on this
//! machine is added with [`Case::pending`] and shows in the report next to what did pass; a case that could not run
//! at all ends with [`Case::blocked`].

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The rows of the threat model, in the specification's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Row {
    ApproveOwnRequest,
    SlipPastCommandRules,
    BinarySwapped,
    SystemServices,
    PlantCode,
    EditPolicy,
    KillKnshd,
    Impostor,
    LeakSecret,
    SendDataOut,
    ApprovalFatigue,
}

impl Row {
    /// Every row, in order.
    pub(super) const ALL: [Self; 11] = [
        Self::ApproveOwnRequest,
        Self::SlipPastCommandRules,
        Self::BinarySwapped,
        Self::SystemServices,
        Self::PlantCode,
        Self::EditPolicy,
        Self::KillKnshd,
        Self::Impostor,
        Self::LeakSecret,
        Self::SendDataOut,
        Self::ApprovalFatigue,
    ];

    /// The row's "Threat" cell, exactly as `security.md` writes it.
    pub(super) const fn threat(self) -> &'static str {
        match self {
            Self::ApproveOwnRequest => "An agent approves its own request",
            Self::SlipPastCommandRules => {
                "An agent slips past command rules (`eval`, interpreters, absolute paths, wrappers)"
            }
            Self::BinarySwapped => "A binary is swapped between classification and execution",
            Self::SystemServices => "An agent escapes through LaunchServices, Apple Events or launchd",
            Self::PlantCode => "An agent plants code that runs later outside the sandbox",
            Self::EditPolicy => "An agent edits policy, hooks or trust",
            Self::KillKnshd => "An agent kills `knshd` or squats its endpoints",
            Self::Impostor => "An impostor daemon or authority",
            Self::LeakSecret => "An agent leaks a secret",
            Self::SendDataOut => "An agent sends data out",
            Self::ApprovalFatigue => "Approval fatigue",
        }
    }
}

/// Every case of the suite and the row it covers. Each name is a `#[test]` in `cases.rs`.
pub(super) const CASES: [(&str, Row); 13] = [
    ("agent_cannot_approve_own_request", Row::ApproveOwnRequest),
    (
        "python_subprocess_git_push_cannot_reach_approval_host",
        Row::SlipPastCommandRules,
    ),
    (
        "eval_and_absolute_path_bypass_stay_inside_profile",
        Row::SlipPastCommandRules,
    ),
    ("binary_swapped_after_classification_cannot_exec", Row::BinarySwapped),
    (
        "open_osascript_launchctl_denied_by_rule_and_profile",
        Row::SystemServices,
    ),
    (
        "writes_to_git_hooks_config_rc_files_launchagents_denied",
        Row::PlantCode,
    ),
    ("agent_cannot_edit_policy_hooks_or_trust", Row::EditPolicy),
    (
        "envelope_cannot_signal_knshd_and_lines_stop_when_it_dies",
        Row::KillKnshd,
    ),
    ("impostor_authority_refused", Row::Impostor),
    ("secret_not_visible_to_other_process_groups", Row::LeakSecret),
    ("injected_secret_reaches_only_its_hosts", Row::LeakSecret),
    ("exfiltration_blocked_by_host_name_and_address_checks", Row::SendDataOut),
    (
        "repeated_denials_rate_limited_and_grants_reduce_asks",
        Row::ApprovalFatigue,
    ),
];

/// The threat model's "Out of scope" list, exactly as `security.md` writes it: documented as not tested.
pub(super) const OUT_OF_SCOPE: [&str; 4] = [
    "Malware running outside any session",
    "A compromised authority",
    "A malicious hook the user installed",
    "Flaws in the macOS sandbox itself",
];

/// Set to `1` by `scripts/check.sh threat-model` and CI: a case that cannot run fails instead of being pending.
pub(super) const STRICT_VAR: &str = "KNSH_THREAT_MODEL_STRICT";

/// Overrides where results and the report are written (default `target/threat-model`).
const DIR_VAR: &str = "KNSH_THREAT_MODEL_DIR";

/// One running case: what is pending so far.
pub(super) struct Case {
    name: &'static str,
    pending: Vec<String>,
}

impl Case {
    /// Starts case `name`, which must be listed in [`CASES`]. Any result an earlier run left is removed first, so a
    /// case that fails this time cannot be reported with an old pass.
    pub(super) fn start(name: &'static str) -> Self {
        assert!(CASES.iter().any(|(case, _)| *case == name), "{name} is not in CASES");
        let _ = std::fs::remove_file(result_file(name));
        Self {
            name,
            pending: Vec::new(),
        }
    }

    /// Records a part of the mitigation that cannot be observed on this machine, and why. Printed, never silent.
    pub(super) fn pending(&mut self, reason: &str) {
        eprintln!("PENDING {}: {reason}", self.name);
        self.pending.push(reason.to_owned());
    }

    /// Every assertion held: writes the result, with anything pending.
    pub(super) fn passed(self) {
        let status = if self.pending.is_empty() {
            "passed"
        } else {
            "passed-partly-pending"
        };
        self.write(status);
    }

    /// The case could not run at all, for `reason`. Fails under [`STRICT_VAR`]; otherwise the case is pending.
    pub(super) fn blocked(mut self, reason: &str) {
        assert!(
            std::env::var_os(STRICT_VAR).is_none(),
            "{}: {reason} ({STRICT_VAR} is set, so this fails instead of being pending)",
            self.name
        );
        self.pending(reason);
        self.write("pending");
    }

    fn write(&self, status: &str) {
        let mut text = format!("status={status}\n");
        for reason in &self.pending {
            // One line per reason: a reason never spans lines.
            let _ = writeln!(text, "pending={}", reason.replace('\n', " "));
        }
        let file = result_file(self.name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, text).unwrap();
    }
}

/// `target/threat-model` (from this test binary's place, `target/<profile>/deps/`), or [`DIR_VAR`].
fn output_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(DIR_VAR) {
        return PathBuf::from(dir);
    }
    let exe = std::env::current_exe().unwrap();
    // target/<profile>/deps/knshd-<hash> → target/
    exe.ancestors().nth(3).unwrap().join("threat-model")
}

fn result_file(name: &str) -> PathBuf {
    output_dir().join("results").join(format!("{name}.result"))
}

/// A case's result as read back: its status and pending reasons, or `None` if it left none (it failed, or was not
/// run).
fn read_result(name: &str) -> Option<(String, Vec<String>)> {
    let text = std::fs::read_to_string(result_file(name)).ok()?;
    let mut status = None;
    let mut pending = Vec::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("status=") {
            status = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("pending=") {
            pending.push(value.to_owned());
        }
    }
    Some((status?, pending))
}

/// `sw_vers -<key>`, or `unknown`.
fn sw_vers(key: &str) -> String {
    std::process::Command::new("/usr/bin/sw_vers")
        .arg(format!("-{key}"))
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or_else(|| "unknown".to_owned(), |text| text.trim().to_owned())
}

/// The threat model page, read from the specification in this repository.
fn security_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs/04-non-functional-requirements/security.md");
    std::fs::read_to_string(path).unwrap()
}

/// The first cell of every row of the "Threat model" table, and every "Out of scope" bullet, in order.
fn spec_rows_and_out_of_scope(text: &str) -> (Vec<String>, Vec<String>) {
    let mut section = "";
    let mut rows = Vec::new();
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ").or_else(|| line.strip_prefix("### ")) {
            section = if heading == "Threat model" || heading == "Out of scope" {
                heading
            } else {
                ""
            };
            continue;
        }
        match section {
            "Threat model" => {
                let Some(row) = line.strip_prefix("| ") else { continue };
                let cell = row.split(" | ").next().unwrap_or_default().trim();
                // The header and the separator are not threats.
                if cell != "Threat" && !cell.starts_with("---") {
                    rows.push(cell.to_owned());
                }
            }
            "Out of scope" => {
                if let Some(item) = line.strip_prefix("- ") {
                    out.push(item.trim().to_owned());
                }
            }
            _ => {}
        }
    }
    (rows, out)
}

// KNSH-075: every row of the threat model has at least one case, and the suite covers no row the specification does
// not have; the out-of-scope list is the specification's. A row added to `security.md` fails here until it has a case.
#[test]
fn every_threat_row_has_a_case() {
    let (rows, out_of_scope) = spec_rows_and_out_of_scope(&security_md());
    let ours: Vec<&str> = Row::ALL.iter().map(|row| row.threat()).collect();
    assert_eq!(rows, ours, "the threat model's rows and Row::ALL differ");
    assert_eq!(out_of_scope, OUT_OF_SCOPE, "the out-of-scope list differs");
    for row in Row::ALL {
        assert!(
            CASES.iter().any(|(_, covered)| *covered == row),
            "no case for {:?}",
            row.threat()
        );
    }
}

/// Writes `target/threat-model/report.md` from the results the cases left, and fails if any case left none. Run
/// after the cases by `scripts/check.sh threat-model`; ignored in a normal test run, where the cases run in parallel
/// with it.
#[test]
#[ignore = "writes the report after the cases ran: scripts/check.sh threat-model"]
fn write_report() {
    let mut failed = Vec::new();
    let mut report = String::from("# Threat-model end-to-end suite (KNSH-075)\n\n");
    let _ = writeln!(
        report,
        "Ran on macOS {} (build {}), {}.\n",
        sw_vers("productVersion"),
        sw_vers("buildVersion"),
        std::env::consts::ARCH
    );
    report.push_str(
        "Every row of the threat model (`specs/04-non-functional-requirements/security.md`) and the end-to-end cases \
         that cover it (`crates/knshd/src/threat_model/cases.rs`). **Pending** parts could not be observed on this \
         machine and are not claimed as passed.\n\n",
    );
    report.push_str("| Threat | Case | Result | Pending |\n| --- | --- | --- | --- |\n");
    for row in Row::ALL {
        for (name, _) in CASES.iter().filter(|(_, covered)| *covered == row) {
            let (result, pending) = if let Some((status, pending)) = read_result(name) {
                (status, pending.join("; "))
            } else {
                failed.push(*name);
                ("**failed** (no result)".to_owned(), String::new())
            };
            let _ = writeln!(report, "| {} | `{name}` | {result} | {pending} |", row.threat());
        }
    }
    report.push_str("\n## Out of scope (not tested)\n\n");
    for item in OUT_OF_SCOPE {
        let _ = writeln!(report, "- {item}");
    }
    report.push_str(
        "\n## macOS versions\n\nThis report covers the version above only. CI runs the suite on every macOS release \
         with a runner (`.github/workflows/ci.yml`, job `threat-model`); versions without one are pending: see \
         `tests/threat-model/README.md`.\n",
    );
    let dir = output_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("report.md"), &report).unwrap();
    println!("{report}");
    assert!(
        failed.is_empty(),
        "cases without a result (failed or not run): {failed:?}"
    );
}
