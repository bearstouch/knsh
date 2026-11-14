//! Test helpers: a scripted oracle and corpus lines, so harness and report tests never depend on the host's bash.

use std::path::PathBuf;

use knsh_corpus::entry::Entry;

use crate::DiffError;
use crate::harness::Line;
use crate::oracle::{Oracle, OracleInfo, Role, bash_major};

/// An oracle whose verdict is a function of the line, or that always fails.
pub(crate) struct FakeOracle {
    info: OracleInfo,
    verdict: Option<fn(&str) -> bool>,
}

impl FakeOracle {
    pub(crate) fn new(info: OracleInfo, verdict: fn(&str) -> bool) -> Self {
        Self {
            info,
            verdict: Some(verdict),
        }
    }

    pub(crate) fn failing(info: OracleInfo) -> Self {
        Self { info, verdict: None }
    }
}

impl Oracle for FakeOracle {
    fn info(&self) -> &OracleInfo {
        &self.info
    }

    fn accepts(&self, command: &str) -> Result<bool, DiffError> {
        self.verdict
            .map(|verdict| verdict(command))
            .ok_or_else(|| DiffError::Oracle {
                path: self.info.path.clone(),
                message: "scripted failure".into(),
            })
    }
}

fn bash(path: &str, version: &str) -> OracleInfo {
    OracleInfo {
        path: PathBuf::from(path),
        version: version.to_owned(),
        major: bash_major(version),
        role: Role::Gate,
    }
}

pub(crate) fn bash3() -> OracleInfo {
    bash(
        "/bin/bash",
        "GNU bash, version 3.2.57(1)-release (arm64-apple-darwin25)",
    )
}

pub(crate) fn bash5() -> OracleInfo {
    bash(
        "/opt/homebrew/bin/bash",
        "GNU bash, version 5.2.37(1)-release (aarch64-apple-darwin24.0.0)",
    )
}

pub(crate) fn reference() -> OracleInfo {
    OracleInfo {
        path: PathBuf::from("/usr/local/bin/brush"),
        version: "brush 0.2.18".to_owned(),
        major: None,
        role: Role::Reference,
    }
}

/// An untagged corpus line from the test source.
pub(crate) fn line(command: &str) -> Line {
    Line {
        file: "test.txt".to_owned(),
        line: 3,
        entry: Entry::new("test", "MIT", Vec::new(), command.to_owned()).unwrap(),
    }
}
