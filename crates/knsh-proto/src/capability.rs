//! The capability model reported by `hello` (`specs/05-models/capabilities.md`, KNSH-014).
//!
//! Every backend field is an enum with an explicit `None` variant, and [`Capabilities`] has no `Default`: a backend
//! cannot be left out or silently replaced, only reported as present or as `none` (NFR-SEC-10, NFR-REL-08). What the
//! probe found is decided in `knshd`; this module only models and writes it.

use std::collections::BTreeMap;
use std::fmt;

use knsh_json::{JsonError, Object, ToJson, Value};

/// The value every missing backend is reported as.
pub const NONE: &str = "none";

/// The OS sandbox that confines agent commands. Without one, agent sessions refuse to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sandbox {
    /// Seatbelt through `sandbox-exec`, checked by a trivial successful run.
    Seatbelt,
    /// No working sandbox on this machine.
    None,
}

/// The network filter (the engine's proxy). Arrives in phase 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkFilter {
    /// The engine's HTTP CONNECT and SOCKS proxy.
    Proxy,
    /// No network filtering.
    None,
}

/// File-change notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileEvents {
    /// `FSEvents`, checked by starting and stopping a stream.
    FsEvents,
    /// No file events.
    None,
}

/// Secret storage for credential scoping. Arrives in a later phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Secrets {
    /// The login Keychain.
    Keychain,
    /// No secret backend.
    None,
}

/// Whether sandbox denials reported by the system reach the engine (FR-SBX-08, KNSH-047). Best effort either way:
/// no method depends on it, and a command is never blocked by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxViolations {
    /// The unified-log reader is running and a canary denial it caused has arrived through it.
    UnifiedLog,
    /// No reader is running, or it has not shown that it receives denials.
    None,
}

/// How one checkpoint root is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckpointBackend {
    /// APFS clones on the root's own volume.
    ApfsClone,
    /// The root cannot be checkpointed.
    None,
}

impl Sandbox {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Seatbelt => "seatbelt",
            Self::None => NONE,
        }
    }
}

impl NetworkFilter {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::None => NONE,
        }
    }
}

impl FileEvents {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsEvents => "fsevents",
            Self::None => NONE,
        }
    }
}

impl Secrets {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keychain => "keychain",
            Self::None => NONE,
        }
    }
}

impl SandboxViolations {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnifiedLog => "unified_log",
            Self::None => NONE,
        }
    }
}

impl CheckpointBackend {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApfsClone => "apfs-clone",
            Self::None => NONE,
        }
    }
}

/// A backend a method can depend on. A method that requires a backend reported as `none` is not listed by `hello`
/// and is answered `-32005` with the backend's name as `capability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    /// [`Capabilities::sandbox`].
    Sandbox,
    /// [`Capabilities::network_filter`].
    NetworkFilter,
    /// [`Capabilities::file_events`].
    FileEvents,
    /// [`Capabilities::secrets`].
    Secrets,
    /// At least one root in [`Capabilities::checkpoints`] with a backend.
    Checkpoints,
}

impl Backend {
    /// The capability field name, as sent in `-32005` `data.capability`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::NetworkFilter => "network_filter",
            Self::FileEvents => "file_events",
            Self::Secrets => "secrets",
            Self::Checkpoints => "checkpoints",
        }
    }
}

/// What this machine can guarantee, as found by the capability probe.
///
/// # Invariants
///
/// Every field is always present. There is deliberately no `Default`: whoever builds the value states each backend,
/// so a new backend cannot be added without deciding what to report for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// The agent sandbox.
    pub sandbox: Sandbox,
    /// The network filter.
    pub network_filter: NetworkFilter,
    /// File-change notification.
    pub file_events: FileEvents,
    /// Secret storage.
    pub secrets: Secrets,
    /// Per checkpoint root (canonical path), how it is protected. Empty when no root is configured.
    pub checkpoints: BTreeMap<String, CheckpointBackend>,
    /// The sandbox violation reader. The one live field: `knshd` reports the reader's state at each `hello`, since
    /// the reader can start, stop and restart while the process runs (KNSH-047).
    pub sandbox_violations: SandboxViolations,
}

impl Capabilities {
    /// Whether `backend` works here. Checkpoints count as present when at least one root has a backend.
    #[must_use]
    pub fn has(&self, backend: Backend) -> bool {
        match backend {
            Backend::Sandbox => self.sandbox != Sandbox::None,
            Backend::NetworkFilter => self.network_filter != NetworkFilter::None,
            Backend::FileEvents => self.file_events != FileEvents::None,
            Backend::Secrets => self.secrets != Secrets::None,
            Backend::Checkpoints => self.checkpoints.values().any(|root| *root != CheckpointBackend::None),
        }
    }

    /// The backend fields as a JSON object: `sandbox`, `network_filter`, `file_events`, `secrets`, `checkpoints`
    /// and `sandbox_violations`. `hello` adds `methods` and `deprecated` to it.
    ///
    /// # Errors
    ///
    /// [`JsonError`] only if the object cannot be built (it always can for these fixed keys).
    pub fn to_object(&self) -> Result<Object, JsonError> {
        let mut checkpoints = Object::new();
        for (root, backend) in &self.checkpoints {
            checkpoints.insert(root.clone(), Value::from(backend.as_str()))?;
        }
        Object::new()
            .with("sandbox", self.sandbox.as_str())?
            .with("network_filter", self.network_filter.as_str())?
            .with("file_events", self.file_events.as_str())?
            .with("secrets", self.secrets.as_str())?
            .with("checkpoints", checkpoints)?
            .with("sandbox_violations", self.sandbox_violations.as_str())
    }
}

impl ToJson for Capabilities {
    fn to_json(&self) -> Result<Value, JsonError> {
        self.to_object().map(Value::Object)
    }
}

/// The `platform` string of `hello`: `macos-<major>-<arch>`, for example `macos-15-arm64`.
///
/// The major version comes from the probe; when it cannot be read it is written `unknown` rather than guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Platform {
    os: &'static str,
    major: Option<u32>,
    arch: &'static str,
}

impl Platform {
    /// The platform of this build, with the probed OS major version (`None` if the probe failed).
    ///
    /// The OS and architecture are those `knshd` was compiled for. Rust's OS name is already the wire name
    /// (`macos`); the architecture is renamed the way Apple names it (`arm64`, not Rust's `aarch64`).
    #[must_use]
    pub const fn this_build(major: Option<u32>) -> Self {
        Self::new(std::env::consts::OS, major, arch_name(std::env::consts::ARCH))
    }

    /// A platform from its parts. `os` and `arch` must already be wire names (`macos`, `arm64`).
    #[must_use]
    pub const fn new(os: &'static str, major: Option<u32>, arch: &'static str) -> Self {
        Self { os, major, arch }
    }

    /// The OS major version, if known.
    #[must_use]
    pub const fn major(&self) -> Option<u32> {
        self.major
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.major {
            Some(major) => write!(f, "{}-{major}-{}", self.os, self.arch),
            None => write!(f, "{}-unknown-{}", self.os, self.arch),
        }
    }
}

/// Rust's architecture name to Apple's (`uname -m`).
const fn arch_name(rust_arch: &'static str) -> &'static str {
    if const_eq(rust_arch, "aarch64") {
        "arm64"
    } else {
        rust_arch
    }
}

/// String equality usable in a `const fn`: compared byte by byte, since `==` on `str` is not const.
const fn const_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nothing() -> Capabilities {
        Capabilities {
            sandbox: Sandbox::None,
            network_filter: NetworkFilter::None,
            file_events: FileEvents::None,
            secrets: Secrets::None,
            checkpoints: BTreeMap::new(),
            sandbox_violations: crate::capability::SandboxViolations::None,
        }
    }

    // KNSH-014: `macos-<major>-<arch>`, with Apple's architecture names; an unreadable version is `unknown`.
    #[test]
    fn platform_string_format() {
        assert_eq!(Platform::new("macos", Some(15), "arm64").to_string(), "macos-15-arm64");
        assert_eq!(
            Platform::new("macos", Some(26), "x86_64").to_string(),
            "macos-26-x86_64"
        );
        assert_eq!(Platform::new("macos", None, "arm64").to_string(), "macos-unknown-arm64");
        assert_eq!(arch_name("aarch64"), "arm64");
        assert_eq!(arch_name("x86_64"), "x86_64");

        let this = Platform::this_build(Some(15)).to_string();
        let parts: Vec<&str> = this.split('-').collect();
        assert_eq!(parts.len(), 3, "{this}");
        assert_eq!(parts[1], "15");
        assert_ne!(parts[2], "aarch64", "Rust's name must not leak onto the wire");
        #[cfg(target_os = "macos")]
        assert_eq!(parts[0], "macos");
    }

    // NFR-SEC-10: every backend field is present, and a missing one reads `none`.
    #[test]
    fn missing_backends_are_written_as_none() {
        let object = nothing().to_object().unwrap();
        for field in ["sandbox", "network_filter", "file_events", "secrets"] {
            assert_eq!(object.get(field).and_then(Value::as_str), Some(NONE), "{field}");
        }
        assert_eq!(
            object.get("checkpoints").and_then(Value::as_object).map(Object::len),
            Some(0)
        );
    }

    #[test]
    fn has_reports_present_backends_only() {
        let mut caps = nothing();
        for backend in [
            Backend::Sandbox,
            Backend::NetworkFilter,
            Backend::FileEvents,
            Backend::Secrets,
            Backend::Checkpoints,
        ] {
            assert!(!caps.has(backend), "{}", backend.name());
        }
        caps.sandbox = Sandbox::Seatbelt;
        caps.file_events = FileEvents::FsEvents;
        assert!(caps.has(Backend::Sandbox) && caps.has(Backend::FileEvents));

        // A root that cannot be checkpointed does not make checkpoints available.
        caps.checkpoints.insert("/a".to_owned(), CheckpointBackend::None);
        assert!(!caps.has(Backend::Checkpoints));
        caps.checkpoints.insert("/b".to_owned(), CheckpointBackend::ApfsClone);
        assert!(caps.has(Backend::Checkpoints));
        let object = caps.to_object().unwrap();
        let roots = object.get("checkpoints").and_then(Value::as_object).unwrap();
        assert_eq!(roots.get("/a").and_then(Value::as_str), Some("none"));
        assert_eq!(roots.get("/b").and_then(Value::as_str), Some("apfs-clone"));
        assert_eq!(object.get("sandbox").and_then(Value::as_str), Some("seatbelt"));
    }
}
