//! The fixed denies (KNSH-041; FR-POL-30, FR-SBX-05, FR-SBX-10): engine files, the endpoint sockets and the control
//! service, denied to every envelope and command whatever the profile says.
//!
//! The set is compiled into the binary, here, and is the one source of the engine's location literals: `knsh-platform`
//! builds its engine directories from [`ENGINE_DATA_DIR`] and [`ENGINE_CONFIG_DIR`] and names the control service
//! [`CONTROL_SERVICE`], so the paths the engine uses and the paths every profile denies cannot drift apart.
//!
//! Two things use it:
//!
//! - **The loader** refuses a profile that would allow a fixed deny ([`FixedDenies::covers`]): a path in `fs.read`
//!   (as a list), `fs.write`, `exec.trusted_folders`, `exec.bash` or `checkpoints.roots` that is an engine path or
//!   lies below one is an error naming the key ([`ProfileErrorKind::FixedDeny`](crate::ProfileErrorKind::FixedDeny)).
//!   A path *above* an engine path (`fs.write = ["~"]`) is accepted: the sandbox compiler adds the fixed denies after
//!   the profile's rules, so they carve the engine paths out of it (KNSH-044). `fs.deny` may name them freely.
//! - **The sandbox compiler** (KNSH-044, KNSH-045) denies [`FixedDenies::paths`] and [`FixedDenies::services`] in
//!   every profile it writes. No profile key names a Mach service or a socket, so nothing can allow those but a path.
//!
//! Engine paths are compared component by component, ignoring ASCII case: the home volume is case-insensitive by
//! default on macOS, so `~/library/application support/KNSH` names the same directory. On a case-sensitive volume this
//! can refuse a path that only differs in case, which fails closed.
//!
//! Checkpoint stores on other volumes (KNSH-078) are folders named [`VOLUME_CHECKPOINT_DIR`] at the volume's root,
//! wherever it is mounted, so they cannot be listed per home: the name itself is reserved. [`FixedDenies::covers`]
//! refuses any path with a `.knsh-checkpoints` component (ignoring ASCII case), and the sandbox compiler denies it
//! with a regex in every profile.

use std::path::{Component, Path};

use crate::path::CanonicalPath;

/// The engine data directory, relative to the home directory: records, grants, pushed policy, checkpoints for the
/// home volume, and the endpoint sockets in its `run/` folder (`specs/09-reference/file-locations.md`).
pub const ENGINE_DATA_DIR: [&str; 3] = ["Library", "Application Support", "knsh"];

/// The engine configuration directory, relative to the home directory: configuration, hooks and policy files.
pub const ENGINE_CONFIG_DIR: [&str; 2] = [".config", "knsh"];

/// The endpoint socket directory, inside [`ENGINE_DATA_DIR`].
pub const ENGINE_RUN_DIR: &str = "run";

/// The agent endpoint socket, inside [`ENGINE_RUN_DIR`]: the only Unix socket an envelope may connect to (FR-SBX-05).
pub const AGENT_SOCKET: &str = "agent.sock";

/// The user endpoint socket, inside [`ENGINE_RUN_DIR`]: denied to every envelope and command (FR-SBX-05).
pub const USER_SOCKET: &str = "user.sock";

/// The checkpoint store on an APFS volume other than the home volume, at that volume's root (FR-CKP-35,
/// `specs/09-reference/file-locations.md`). Any path component with this name is a fixed deny.
pub const VOLUME_CHECKPOINT_DIR: &str = ".knsh-checkpoints";

/// The XPC Mach service of the control endpoint (`specs/09-reference/file-locations.md`; the final name is tied to
/// the signing identity).
pub const CONTROL_SERVICE: &str = "knsh.control";

/// The Mach services every profile denies.
const FIXED_SERVICES: [&str; 1] = [CONTROL_SERVICE];

/// The fixed denies for one home directory (module documentation).
///
/// Invariant: every path is canonical and lies below the home directory it was built for; the sockets
/// (`run/agent.sock`, `run/user.sock`) and every other engine file lie below one of them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FixedDenies {
    paths: [CanonicalPath; 2],
    agent_socket: CanonicalPath,
    user_socket: CanonicalPath,
}

impl FixedDenies {
    /// The fixed denies below `home`, the user's canonical home directory.
    #[must_use]
    pub fn for_home(home: &CanonicalPath) -> Self {
        let data = join(home, &ENGINE_DATA_DIR);
        Self {
            agent_socket: join(&data, &[ENGINE_RUN_DIR, AGENT_SOCKET]),
            user_socket: join(&data, &[ENGINE_RUN_DIR, USER_SOCKET]),
            paths: [data, join(home, &ENGINE_CONFIG_DIR)],
        }
    }

    /// The directory trees denied to every envelope and command: the engine data and configuration directories.
    #[must_use]
    pub fn paths(&self) -> &[CanonicalPath] {
        &self.paths
    }

    /// `run/agent.sock` in the engine data directory: the socket an envelope connects to. It lies below
    /// [`FixedDenies::paths`], so files cannot reach it; only a Unix-socket connection rule can (KNSH-045).
    #[must_use]
    pub fn agent_socket(&self) -> &CanonicalPath {
        &self.agent_socket
    }

    /// `run/user.sock` in the engine data directory: denied to every envelope and command (FR-SBX-05).
    #[must_use]
    pub fn user_socket(&self) -> &CanonicalPath {
        &self.user_socket
    }

    /// The Mach services denied to every envelope and command: the control service.
    #[must_use]
    pub fn services(&self) -> &'static [&'static str] {
        &FIXED_SERVICES
    }

    /// Whether `path` is a fixed-deny path or lies below one, or is (or lies in) a checkpoint store on another volume
    /// (any [`VOLUME_CHECKPOINT_DIR`] component), ignoring ASCII case (module documentation), so that allowing it
    /// would allow engine files.
    #[must_use]
    pub fn covers(&self, path: &CanonicalPath) -> bool {
        self.paths
            .iter()
            .any(|denied| starts_with_ignoring_case(path.as_path(), denied.as_path()))
            || path.as_path().components().any(|component| {
                component
                    .as_os_str()
                    .as_encoded_bytes()
                    .eq_ignore_ascii_case(VOLUME_CHECKPOINT_DIR.as_bytes())
            })
    }
}

/// `base` joined with each of `components`. A canonical path joined with plain names (no `/`, `.` or `..`) stays
/// canonical, so the constructor's check cannot fail; it is still checked rather than assumed.
fn join(base: &CanonicalPath, components: &[&str]) -> CanonicalPath {
    let mut path = base.as_path().to_path_buf();
    path.extend(components);
    // Unreachable with the constants above; should it ever happen, the base (the home, or the engine data
    // directory, itself denied) stands in, which fails closed: denying it denies more, and no socket rule allows it.
    CanonicalPath::new(path).unwrap_or_else(|_| base.clone())
}

/// Whether `path` equals `prefix` or lies below it, comparing whole components with ASCII case ignored.
fn starts_with_ignoring_case(path: &Path, prefix: &Path) -> bool {
    let mut path = path.components();
    prefix
        .components()
        .all(|wanted| path.next().is_some_and(|found| same_component(found, wanted)))
}

/// Whether two path components are equal, ignoring ASCII case.
fn same_component(a: Component<'_>, b: Component<'_>) -> bool {
    a.as_os_str()
        .as_encoded_bytes()
        .eq_ignore_ascii_case(b.as_os_str().as_encoded_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(path: &str) -> CanonicalPath {
        CanonicalPath::new(path).unwrap()
    }

    #[test]
    fn fixed_denies_cover_engine_dirs_and_sockets() {
        let denies = FixedDenies::for_home(&canonical("/Users/u"));
        assert_eq!(
            denies.paths(),
            [
                canonical("/Users/u/Library/Application Support/knsh"),
                canonical("/Users/u/.config/knsh"),
            ]
        );
        assert_eq!(denies.services(), ["knsh.control"]);
        assert_eq!(
            denies.agent_socket(),
            &canonical("/Users/u/Library/Application Support/knsh/run/agent.sock")
        );
        assert_eq!(
            denies.user_socket(),
            &canonical("/Users/u/Library/Application Support/knsh/run/user.sock")
        );
        assert!(denies.covers(denies.agent_socket()) && denies.covers(denies.user_socket()));
        for covered in [
            "/Users/u/Library/Application Support/knsh",
            "/Users/u/Library/Application Support/knsh/run/user.sock",
            "/Users/u/Library/Application Support/knsh/run/agent.sock",
            "/Users/u/.config/knsh/policies",
            // The home volume is case-insensitive by default.
            "/Users/u/library/application support/KNSH/records.db",
            "/users/U/.CONFIG/knsh",
            // Checkpoint stores on other volumes, wherever they are mounted (KNSH-078).
            "/Volumes/External/.knsh-checkpoints",
            "/Volumes/External/.knsh-checkpoints/format",
            "/Volumes/External/.KNSH-Checkpoints/x",
        ] {
            assert!(denies.covers(&canonical(covered)), "{covered}");
        }
        for open in [
            "/Users/u",
            "/Users/u/Library",
            "/Users/u/Library/Application Support",
            "/Users/u/Library/Application Support/knsh2",
            "/Users/u/.config",
            "/Users/u/.config/knshx",
            "/Users/v/.config/knsh",
            "/Volumes/External",
            "/Volumes/External/.knsh-checkpoints2",
            "/Volumes/External/knsh-checkpoints",
        ] {
            assert!(!denies.covers(&canonical(open)), "{open}");
        }
    }
}
