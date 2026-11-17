//! Pushed-policy expiry and `profile.use` (KNSH-072; FR-POL-51, FR-POL-52, FR-SES-13;
//! `specs/06-api/control-service.md#policyset`, `specs/06-api/user-socket.md#profileuse`).
//!
//! # Pausing at expiry
//!
//! From a snapshot's `expires_at` on, its profile loads from nothing (`crate::pushed`), so every line of a session
//! using it is already denied. [`PolicyExpiry::check`], run every [`CHECK_PERIOD`] by a watcher thread, also pauses
//! each active agent session using it (`session.state_changed`, FR-SES-13): one whose profile is the expired snapshot,
//! or `extends` it. A clock that cannot be read makes every snapshot count as expired, as it does for loading. A
//! session under human control is left to the human; once handed back it is active again and the next check pauses
//! it. Human sessions are never paused (FR-SES-22).
//!
//! # Resuming: only two events
//!
//! A session paused here resumes only when (FR-POL-51):
//!
//! 1. **The authority pushes a snapshot** with which its profile loads again: `policy.set` calls
//!    [`PolicyExpiry::snapshot_pushed`], which resumes it under its own profile.
//! 2. **The user runs `knsh profile use <name>`** (`profile.use` on `user.sock`) and passes `knshd`'s Touch ID or
//!    password prompt: every session paused here then runs under the signed local profile `<name>` and resumes.
//!
//! Nothing else resumes it (`session.resume` is refused, `crate::sessions`) and nothing else changes a session's
//! profile, so the engine never moves a session to another policy on its own (FR-POL-52).
//!
//! # `profile.use`
//!
//! `<name>` must be a signed local profile: a file in the policies directory whose signature verifies, loading with
//! its `extends` chain read from files only. The built-in `unattended` profile, a name the authority pushed a snapshot
//! for, and a profile extending one are refused (`-32602` with `data.reason`): the loader reads a snapshot in place of
//! a file of the same name, so such a profile would not run as the local file says. With no session paused by expiry,
//! nothing is asked and the answer lists no session. Otherwise the prompt names the profile and the number of
//! sessions; any outcome but success is `-32001` with `source: "user"` and nothing changes. The profile is checked
//! again after the prompt, and only sessions still paused by expiry are moved. An envelope already running keeps the
//! sandbox profile it started with; its new lines are decided with the selected profile.
//!
//! Selections are serialised by [`PolicyExpiry::selecting`], held across the prompt. A check and the resumption after
//! a push are serialised by [`PolicyExpiry::watching`]: a check that read the snapshots before a push either pauses
//! before the resumption runs (which then resumes the session) or waits for it, so a session is never left paused
//! under policy that loads again. Lock order: either lock (never both), then the pushed snapshots' or the registry's
//! (`crate::pushed`, `crate::sessions`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use knsh_core::{ProfileName, ProfileOrigin, SessionId, UNATTENDED_PROFILE, load_profile};
use knsh_platform::{Field, Level, PromptReason, SystemLog, UserPresence, Value};
use knsh_proto::{ProfileUseParams, ProfileUseResult, RpcError};

use crate::dispatch::{Call, Handler, Handlers, Reply, answer, params};
use crate::policy::ProfileLoader;
use crate::policy_edit::{invalid_text, not_authenticated, user_only};
use crate::pushed::PushedPolicies;
use crate::sessions::Sessions;

/// How often the watcher looks for expired snapshots. Lines of a session using one are denied from `expires_at` on
/// whatever the period; the period only bounds how late the session is paused.
pub(crate) const CHECK_PERIOD: Duration = Duration::from_secs(1);

/// How long the `profile.use` prompt waits for the user: the same as a policy edit's, shorter than the CLI's read
/// timeout, so the CLI always gets the answer.
pub(crate) const PROFILE_PROMPT_TIMEOUT: Duration = crate::policy_edit::EDIT_PROMPT_TIMEOUT;

/// The method name.
const PROFILE_USE: &str = "profile.use";

/// What is in the log line of a session paused or resumed here; never a profile's text.
const EVENT: &str = "session.state_changed";

/// Pauses sessions on expired pushed policy and resumes them on the two events of the module documentation. One per
/// `knshd`.
pub(crate) struct PolicyExpiry {
    sessions: Arc<Sessions>,
    pushed: Arc<PushedPolicies>,
    /// Loads profiles as lines do (snapshots in front of files), and reads the policies directory alone.
    profiles: ProfileLoader,
    /// `knshd`'s own Touch ID or password prompt.
    presence: Arc<dyn UserPresence>,
    /// Fixed reasons only.
    log: Arc<dyn SystemLog>,
    /// Serialises `profile.use` (module documentation).
    selecting: Mutex<()>,
    /// Serialises [`PolicyExpiry::check`] and [`PolicyExpiry::snapshot_pushed`] (module documentation).
    watching: Mutex<()>,
}

impl PolicyExpiry {
    /// The service over `sessions` and `pushed`, loading with `profiles` and prompting through `presence`.
    pub(crate) fn new(
        sessions: Arc<Sessions>,
        pushed: Arc<PushedPolicies>,
        profiles: ProfileLoader,
        presence: Arc<dyn UserPresence>,
        log: Arc<dyn SystemLog>,
    ) -> Arc<Self> {
        Arc::new(Self {
            sessions,
            pushed,
            profiles,
            presence,
            log,
            selecting: Mutex::new(()),
            watching: Mutex::new(()),
        })
    }

    /// The `profile.use` handler.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let expiry = Arc::clone(self);
        let handler: Handler = Arc::new(move |call: &Call<'_>| expiry.use_profile(call));
        [(PROFILE_USE, handler)].into_iter().collect()
    }

    /// Starts the watcher thread, running [`PolicyExpiry::check`] every `period` for as long as the service lives.
    ///
    /// # Errors
    ///
    /// The thread could not be started. Lines on expired policy are still denied; their sessions are not paused.
    pub(crate) fn watch(self: &Arc<Self>, period: Duration) -> std::io::Result<()> {
        // Weak: the thread must not keep the service alive on its own.
        let expiry = Arc::downgrade(self);
        thread::Builder::new()
            .name(String::from("knshd-policy-expiry"))
            .spawn(move || {
                loop {
                    thread::sleep(period);
                    let Some(expiry) = expiry.upgrade() else {
                        return;
                    };
                    expiry.check();
                }
            })
            .map(drop)
    }

    /// Pauses every active agent session using an expired snapshot (module documentation, "Pausing at expiry").
    pub(crate) fn check(&self) {
        // Held to the last pause: a push stored meanwhile resumes only after this check, never before it.
        let _watching = self.watching.lock().unwrap_or_else(PoisonError::into_inner);
        let expired = self.pushed.expired();
        if expired.is_empty() {
            return;
        }
        // Each profile is judged once per check, however many sessions use it.
        let mut uses: BTreeMap<ProfileName, bool> = BTreeMap::new();
        for (session_id, profile) in self.sessions.active_agents() {
            let affected = *uses
                .entry(profile.clone())
                .or_insert_with(|| self.uses_expired(&profile, &expired));
            // A session that ended or moved since it was listed is refused and left as it is.
            if affected && self.sessions.pause_for_expiry(session_id).is_ok() {
                self.log.log(
                    Level::Notice,
                    "agent session paused: the pushed policy it uses expired",
                    &[Field::new("event", Value::Static(EVENT))],
                );
            }
        }
    }

    /// Resumes every session paused by expiry whose profile loads again, under its own profile: the authority pushed
    /// a snapshot (`policy.set`, after the snapshot is stored). A profile that still does not load keeps its sessions
    /// paused.
    pub(crate) fn snapshot_pushed(&self) {
        // Waits for a check that may have read the snapshots before this push, so its pauses are undone here.
        let _watching = self.watching.lock().unwrap_or_else(PoisonError::into_inner);
        for (session_id, profile) in self.sessions.expiry_paused() {
            if self.profiles.load(&profile, self.profiles.home()).is_ok()
                && self.sessions.release_from_expiry(session_id).is_ok()
            {
                self.log.log(
                    Level::Notice,
                    "agent session resumed: the authority pushed policy for it",
                    &[Field::new("event", Value::Static(EVENT))],
                );
            }
        }
    }

    /// Whether `profile` is an expired snapshot or extends one: it does not load, and the snapshot is what failed.
    fn uses_expired(&self, profile: &ProfileName, expired: &BTreeSet<ProfileName>) -> bool {
        if expired.contains(profile) {
            return true;
        }
        match self.profiles.load(profile, self.profiles.home()) {
            Ok(_) => false,
            // An expired snapshot reads as unreadable, and the error names the profile that could not be read.
            Err(error) => matches!(error.origin(), Some(ProfileOrigin::Profile(name)) if expired.contains(name)),
        }
    }

    /// `profile.use` (module documentation, "`profile.use`").
    fn use_profile(&self, call: &Call<'_>) -> Reply {
        // FR-POL-51: only the user selects a local profile; the catalogue already keeps the method off the other
        // endpoints, and this is the second lock on the door.
        user_only(call)?;
        let ProfileUseParams { profile } = params(call)?;
        // Refused before the prompt, so the user is never asked to confirm a profile that could not be used.
        self.check_local(&profile)?;
        // Held across the prompt: a second selection waits, then sees only the sessions the first left paused.
        let _selecting = self.selecting.lock().unwrap_or_else(PoisonError::into_inner);
        let paused: Vec<SessionId> = self
            .sessions
            .expiry_paused()
            .into_iter()
            .map(|(session_id, _)| session_id)
            .collect();
        // Nothing to move, so nothing to authorise: no prompt is shown for an empty selection.
        if paused.is_empty() {
            return answer(&ProfileUseResult {
                profile,
                sessions: Vec::new(),
            });
        }

        let count = paused.len();
        let detail = format!(
            "{profile} for {count} agent session{} paused by expired pushed policy",
            if count == 1 { "" } else { "s" }
        );
        let reason = PromptReason::change("use the local policy profile", &detail);
        let proof = self
            .presence
            .authenticate(&reason, PROFILE_PROMPT_TIMEOUT)
            // Any outcome but success is `-32001` from the user, and no session moves (decision 12).
            .map_err(|refusal| {
                self.log
                    .log(Level::Notice, "profile selection refused: not authenticated", &[]);
                not_authenticated(&refusal)
            })?;

        // The authority may have pushed a snapshot of this name (or of a parent) while the prompt was up.
        self.check_local(&profile)?;
        // Only sessions the prompt counted, and only those still paused by expiry: one resumed by a new snapshot in
        // the meantime, or ended, is refused by `Sessions` and left out of the answer, so it keeps its own profile.
        let sessions: Vec<SessionId> = paused
            .into_iter()
            .filter(|session_id| {
                self.sessions
                    .select_profile_after_expiry(*session_id, profile.clone(), &proof)
                    .is_ok()
            })
            .collect();
        self.log.log(
            Level::Notice,
            "local policy profile selected for agent sessions paused by expired pushed policy",
            &[Field::new("event", Value::Static(PROFILE_USE))],
        );
        answer(&ProfileUseResult { profile, sessions })
    }

    /// `-32602` with `data.reason` unless `profile` is a signed local profile (module documentation).
    fn check_local(&self, profile: &ProfileName) -> Result<(), RpcError> {
        // The built-in profile has no file, so no signature the user could have approved.
        if profile.as_str() == UNATTENDED_PROFILE {
            return Err(invalid_text(
                "profile: unattended is built in, not a signed local profile",
            ));
        }
        // Lines load a snapshot in place of the file of its name, so the file the user names would not be what runs.
        if self.pushed.get(profile).is_some() {
            return Err(invalid_text("profile: pushed by the authority, not a local profile"));
        }
        // Files only: the policies directory checks each file's signature (FR-POL-42), and no snapshot is read.
        let directory = self.profiles.directory();
        let context = self.profiles.context(self.profiles.home());
        // A missing, unsigned, tampered or invalid file is refused with the loader's reason.
        let loaded = load_profile(profile, &directory, &context, self.profiles.fs())
            .map_err(|error| invalid_text(&error.to_string()))?;
        // The same holds for a parent: lines would read its snapshot, not the file this load just checked.
        if let Some(parent) = loaded.extends.iter().find(|parent| self.pushed.get(parent).is_some()) {
            return Err(invalid_text(&format!(
                "profile: extends {parent}, which the authority pushes"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
