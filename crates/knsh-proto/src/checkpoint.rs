//! Checkpoint methods on the wire.
//!
//! - KNSH-084: the `-32004` error of an undo or redo that would overwrite work the engine did not record (FR-CKP-20,
//!   `specs/06-api/errors.md`).
//! - KNSH-086: `checkpoint.restore` (every root back to a state) and `checkpoint.diff` (the paths that differ between
//!   two states, with a unified diff of each text file), `specs/03-functional-requirements/checkpoints.md#history-tree`.
//!   Each diff travels as raw bytes beside the JSON answer: a binary stream the answer names (`stream_id`, `size`,
//!   `content_type`), closed by an end-of-stream frame, or inline base64 for a client that opted out of binary frames
//!   (`specs/06-api/wire-format.md`).
//!
//! - KNSH-088: `checkpoint.undo` and `checkpoint.redo` (one change, by its line or its checkpoint), `checkpoint.list`
//!   (the changes of the history, with where each stands), and how a refusal of the history becomes an API error
//!   ([`history_error`]).
//!
//! Parameters come from untrusted clients: each is bounded and parsed strictly, and anything else is `-32602`.

use std::io::Write;

use knsh_core::{
    Attribution, CanonicalPath, CheckpointId, Diff, DiffTarget, FileDiff, HistoryError, RecordId, RestoreConflict,
    RestoreOperation, SessionId, StateId, TextDiff, Timestamp, TornPath,
};
use knsh_json::{Fields, FrameWriter, FromJson, JsonError, MAX_OPEN_STREAMS, Object, StreamId, ToJson, Value};

use crate::envelope::RpcError;
use crate::error_code::ErrorCode;
use crate::hello::ByteTransport;

/// The most paths one `checkpoint.diff` answer lists, and its default: each may open a binary stream, and a client
/// may have at most this many open at once.
pub const MAX_DIFF_PAGE: u32 = 256;

/// The content type announced for a diff stream: a unified diff, UTF-8.
pub const DIFF_CONTENT_TYPE: &str = "text/x-diff";

/// The most diff bytes one `checkpoint.diff` answer carries inline as base64 (384 KiB, about 512 KiB encoded), so
/// the answer, with up to [`MAX_DIFF_PAGE`] paths listed, fits in one 1 MB frame. The answer ends before the diff
/// that would pass it; a single diff larger than this is sent as `too_large` to such a client.
pub const MAX_BASE64_DIFF: usize = 384 * 1024;

/// The most restored paths a `checkpoint.restore` answer lists; `files_restored` counts them all.
pub const MAX_LISTED_RESTORED: usize = 1_000;

// `MAX_DIFF_PAGE` streams may be open at once on the client.
const _: () = assert!(MAX_DIFF_PAGE as usize <= MAX_OPEN_STREAMS);

/// The `-32004` error for `conflicts`: `data.conflicts` holds one `{"path", "reason"}` object per conflicting path, in
/// the order given. Nothing was restored (FR-CKP-20: no partial restore).
#[must_use]
pub fn undo_conflict(conflicts: &[RestoreConflict]) -> RpcError {
    match conflicts_data(conflicts) {
        Ok(data) => RpcError::new(ErrorCode::UndoConflict).with_data(Value::Object(data)),
        // A key written twice is a bug here, never input; the code alone still says what happened.
        Err(_) => RpcError::new(ErrorCode::UndoConflict),
    }
}

fn conflicts_data(conflicts: &[RestoreConflict]) -> Result<Object, JsonError> {
    let mut list = Vec::with_capacity(conflicts.len());
    for conflict in conflicts {
        // Paths are shown like `cwd`: APFS names are UTF-8, anything else gets U+FFFD.
        let entry = Object::new()
            .with("path", conflict.path.as_path().to_string_lossy().into_owned())?
            .with("reason", conflict.reason.as_str())?;
        list.push(Value::Object(entry));
    }
    Object::new().with("conflicts", Value::Array(list))
}

/// `-32004` for an older change that later changes overlap (FR-CKP-30): `data.conflicts` lists each path both
/// touched with the reason `later_change`. A change whose path list was cut short or scrubbed overlaps every later
/// change, so the list may be empty or partial: the refusal stands either way. Nothing was restored.
#[must_use]
pub fn overlap_conflict(paths: &[CanonicalPath]) -> RpcError {
    let mut list = Vec::with_capacity(paths.len());
    for path in paths {
        match Object::new()
            .with("path", path_text(path))
            .and_then(|entry| entry.with("reason", LATER_CHANGE))
        {
            Ok(entry) => list.push(Value::Object(entry)),
            // Fixed keys written once: cannot fail. The code alone still says what happened.
            Err(_) => return RpcError::new(ErrorCode::UndoConflict),
        }
    }
    match Object::new().with("conflicts", Value::Array(list)) {
        Ok(data) => RpcError::new(ErrorCode::UndoConflict).with_data(Value::Object(data)),
        Err(_) => RpcError::new(ErrorCode::UndoConflict),
    }
}

/// The `-32004` conflict reason of a path a later change also touched (FR-CKP-30, KNSH-088).
pub const LATER_CHANGE: &str = "later_change";

/// The most conflicting paths one `-32004` answer lists, so the answer always fits a frame.
pub const MAX_LISTED_CONFLICTS: usize = 1_000;

/// The API error for a refusal of the history tree (KNSH-088, `specs/06-api/errors.md`):
///
/// - an older change overlapped by later ones (FR-CKP-30) is `-32004` with each shared path ([`overlap_conflict`],
///   at most [`MAX_LISTED_CONFLICTS`]);
/// - a change or state the history does not know, or can no longer act on, is `-32602` with `data.reason`:
///   `unknown`, `expired` (removed by retention or `knsh forget --with-checkpoints`), `not_in_effect` (already
///   undone, or on a branch the head left), `not_undone` (nothing to redo), or `redo_blocked` (a later change started
///   another branch: `checkpoint.restore` returns to it);
/// - anything else is the engine's own failure, `-32603` with no detail.
#[must_use]
pub fn history_error(error: &HistoryError) -> RpcError {
    let reason = match error {
        HistoryError::Conflict { paths, .. } => {
            let listed: Vec<CanonicalPath> = paths.iter().take(MAX_LISTED_CONFLICTS).cloned().collect();
            return overlap_conflict(&listed);
        }
        HistoryError::UnknownChange | HistoryError::UnknownState => "unknown",
        HistoryError::Expired => "expired",
        HistoryError::NotInEffect => "not_in_effect",
        HistoryError::NotUndone => "not_undone",
        HistoryError::RedoBlocked => "redo_blocked",
        HistoryError::Stale
        | HistoryError::SavedVersions
        | HistoryError::DuplicateCheckpoint
        | HistoryError::DuplicateRecord
        | HistoryError::StatesExhausted
        | HistoryError::UnencodablePath
        | HistoryError::TooLarge
        | HistoryError::NewerFormat(_)
        | HistoryError::Corrupt => return RpcError::new(ErrorCode::InternalError),
    };
    match Object::new().with("reason", reason) {
        Ok(data) => RpcError::new(ErrorCode::InvalidParams).with_data(Value::Object(data)),
        Err(_) => RpcError::new(ErrorCode::InvalidParams),
    }
}

/// Which change `checkpoint.undo` or `checkpoint.redo` acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeTarget {
    /// A line's change (`record_id`): for a line of a concurrent set, the whole set (FR-CKP-07).
    Record(RecordId),
    /// The change a checkpoint holds (`checkpoint_id`), such as a run of agent edits, which has no line.
    Checkpoint(CheckpointId),
}

/// The parameters of `checkpoint.undo` and `checkpoint.redo` (KNSH-088): exactly one of `record_id` and
/// `checkpoint_id`, and `force`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointUndoParams {
    /// The change.
    pub target: ChangeTarget,
    /// Restore paths whose identity no longer matches, and possibly-torn paths (user and authority only,
    /// FR-CKP-21); `false` when absent. `knshd` refuses it on `agent.sock` before anything else.
    pub force: bool,
}

impl FromJson for CheckpointUndoParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let record_id = fields.optional::<String>("record_id")?;
        let checkpoint_id = fields.optional::<String>("checkpoint_id")?;
        let force = fields.optional::<bool>("force")?.unwrap_or(false);
        fields.finish()?;
        let target = match (record_id, checkpoint_id) {
            (Some(record), None) => ChangeTarget::Record(record.parse().map_err(|_| out_of_range("record_id"))?),
            (None, Some(checkpoint)) => {
                ChangeTarget::Checkpoint(checkpoint.parse().map_err(|_| out_of_range("checkpoint_id"))?)
            }
            // Neither or both: never guessed at.
            (None, None) | (Some(_), Some(_)) => return Err(out_of_range("record_id")),
        };
        Ok(Self { target, force })
    }
}

impl ToJson for CheckpointUndoParams {
    /// `force` is written only when set.
    fn to_json(&self) -> Result<Value, JsonError> {
        let mut object = match self.target {
            ChangeTarget::Record(record) => Object::new().with("record_id", record.to_string())?,
            ChangeTarget::Checkpoint(checkpoint) => Object::new().with("checkpoint_id", checkpoint.to_string())?,
        };
        if self.force {
            object.insert("force", Value::from(true))?;
        }
        Ok(Value::Object(object))
    }
}

/// The result of `checkpoint.undo` and `checkpoint.redo` (KNSH-088).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointUndoResult {
    /// Undo or redo.
    pub operation: RestoreOperation,
    /// The change undone or redone: its checkpoint.
    pub checkpoint_id: CheckpointId,
    /// Its lines; empty for agent and external edits.
    pub record_ids: Vec<RecordId>,
    /// The checkpoint roots it covers.
    pub roots: Vec<CanonicalPath>,
    /// The state the history is in now.
    pub state_id: StateId,
    /// Every path restored, sorted.
    pub restored: Vec<CanonicalPath>,
    /// Excluded folders the change touched: not restored (FR-CKP-31).
    pub not_restored: Vec<CanonicalPath>,
    /// More excluded folders were changed than `not_restored` lists.
    pub not_restored_incomplete: bool,
    /// What the change did that no restore can undo (FR-CKP-36); its files were still restored.
    pub irreversible: Vec<String>,
    /// Whether `force` overrode a check.
    pub forced: bool,
    /// Possibly-torn files skipped (FR-CKP-24).
    pub skipped_torn: Vec<TornPath>,
    /// Possibly-torn files restored under `force` (FR-CKP-24).
    pub forced_torn: Vec<TornPath>,
}

impl ToJson for CheckpointUndoResult {
    /// `{"operation", "checkpoint_id", "record_ids", "roots", "state_id", "files_restored", "restored",
    /// "restored_incomplete", "not_restored", "not_restored_incomplete", "irreversible", "forced", "skipped_torn",
    /// "forced_torn"}`. `files_restored` counts every path restored; `restored` lists at most
    /// [`MAX_LISTED_RESTORED`] of them, so the answer always fits a frame.
    fn to_json(&self) -> Result<Value, JsonError> {
        let records: Vec<Value> = self.record_ids.iter().map(|id| Value::from(id.to_string())).collect();
        Ok(Value::Object(
            Object::new()
                .with("operation", self.operation.as_str())?
                .with("checkpoint_id", self.checkpoint_id.to_string())?
                .with("record_ids", Value::Array(records))?
                .with("roots", paths(&self.roots, usize::MAX))?
                .with("state_id", self.state_id.get().to_json()?)?
                .with("files_restored", (self.restored.len() as u64).to_json()?)?
                .with("restored", paths(&self.restored, MAX_LISTED_RESTORED))?
                .with("restored_incomplete", self.restored.len() > MAX_LISTED_RESTORED)?
                .with("not_restored", paths(&self.not_restored, usize::MAX))?
                .with("not_restored_incomplete", self.not_restored_incomplete)?
                .with("irreversible", strings(&self.irreversible))?
                .with("forced", self.forced)?
                .with("skipped_torn", torn_list(&self.skipped_torn)?)?
                .with("forced_torn", torn_list(&self.forced_torn)?)?,
        ))
    }
}

/// The most changes one `checkpoint.list` answer lists, and its default.
pub const MAX_LIST_PAGE: u32 = 256;

/// The parameters of `checkpoint.list` (KNSH-088).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointListParams {
    /// Only changes belonging to this session. On `agent.sock` it may only name the caller's own session.
    pub session_id: Option<SessionId>,
    /// The previous answer's `next_cursor`: only changes after that checkpoint.
    pub cursor: Option<CheckpointId>,
    /// Changes per answer, 1 to [`MAX_LIST_PAGE`]; [`MAX_LIST_PAGE`] when absent.
    pub limit: u32,
}

impl FromJson for CheckpointListParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let session_id = fields
            .optional::<String>("session_id")?
            .map(|id| id.parse().map_err(|_| out_of_range("session_id")))
            .transpose()?;
        let cursor = fields
            .optional::<String>("cursor")?
            .map(|id| id.parse().map_err(|_| out_of_range("cursor")))
            .transpose()?;
        let limit = fields.optional::<u32>("limit")?.unwrap_or(MAX_LIST_PAGE);
        fields.finish()?;
        if !(1..=MAX_LIST_PAGE).contains(&limit) {
            return Err(out_of_range("limit"));
        }
        Ok(Self {
            session_id,
            cursor,
            limit,
        })
    }
}

impl ToJson for CheckpointListParams {
    /// Absent filters are left out; `limit` is written only when not the default.
    fn to_json(&self) -> Result<Value, JsonError> {
        let mut object = Object::new();
        if let Some(session_id) = self.session_id {
            object.insert("session_id", Value::from(session_id.to_string()))?;
        }
        if let Some(cursor) = self.cursor {
            object.insert("cursor", Value::from(cursor.to_string()))?;
        }
        if self.limit != MAX_LIST_PAGE {
            object.insert("limit", self.limit.to_json()?)?;
        }
        Ok(Value::Object(object))
    }
}

/// What an edge of the history stands for, in `checkpoint.list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListedKind {
    /// A captured change, with how it was attributed.
    Change(Attribution),
    /// The undo of an older change made on top of later ones (a revert, FR-CKP-30): the change it reverted.
    Revert(CheckpointId),
}

/// Where a change stands relative to the current state, in `checkpoint.list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListedStatus {
    /// Part of the current state and not undone: `checkpoint.undo` applies.
    InEffect,
    /// Stepped back over by an undo, with the versions it replaced saved: `checkpoint.redo` applies while its
    /// parent state is the current one, `checkpoint.restore` otherwise.
    Undone,
    /// Reverted by a later undo, or on a branch the current state left without saved versions.
    Inactive,
    /// Removed by retention or `knsh forget --with-checkpoints`: nothing can be done with it any more.
    Expired,
}

impl ListedStatus {
    /// The wire value: `in_effect`, `undone`, `inactive` or `expired`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InEffect => "in_effect",
            Self::Undone => "undone",
            Self::Inactive => "inactive",
            Self::Expired => "expired",
        }
    }
}

/// One change of `checkpoint.list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedChange {
    /// Its checkpoint: what identifies it for undo and redo.
    pub checkpoint_id: CheckpointId,
    /// A change or a revert.
    pub kind: ListedKind,
    /// Its lines; empty for agent and external edits and reverts.
    pub record_ids: Vec<RecordId>,
    /// The sessions it belongs to (on `agent.sock`, only the caller's own).
    pub session_ids: Vec<SessionId>,
    /// The checkpoint roots it covers.
    pub roots: Vec<CanonicalPath>,
    /// How many paths it changed.
    pub files_changed: u64,
    /// It may be incomplete (FR-CKP-04).
    pub uncertain: bool,
    /// The state it starts from.
    pub from: StateId,
    /// The state it leads to.
    pub to: StateId,
    /// Where it stands.
    pub status: ListedStatus,
}

impl ToJson for ListedChange {
    /// `{"checkpoint_id", "created_at", "kind": "change" | "revert", "attribution", "reverts", "record_ids",
    /// "session_ids", "roots", "files_changed", "uncertain", "from", "to", "status"}`: `attribution` is null for a
    /// revert, `reverts` null for a change. `created_at` is the time in the checkpoint's ID (its first captured
    /// change, or the undo that made a revert).
    fn to_json(&self) -> Result<Value, JsonError> {
        let (kind, attribution, reverts) = match self.kind {
            ListedKind::Change(attribution) => ("change", Value::from(attribution.as_str()), Value::Null),
            ListedKind::Revert(of) => ("revert", Value::Null, Value::from(of.to_string())),
        };
        let created_at = self
            .checkpoint_id
            .ulid()
            .millis()
            .checked_mul(1_000)
            .and_then(|micros| Timestamp::from_unix_micros(micros).ok())
            .map_or(Value::Null, |time| Value::from(time.to_string()));
        let records: Vec<Value> = self.record_ids.iter().map(|id| Value::from(id.to_string())).collect();
        let sessions: Vec<Value> = self.session_ids.iter().map(|id| Value::from(id.to_string())).collect();
        Ok(Value::Object(
            Object::new()
                .with("checkpoint_id", self.checkpoint_id.to_string())?
                .with("created_at", created_at)?
                .with("kind", kind)?
                .with("attribution", attribution)?
                .with("reverts", reverts)?
                .with("record_ids", Value::Array(records))?
                .with("session_ids", Value::Array(sessions))?
                .with("roots", paths(&self.roots, usize::MAX))?
                .with("files_changed", self.files_changed.to_json()?)?
                .with("uncertain", self.uncertain)?
                .with("from", self.from.get().to_json()?)?
                .with("to", self.to.get().to_json()?)?
                .with("status", self.status.as_str())?,
        ))
    }
}

/// The result of `checkpoint.list` (KNSH-088).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointListResult {
    /// The current state.
    pub head: StateId,
    /// The changes of this page, oldest first (by checkpoint ID).
    pub changes: Vec<ListedChange>,
    /// The `cursor` of the next page; `None` on the last.
    pub next_cursor: Option<CheckpointId>,
}

impl ToJson for CheckpointListResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new()
                .with("head", self.head.get().to_json()?)?
                .with("changes", self.changes.to_json()?)?
                .with(
                    "next_cursor",
                    self.next_cursor
                        .map_or(Value::Null, |cursor| Value::from(cursor.to_string())),
                )?,
        ))
    }
}

/// The parameters of `checkpoint.restore` (`user.sock` and the authority only, KNSH-086).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointRestoreParams {
    /// The state to return every root to.
    pub state_id: StateId,
    /// Restore paths whose identity no longer matches, and possibly-torn paths (FR-CKP-21, FR-CKP-24); `false` when
    /// absent.
    pub force: bool,
}

impl FromJson for CheckpointRestoreParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let state_id = state(fields.required::<u64>("state_id")?, "state_id")?;
        let force = fields.optional::<bool>("force")?.unwrap_or(false);
        fields.finish()?;
        Ok(Self { state_id, force })
    }
}

/// One change a `checkpoint.restore` undid or redid on its way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredChange {
    /// The change's checkpoint.
    pub checkpoint_id: CheckpointId,
    /// Undone or redone.
    pub operation: RestoreOperation,
    /// Its lines.
    pub record_ids: Vec<RecordId>,
    /// How many paths this step restored.
    pub files_restored: u64,
}

impl ToJson for RestoredChange {
    fn to_json(&self) -> Result<Value, JsonError> {
        let records: Vec<Value> = self.record_ids.iter().map(|id| Value::from(id.to_string())).collect();
        Ok(Value::Object(
            Object::new()
                .with("checkpoint_id", self.checkpoint_id.to_string())?
                .with("operation", self.operation.as_str())?
                .with("record_ids", Value::Array(records))?
                .with("files_restored", self.files_restored.to_json()?)?,
        ))
    }
}

/// The result of `checkpoint.restore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRestoreResult {
    /// The state before.
    pub from: StateId,
    /// The state now: the one asked for.
    pub state_id: StateId,
    /// Each change undone (newest first), then each change of the target's branch redone (oldest first).
    pub changes: Vec<RestoredChange>,
    /// Every path restored, sorted.
    pub restored: Vec<CanonicalPath>,
    /// Excluded folders changed on the way: not restored (FR-CKP-31).
    pub not_restored: Vec<CanonicalPath>,
    /// More excluded folders were changed than `not_restored` lists.
    pub not_restored_incomplete: bool,
    /// What the changes did that no restore can undo (FR-CKP-36).
    pub irreversible: Vec<String>,
    /// Whether `force` overrode a check.
    pub forced: bool,
    /// Possibly-torn files skipped (FR-CKP-24).
    pub skipped_torn: Vec<TornPath>,
    /// Possibly-torn files restored under `force` (FR-CKP-24).
    pub forced_torn: Vec<TornPath>,
}

impl ToJson for CheckpointRestoreResult {
    /// `files_restored` counts every path restored; `restored` lists at most [`MAX_LISTED_RESTORED`] of them, and
    /// `restored_incomplete` says whether it lists fewer, so the answer always fits a frame.
    fn to_json(&self) -> Result<Value, JsonError> {
        let listed: Vec<Value> = self
            .restored
            .iter()
            .take(MAX_LISTED_RESTORED)
            .map(|path| Value::from(path_text(path)))
            .collect();
        let not_restored: Vec<Value> = self
            .not_restored
            .iter()
            .map(|path| Value::from(path_text(path)))
            .collect();
        let irreversible: Vec<Value> = self
            .irreversible
            .iter()
            .map(|reason| Value::from(reason.as_str()))
            .collect();
        Ok(Value::Object(
            Object::new()
                .with("from", self.from.get().to_json()?)?
                .with("state_id", self.state_id.get().to_json()?)?
                .with("changes", self.changes.to_json()?)?
                .with("files_restored", (self.restored.len() as u64).to_json()?)?
                .with("restored", Value::Array(listed))?
                .with("restored_incomplete", self.restored.len() > MAX_LISTED_RESTORED)?
                .with("not_restored", Value::Array(not_restored))?
                .with("not_restored_incomplete", self.not_restored_incomplete)?
                .with("irreversible", Value::Array(irreversible))?
                .with("forced", self.forced)?
                .with("skipped_torn", torn_list(&self.skipped_torn)?)?
                .with("forced_torn", torn_list(&self.forced_torn)?)?,
        ))
    }
}

/// The parameters of `checkpoint.diff` (KNSH-086): exactly one of `record_id` and `state_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointDiffParams {
    /// A line's change, or a state compared with the current one.
    pub target: DiffTarget,
    /// The previous answer's `next_cursor`: only paths after it.
    pub cursor: Option<CanonicalPath>,
    /// Paths per answer, 1 to [`MAX_DIFF_PAGE`]; [`MAX_DIFF_PAGE`] when absent.
    pub limit: u32,
}

impl FromJson for CheckpointDiffParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let record_id = fields.optional::<String>("record_id")?;
        let state_id = fields.optional::<u64>("state_id")?;
        let target = match (record_id, state_id) {
            (Some(record_id), None) => DiffTarget::Record(record_id.parse().map_err(|_| out_of_range("record_id"))?),
            (None, Some(state_id)) => DiffTarget::State(state(state_id, "state_id")?),
            // Neither or both: the call is ambiguous, never guessed at.
            (None, None) | (Some(_), Some(_)) => return Err(out_of_range("record_id")),
        };
        let cursor = fields
            .optional::<String>("cursor")?
            .map(|cursor| CanonicalPath::new(cursor).map_err(|_| out_of_range("cursor")))
            .transpose()?;
        let limit = fields.optional::<u32>("limit")?.unwrap_or(MAX_DIFF_PAGE);
        if limit == 0 || limit > MAX_DIFF_PAGE {
            return Err(out_of_range("limit"));
        }
        fields.finish()?;
        Ok(Self { target, cursor, limit })
    }
}

/// A `checkpoint.diff` answer: the JSON result, and the raw bytes of each stream it names, to send right after it
/// ([`DiffAnswer::write_streams`]). Built by [`diff_answer`].
#[derive(Debug, Clone, PartialEq)]
pub struct DiffAnswer<'a> {
    /// The result.
    pub result: Value,
    /// Each stream the result names, in order, with its bytes.
    pub streams: Vec<(StreamId, &'a [u8])>,
}

impl DiffAnswer<'_> {
    /// Writes each stream's bytes as binary chunks, then its end-of-stream frame, in the order the result names them.
    /// Call right after writing the result itself.
    ///
    /// # Errors
    ///
    /// [`JsonError::Io`] if the transport fails.
    pub fn write_streams<W: Write>(&self, writer: &mut FrameWriter<W>) -> Result<(), JsonError> {
        for (stream, bytes) in &self.streams {
            writer.write_chunk(*stream, bytes)?;
            writer.write_end(*stream)?;
        }
        Ok(())
    }
}

/// The answer to `checkpoint.diff` for one page `diff` (`more`: paths follow its last one), with the diffs sent as
/// `transport` says:
///
/// - **Binary frames:** each text diff is a stream, numbered from 1 in path order: `"diff": {"stream_id", "size",
///   "content_type": "text/x-diff"}`.
/// - **Base64:** `"diff_base64"` inline, up to [`MAX_BASE64_DIFF`] bytes in all: the answer ends before the diff that
///   would pass it (`next_cursor` then names the last path listed); one diff alone larger than that is `too_large`.
///
/// A path without a text diff has `diff` (or `diff_base64`) `null` and says why in `reason`.
///
/// # Errors
///
/// [`JsonError`] if a value cannot be written (a bug, never input).
pub fn diff_answer(diff: &Diff, more: bool, transport: ByteTransport) -> Result<DiffAnswer<'_>, JsonError> {
    let mut files = Vec::with_capacity(diff.files.len());
    let mut streams = Vec::new();
    let mut inline = 0usize;
    let mut cursor = more.then(|| diff.files.last().map(|file| &file.path)).flatten();
    let mut next_stream = 1u32;
    for (index, file) in diff.files.iter().enumerate() {
        let entry = file_entry(file)?;
        let entry = match (&file.text, transport) {
            (TextDiff::Unified(text), ByteTransport::BinaryFrames) => {
                let stream = StreamId::new(next_stream).ok_or(out_of_range("stream_id"))?;
                next_stream += 1;
                streams.push((stream, text.as_slice()));
                entry
                    .with(
                        "diff",
                        Object::new()
                            .with("stream_id", stream.get())?
                            .with("size", Value::int_string(i128::from(text.len() as u64)))?
                            .with("content_type", DIFF_CONTENT_TYPE)?,
                    )?
                    .with("reason", Value::Null)?
            }
            (TextDiff::Unified(text), ByteTransport::Base64) if text.len() > MAX_BASE64_DIFF => entry
                .with("diff_base64", Value::Null)?
                .with("reason", knsh_core::NoTextDiff::TooLarge.as_str())?,
            (TextDiff::Unified(text), ByteTransport::Base64) => {
                if inline + text.len() > MAX_BASE64_DIFF && index > 0 {
                    // The rest goes in the next answer, from the last path listed here.
                    cursor = Some(&diff.files[index - 1].path);
                    break;
                }
                inline += text.len();
                entry
                    .with("diff_base64", knsh_json::base64_encode(text))?
                    .with("reason", Value::Null)?
            }
            (TextDiff::Omitted(reason), _) => {
                let key = match transport {
                    ByteTransport::BinaryFrames => "diff",
                    ByteTransport::Base64 => "diff_base64",
                };
                entry.with(key, Value::Null)?.with("reason", reason.as_str())?
            }
        };
        files.push(Value::Object(entry));
    }
    let result = Object::new()
        .with("from", diff.from.get().to_json()?)?
        .with("to", diff.to.get().to_json()?)?
        .with("files", Value::Array(files))?
        .with("next_cursor", cursor.map(path_text).to_json()?)?;
    Ok(DiffAnswer {
        result: Value::Object(result),
        streams,
    })
}

/// A file's entry without its diff: `path`, `change`, `before`, `after`.
fn file_entry(file: &FileDiff) -> Result<Object, JsonError> {
    Object::new()
        .with("path", path_text(&file.path))?
        .with("change", file.change.as_str())?
        .with("before", file.before.as_str())?
        .with("after", file.after.as_str())
}

/// `[{"path", "reason"}]` for possibly-torn paths.
fn torn_list(torn: &[TornPath]) -> Result<Value, JsonError> {
    let mut list = Vec::with_capacity(torn.len());
    for path in torn {
        list.push(Value::Object(
            Object::new()
                .with("path", path_text(&path.path))?
                .with("reason", path.reason.as_str())?,
        ));
    }
    Ok(Value::Array(list))
}

/// At most `limit` of `list` as JSON strings.
fn paths(list: &[CanonicalPath], limit: usize) -> Value {
    Value::Array(
        list.iter()
            .take(limit)
            .map(|path| Value::from(path_text(path)))
            .collect(),
    )
}

fn strings(list: &[String]) -> Value {
    Value::Array(list.iter().map(|text| Value::from(text.as_str())).collect())
}

/// Paths are shown like `cwd`: APFS names are UTF-8, anything else gets U+FFFD.
fn path_text(path: &CanonicalPath) -> String {
    path.as_path().to_string_lossy().into_owned()
}

/// The state numbered `number`; `-32602` beyond the numbers a tree hands out.
fn state(number: u64, field: &'static str) -> Result<StateId, JsonError> {
    StateId::new(number).ok_or(out_of_range(field))
}

const fn out_of_range(field: &'static str) -> JsonError {
    JsonError::OutOfRange { field: Some(field) }
}

#[cfg(test)]
mod tests {
    use knsh_core::{ConflictReason, EntryKind, FileChange, NoTextDiff, TornReason};
    use knsh_json::{Frame, FrameReader};

    use super::*;

    const RECORD: &str = "01JCZ0000000000000000000AB";

    fn params<T: FromJson>(text: &str) -> Result<T, JsonError> {
        T::from_json(&knsh_json::parse(text.as_bytes(), 1 << 16).unwrap())
    }

    fn path(text: &str) -> CanonicalPath {
        CanonicalPath::new(text).unwrap()
    }

    fn file(name: &str, change: FileChange, text: TextDiff) -> FileDiff {
        FileDiff {
            path: path(&format!("/code/app/{name}")),
            change,
            before: if change == FileChange::Created {
                EntryKind::Absent
            } else {
                EntryKind::File
            },
            after: if change == FileChange::Deleted {
                EntryKind::Absent
            } else {
                EntryKind::File
            },
            text,
        }
    }

    /// A page: `a.txt` and `b.txt` with text diffs, `logo.png` binary.
    fn page() -> Diff {
        Diff {
            from: StateId::new(1).unwrap(),
            to: StateId::new(4).unwrap(),
            files: vec![
                file(
                    "a.txt",
                    FileChange::Modified,
                    TextDiff::Unified(b"--- a\n+++ a\n@@ -1 +1 @@\n-x\n+y\n".to_vec()),
                ),
                file(
                    "b.txt",
                    FileChange::Created,
                    TextDiff::Unified(b"--- /dev/null\n+++ b\n@@ -0,0 +1 @@\n+new\n".to_vec()),
                ),
                file("logo.png", FileChange::Modified, TextDiff::Omitted(NoTextDiff::Binary)),
            ],
        }
    }

    fn object(value: &Value) -> &Object {
        match value {
            Value::Object(object) => object,
            other => panic!("not an object: {other:?}"),
        }
    }

    fn files(result: &Value) -> Vec<Object> {
        match object(result).get("files") {
            Some(Value::Array(files)) => files.iter().map(|file| object(file).clone()).collect(),
            other => panic!("no files: {other:?}"),
        }
    }

    // KNSH-086: `state_id` is required and bounded; `force` defaults to false.
    const CHECKPOINT: &str = "01JCZ0000000000000000000CK";
    const SESSION: &str = "01JCZ0000000000000000000SS";

    // KNSH-088: exactly one of record_id and checkpoint_id; force only as a boolean; nothing else.
    #[test]
    fn undo_params_take_exactly_one_target() {
        let by_record: CheckpointUndoParams = params(&format!(r#"{{"record_id":"{RECORD}"}}"#)).unwrap();
        assert_eq!(by_record.target, ChangeTarget::Record(RECORD.parse().unwrap()));
        assert!(!by_record.force);
        let by_checkpoint: CheckpointUndoParams =
            params(&format!(r#"{{"checkpoint_id":"{CHECKPOINT}","force":true}}"#)).unwrap();
        assert_eq!(
            by_checkpoint.target,
            ChangeTarget::Checkpoint(CHECKPOINT.parse().unwrap())
        );
        assert!(by_checkpoint.force);
        for bad in [
            "{}".to_owned(),
            format!(r#"{{"record_id":"{RECORD}","checkpoint_id":"{CHECKPOINT}"}}"#),
            r#"{"record_id":"nope"}"#.to_owned(),
            format!(r#"{{"record_id":"{RECORD}","force":"yes"}}"#),
        ] {
            assert!(params::<CheckpointUndoParams>(&bad).is_err(), "{bad}");
        }
        // The CLI writes what knshd reads.
        for parsed in [by_record, by_checkpoint] {
            assert_eq!(
                CheckpointUndoParams::from_json(&parsed.to_json().unwrap()).unwrap(),
                parsed
            );
        }
    }

    #[test]
    fn list_params_are_bounded() {
        let all: CheckpointListParams = params("{}").unwrap();
        assert_eq!((all.session_id, all.cursor, all.limit), (None, None, MAX_LIST_PAGE));
        let some: CheckpointListParams = params(&format!(
            r#"{{"session_id":"{SESSION}","cursor":"{CHECKPOINT}","limit":5}}"#
        ))
        .unwrap();
        assert_eq!(some.session_id, Some(SESSION.parse().unwrap()));
        assert_eq!(some.cursor, Some(CHECKPOINT.parse().unwrap()));
        assert_eq!(some.limit, 5);
        assert_eq!(CheckpointListParams::from_json(&some.to_json().unwrap()).unwrap(), some);
        for bad in [
            r#"{"limit":0}"#,
            r#"{"limit":257}"#,
            r#"{"session_id":"x"}"#,
            r#"{"cursor":"x"}"#,
        ] {
            assert!(params::<CheckpointListParams>(bad).is_err(), "{bad}");
        }
    }

    // KNSH-088: a refusal of the history tree becomes the API error the spec names, with a reason a client can act
    // on and never a path in the message.
    #[test]
    fn history_refusals_map_to_api_errors() {
        let reason = |error: &RpcError| {
            error
                .data
                .as_ref()
                .and_then(Value::as_object)
                .and_then(|data| data.get("reason"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        for (error, expected) in [
            (HistoryError::UnknownChange, "unknown"),
            (HistoryError::UnknownState, "unknown"),
            (HistoryError::Expired, "expired"),
            (HistoryError::NotInEffect, "not_in_effect"),
            (HistoryError::NotUndone, "not_undone"),
            (HistoryError::RedoBlocked, "redo_blocked"),
        ] {
            let rpc = history_error(&error);
            assert_eq!(rpc.code, ErrorCode::InvalidParams, "{error}");
            assert_eq!(reason(&rpc).as_deref(), Some(expected), "{error}");
        }
        for error in [
            HistoryError::Stale,
            HistoryError::Corrupt,
            HistoryError::StatesExhausted,
        ] {
            let rpc = history_error(&error);
            assert_eq!(rpc.code, ErrorCode::InternalError, "{error}");
            assert!(rpc.data.is_none());
        }
        // FR-CKP-30: the shared paths, as -32004 conflicts.
        let overlap = history_error(&HistoryError::Conflict {
            paths: [path("/r/a"), path("/r/b")].into_iter().collect(),
            incomplete: false,
        });
        assert_eq!(overlap.code, ErrorCode::UndoConflict);
        let conflicts = overlap
            .data
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|data| data.get("conflicts"))
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(conflicts.len(), 2);
        let first = conflicts[0].as_object().unwrap();
        assert_eq!(first.get("path").and_then(Value::as_str), Some("/r/a"));
        assert_eq!(first.get("reason").and_then(Value::as_str), Some(LATER_CHANGE));
    }

    #[test]
    fn undo_result_lists_what_was_restored() {
        let result = CheckpointUndoResult {
            operation: RestoreOperation::Undo,
            checkpoint_id: CHECKPOINT.parse().unwrap(),
            record_ids: vec![RECORD.parse().unwrap()],
            roots: vec![path("/r")],
            state_id: StateId::new(3).unwrap(),
            restored: vec![path("/r/a"), path("/r/b")],
            not_restored: vec![path("/r/node_modules")],
            not_restored_incomplete: false,
            irreversible: vec![String::from("network")],
            forced: false,
            skipped_torn: vec![TornPath {
                path: path("/r/db"),
                reason: TornReason::SqliteJournal,
            }],
            forced_torn: Vec::new(),
        };
        let value = result.to_json().unwrap();
        let object = object(&value);
        assert_eq!(object.get("operation").and_then(Value::as_str), Some("undo"));
        assert_eq!(object.get("checkpoint_id").and_then(Value::as_str), Some(CHECKPOINT));
        assert_eq!(object.get("state_id").and_then(Value::as_i64), Some(3));
        assert_eq!(object.get("files_restored").and_then(Value::as_i64), Some(2));
        assert_eq!(object.get("restored_incomplete").and_then(Value::as_bool), Some(false));
        let torn = object.get("skipped_torn").and_then(Value::as_array).unwrap();
        assert_eq!(
            torn[0].as_object().unwrap().get("reason").and_then(Value::as_str),
            Some("sqlite_journal")
        );
        assert_eq!(object.len(), 14);
    }

    #[test]
    fn listed_change_says_where_it_stands() {
        let change = ListedChange {
            checkpoint_id: CHECKPOINT.parse().unwrap(),
            kind: ListedKind::Change(Attribution::Command),
            record_ids: vec![RECORD.parse().unwrap()],
            session_ids: vec![SESSION.parse().unwrap()],
            roots: vec![path("/r")],
            files_changed: 2,
            uncertain: false,
            from: StateId::new(1).unwrap(),
            to: StateId::new(2).unwrap(),
            status: ListedStatus::Undone,
        };
        let revert = ListedChange {
            kind: ListedKind::Revert(CHECKPOINT.parse().unwrap()),
            record_ids: Vec::new(),
            status: ListedStatus::InEffect,
            ..change.clone()
        };
        let result = CheckpointListResult {
            head: StateId::new(1).unwrap(),
            changes: vec![change, revert],
            next_cursor: None,
        };
        let value = result.to_json().unwrap();
        let object = object(&value);
        assert_eq!(object.get("head").and_then(Value::as_i64), Some(1));
        assert_eq!(object.get("next_cursor"), Some(&Value::Null));
        let changes = object.get("changes").and_then(Value::as_array).unwrap();
        let first = changes[0].as_object().unwrap();
        assert_eq!(first.get("kind").and_then(Value::as_str), Some("change"));
        assert_eq!(first.get("attribution").and_then(Value::as_str), Some("command"));
        assert_eq!(first.get("reverts"), Some(&Value::Null));
        assert_eq!(first.get("status").and_then(Value::as_str), Some("undone"));
        assert!(first.get("created_at").and_then(Value::as_str).is_some());
        let second = changes[1].as_object().unwrap();
        assert_eq!(second.get("kind").and_then(Value::as_str), Some("revert"));
        assert_eq!(second.get("attribution"), Some(&Value::Null));
        assert_eq!(second.get("reverts").and_then(Value::as_str), Some(CHECKPOINT));
    }

    #[test]
    fn restore_params_parse_strictly() {
        let parsed: CheckpointRestoreParams = params(r#"{"state_id":3}"#).unwrap();
        assert_eq!((parsed.state_id.get(), parsed.force), (3, false));
        let forced: CheckpointRestoreParams = params(r#"{"state_id":0,"force":true}"#).unwrap();
        assert!(forced.force);
        assert!(params::<CheckpointRestoreParams>("{}").is_err());
        assert!(params::<CheckpointRestoreParams>(r#"{"state_id":-1}"#).is_err());
        assert!(params::<CheckpointRestoreParams>(r#"{"state_id":"3"}"#).is_err());
        assert!(params::<CheckpointRestoreParams>(r#"{"state_id":3,"force":"yes"}"#).is_err());
    }

    // KNSH-086: exactly one of `record_id` and `state_id`; a bounded page size; a canonical cursor.
    #[test]
    fn diff_params_take_exactly_one_target() {
        let by_record: CheckpointDiffParams = params(&format!(r#"{{"record_id":"{RECORD}"}}"#)).unwrap();
        assert_eq!(by_record.target, DiffTarget::Record(RECORD.parse().unwrap()));
        assert_eq!((by_record.limit, by_record.cursor), (MAX_DIFF_PAGE, None));
        let by_state: CheckpointDiffParams = params(r#"{"state_id":2,"limit":10,"cursor":"/code/app/a.txt"}"#).unwrap();
        assert_eq!(by_state.target, DiffTarget::State(StateId::new(2).unwrap()));
        assert_eq!(by_state.cursor, Some(path("/code/app/a.txt")));
        assert_eq!(by_state.limit, 10);
        for bad in [
            "{}".to_owned(),
            format!(r#"{{"record_id":"{RECORD}","state_id":1}}"#),
            r#"{"record_id":"not-a-ulid"}"#.to_owned(),
            r#"{"state_id":1,"limit":0}"#.to_owned(),
            r#"{"state_id":1,"limit":257}"#.to_owned(),
            r#"{"state_id":1,"cursor":"relative/path"}"#.to_owned(),
            r#"{"state_id":1,"cursor":"/a/../b"}"#.to_owned(),
        ] {
            assert!(params::<CheckpointDiffParams>(&bad).is_err(), "{bad}");
        }
    }

    // KNSH-086, wire format: each text diff is a binary stream the JSON names with its ID, size and content type,
    // sent as chunks right after it and closed by an end-of-stream frame. A strict reader accepts the whole answer
    // and gets back exactly the diffs.
    #[test]
    fn diff_streams_file_contents_as_binary_chunks() {
        let diff = page();
        let answer = diff_answer(&diff, false, ByteTransport::BinaryFrames).unwrap();
        let mut writer = FrameWriter::new(Vec::new());
        writer.write_json(&answer.result).unwrap();
        answer.write_streams(&mut writer).unwrap();
        let wire = writer.into_inner();

        let mut reader = FrameReader::new(wire.as_slice());
        let Some(Frame::Json(json)) = reader.read_frame().unwrap() else {
            panic!("the JSON answer comes first");
        };
        let result = knsh_json::parse(&json, 1 << 20).unwrap();
        assert_eq!(object(&result).get("next_cursor"), Some(&Value::Null));
        let mut declared = Vec::new();
        for entry in files(&result) {
            match entry.get("diff") {
                Some(Value::Object(data)) => {
                    assert_eq!(
                        data.get("content_type").and_then(Value::as_str),
                        Some(DIFF_CONTENT_TYPE)
                    );
                    let id = StreamId::from_json(data.get("stream_id").unwrap()).unwrap();
                    let size = u64::try_from(data.get("size").and_then(Value::as_int_string).unwrap()).unwrap();
                    reader.open_stream(id, Some(size)).unwrap();
                    declared.push(id);
                    assert_eq!(entry.get("reason"), Some(&Value::Null));
                }
                Some(Value::Null) => {
                    // Binary files are reported as changed without a text diff.
                    assert_eq!(entry.get("path").and_then(Value::as_str), Some("/code/app/logo.png"));
                    assert_eq!(entry.get("change").and_then(Value::as_str), Some("modified"));
                    assert_eq!(entry.get("reason").and_then(Value::as_str), Some("binary"));
                }
                other => panic!("unexpected diff: {other:?}"),
            }
        }
        assert_eq!(declared.len(), 2);
        let mut received: Vec<(StreamId, Vec<u8>)> = declared.iter().map(|id| (*id, Vec::new())).collect();
        let mut ended = Vec::new();
        while let Some(frame) = reader.read_frame().unwrap() {
            match frame {
                Frame::Chunk { stream, data } => {
                    received
                        .iter_mut()
                        .find(|(id, _)| *id == stream)
                        .unwrap()
                        .1
                        .extend(data);
                }
                Frame::End { stream } => ended.push(stream),
                Frame::Json(_) => panic!("no second JSON message"),
            }
        }
        assert_eq!(ended, declared, "every stream is closed, in order");
        let texts: Vec<Vec<u8>> = diff
            .files
            .iter()
            .filter_map(|file| match &file.text {
                TextDiff::Unified(text) => Some(text.clone()),
                TextDiff::Omitted(_) => None,
            })
            .collect();
        assert_eq!(received.into_iter().map(|(_, bytes)| bytes).collect::<Vec<_>>(), texts);
    }

    // KNSH-086, wire format: a client that opted out of binary frames gets each diff as canonical base64 inside the
    // JSON, and no stream follows.
    #[test]
    fn diff_falls_back_to_base64_for_clients_without_binary_frames() {
        let diff = page();
        let answer = diff_answer(&diff, true, ByteTransport::Base64).unwrap();
        assert_eq!(answer.streams.len(), 0);
        let entries = files(&answer.result);
        let decoded = knsh_json::base64_decode(entries[0].get("diff_base64").and_then(Value::as_str).unwrap()).unwrap();
        assert_eq!(TextDiff::Unified(decoded), diff.files[0].text);
        assert!(!entries[0].contains_key("diff"));
        assert_eq!(entries[2].get("diff_base64"), Some(&Value::Null));
        assert_eq!(entries[2].get("reason").and_then(Value::as_str), Some("binary"));
        assert_eq!(
            object(&answer.result).get("next_cursor").and_then(Value::as_str),
            Some("/code/app/logo.png"),
            "more paths follow the last one listed"
        );
        let text = knsh_json::write(&answer.result).unwrap();
        assert!(text.len() < knsh_json::MAX_PAYLOAD);
    }

    // KNSH-086: inline base64 stays within one frame. The answer ends before the diff that would pass the budget and
    // names the last path listed; a diff larger than the budget alone is reported `too_large`.
    #[test]
    fn base64_answer_ends_before_the_budget() {
        let half = vec![b'+'; MAX_BASE64_DIFF / 2 + 1];
        let diff = Diff {
            from: StateId::new(0).unwrap(),
            to: StateId::new(1).unwrap(),
            files: vec![
                file(
                    "huge.txt",
                    FileChange::Created,
                    TextDiff::Unified(vec![b'+'; MAX_BASE64_DIFF + 1]),
                ),
                file("one.txt", FileChange::Created, TextDiff::Unified(half.clone())),
                file("two.txt", FileChange::Created, TextDiff::Unified(half)),
            ],
        };
        let answer = diff_answer(&diff, false, ByteTransport::Base64).unwrap();
        let entries = files(&answer.result);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].get("reason").and_then(Value::as_str), Some("too_large"));
        assert!(entries[1].get("diff_base64").and_then(Value::as_str).is_some());
        assert_eq!(
            object(&answer.result).get("next_cursor").and_then(Value::as_str),
            Some("/code/app/one.txt")
        );
        assert!(knsh_json::write(&answer.result).unwrap().len() < knsh_json::MAX_PAYLOAD);
    }

    // KNSH-086: the restore result counts every path and lists a bounded number.
    #[test]
    fn restore_result_shape() {
        let result = CheckpointRestoreResult {
            from: StateId::new(5).unwrap(),
            state_id: StateId::new(2).unwrap(),
            changes: vec![RestoredChange {
                checkpoint_id: "01JCZ0000000000000000000CD".parse().unwrap(),
                operation: RestoreOperation::Undo,
                record_ids: vec![RECORD.parse().unwrap()],
                files_restored: 2,
            }],
            restored: vec![path("/code/app/a.txt"), path("/code/app/b.txt")],
            not_restored: vec![path("/code/app/node_modules")],
            not_restored_incomplete: false,
            irreversible: vec!["network".to_owned()],
            forced: false,
            skipped_torn: vec![TornPath {
                path: path("/code/app/app.db"),
                reason: TornReason::SqliteJournal,
            }],
            forced_torn: Vec::new(),
        };
        assert_eq!(
            knsh_json::write(&result.to_json().unwrap()).unwrap(),
            format!(
                r#"{{"from":5,"state_id":2,"changes":[{{"checkpoint_id":"01JCZ0000000000000000000CD","operation":"undo","record_ids":["{RECORD}"],"files_restored":2}}],"files_restored":2,"restored":["/code/app/a.txt","/code/app/b.txt"],"restored_incomplete":false,"not_restored":["/code/app/node_modules"],"not_restored_incomplete":false,"irreversible":["network"],"forced":false,"skipped_torn":[{{"path":"/code/app/app.db","reason":"sqlite_journal"}}],"forced_torn":[]}}"#
            )
        );
        let many = CheckpointRestoreResult {
            restored: (0..=MAX_LISTED_RESTORED)
                .map(|n| path(&format!("/code/app/{n}")))
                .collect(),
            ..result
        };
        let text = knsh_json::write(&many.to_json().unwrap()).unwrap();
        assert!(text.contains(r#""files_restored":1001,"#), "{text}");
        assert!(text.contains(r#""restored_incomplete":true"#));
    }

    // FR-CKP-20: `-32004` lists every conflicting path with its reason.
    #[test]
    fn undo_conflict_lists_paths_and_reasons() {
        let error = undo_conflict(&[
            RestoreConflict {
                path: CanonicalPath::new("/Users/me/app/a.txt").unwrap(),
                reason: ConflictReason::Changed,
            },
            RestoreConflict {
                path: CanonicalPath::new("/Users/me/app/b").unwrap(),
                reason: ConflictReason::FolderNotEmpty,
            },
        ]);
        assert_eq!(error.code, ErrorCode::UndoConflict);
        assert_eq!(error.code.code(), -32004);
        let data = knsh_json::write(error.data.as_ref().unwrap()).unwrap();
        assert_eq!(
            data,
            r#"{"conflicts":[{"path":"/Users/me/app/a.txt","reason":"changed"},{"path":"/Users/me/app/b","reason":"folder_not_empty"}]}"#
        );
    }
}
