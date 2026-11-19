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
//! Parameters come from untrusted clients: each is bounded and parsed strictly, and anything else is `-32602`.

use std::io::Write;

use knsh_core::{
    CanonicalPath, CheckpointId, Diff, DiffTarget, FileDiff, RecordId, RestoreConflict, RestoreOperation, StateId,
    TextDiff, TornPath,
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
