//! The database itself: one connection, the schema checks, and every read and write (KNSH-016).
//!
//! [`Database`] is used by exactly one thread, the store thread ([`crate::RecordStore`]), so the engine has a single
//! writer. Every write runs in its own transaction and returns only after `COMMIT`, so a caller that has been
//! answered knows the record is durable (FR-REC-02, NFR-REL-05; the connection runs with `synchronous = FULL`).
//!
//! All SQL text is constant; values reach SQL only as bound parameters. Optional filters use the
//! `(?n IS NULL OR column = ?n)` form so the statement stays fixed whatever the caller asks.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use knsh_core::{
    Actor, ActorKind, AgentId, CanonicalPath, CheckpointId, ExecutionRecord, OutputInfo, OutputStream, RecordDetails,
    RecordId, Redacted, Session, SessionId, Timestamp,
};
use knsh_platform::sqlite::{Connection, DATABASE_MODE, DEFAULT_BUSY_TIMEOUT, Statement, Step, Value};
use knsh_platform::{FileKind, Fs};

use crate::error::StoreError;
use crate::output::{Capped, cap_output, len_u64};
use crate::query::{OutputRange, OutputRequest, Page, RecordQuery, Scope, StoredRecord, clamp};
use crate::schema;

/// A command's output as captured, before capping. Wrapped so it is never printed (NFR-PRIV-02): output may hold
/// secrets the redaction engine (KNSH-090) has not yet removed.
#[derive(Debug, Clone, Default)]
pub struct RecordedOutput {
    /// Standard output, when output recording is on.
    pub stdout: Option<Redacted<Vec<u8>>>,
    /// Standard error, when output recording is on.
    pub stderr: Option<Redacted<Vec<u8>>>,
}

impl RecordedOutput {
    fn get(&self, stream: OutputStream) -> Option<&Redacted<Vec<u8>>> {
        match stream {
            OutputStream::Stdout => self.stdout.as_ref(),
            OutputStream::Stderr => self.stderr.as_ref(),
        }
    }
}

/// The columns [`read_record`] expects, in order.
const RECORD_COLUMNS: &str = "record_id, session_id, actor_kind, agent_id, command, rewritten_from, cwd, started_at, \
     ended_at, exit_code, pipestatus, signal, sandbox_profile, secrets_injected, checkpoint_id";

/// The open record database.
pub(crate) struct Database {
    connection: Connection,
    output_cap: usize,
}

impl Database {
    /// Opens (creating if missing) the database at `path`, checks that it is a private file owned by `owner_uid`,
    /// and migrates it to the current schema.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnsafeFile`] for a file that is not a regular `0600` file owned by `owner_uid`;
    /// [`StoreError::NewerSchema`] or [`StoreError::ForeignDatabase`] for a file this build must not write; a
    /// [`StoreError::Platform`] error if it cannot be opened or migrated. On error nothing was written.
    pub(crate) fn open(fs: &dyn Fs, path: &Path, owner_uid: u32, output_cap: usize) -> Result<Self, StoreError> {
        let mut connection = Connection::open(fs, path, DEFAULT_BUSY_TIMEOUT)?;
        // `Connection::open` creates a missing file with 0600, but an existing one is opened as it is. Refuse it
        // unless it is private: a readable record store leaks every command line (NFR-PRIV-04).
        let metadata = fs.metadata(path)?;
        if metadata.kind != FileKind::File || metadata.mode != DATABASE_MODE || metadata.uid != owner_uid {
            return Err(StoreError::UnsafeFile);
        }
        schema::migrate(&mut connection)?;
        // Per connection, not stored in the file: deleting a record deletes its output.
        connection.exec("PRAGMA foreign_keys = ON")?;
        Ok(Self { connection, output_cap })
    }

    /// Writes or updates a session row, stamped `at`.
    pub(crate) fn write_session(&mut self, session: &Session, at: Timestamp) -> Result<(), StoreError> {
        let session_id = session.session_id().to_string();
        let parent = session.parent_session_id().map(|id| id.to_string());
        let at = micros(at)?;
        self.connection.execute(
            "INSERT INTO sessions (session_id, actor_kind, agent_id, profile, envelope, recording, parent_session_id, \
             state, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9) \
             ON CONFLICT (session_id) DO UPDATE SET recording = excluded.recording, state = excluded.state, \
             updated_at = excluded.updated_at",
            &[
                Value::Text(&session_id),
                Value::Text(session.actor().kind().as_str()),
                optional_text(session.actor().agent_id().map(AgentId::as_str)),
                Value::Text(session.profile().as_str()),
                Value::Integer(i64::from(session.envelope())),
                Value::Integer(i64::from(session.recording())),
                optional_text(parent.as_deref()),
                Value::Text(session.state().as_str()),
                Value::Integer(at),
            ],
        )?;
        Ok(())
    }

    /// Writes one record and its output in one transaction, committed before this returns.
    ///
    /// A human record keeps only `command`, `cwd`, times and `exit_code` (FR-REC-09): its [`RecordDetails`] and its
    /// output are dropped here, whatever the caller supplied. Output is capped per stream (FR-REC-06).
    pub(crate) fn write_record(
        &mut self,
        mut record: ExecutionRecord,
        mut output: RecordedOutput,
    ) -> Result<(), StoreError> {
        match record.actor {
            Actor::Human => {
                record.details = RecordDetails::default();
                output = RecordedOutput::default();
            }
            Actor::Agent(_) => {}
        }
        let encoded = Encoded::new(&record)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            &format!(
                "INSERT INTO records ({RECORD_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, \
                 ?13, ?14, ?15)"
            ),
            &encoded.values(&record),
        )?;
        for stream in OutputStream::ALL {
            let Some(bytes) = output.get(stream) else {
                continue;
            };
            let Capped { data, info } = cap_output(bytes.expose(), self.output_cap);
            transaction.execute(
                "INSERT INTO outputs (record_id, stream, data, original, skipped, skipped_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    Value::Text(&encoded.record_id),
                    Value::Text(stream.as_str()),
                    Value::Blob(&data),
                    Value::Integer(count(info.original)?),
                    Value::Integer(count(info.skipped)?),
                    Value::Integer(count(info.skipped_at)?),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// One page of records visible in `scope`, ordered by `record_id`.
    ///
    /// # Errors
    ///
    /// [`StoreError::OutOfScope`] if `query.session` names a session other than the scope's.
    pub(crate) fn query(&self, scope: Scope, query: &RecordQuery) -> Result<Page, StoreError> {
        // The scope is applied in SQL, not filtered afterwards: a session-scoped caller's query never reads another
        // session's rows. Asking for another session explicitly is refused rather than answered empty, so an agent
        // learns it may not look, as `agent.sock` specifies (-32003).
        let session = match (scope, query.session) {
            (Scope::All, session) => session,
            (Scope::Session(own), None) => Some(own),
            (Scope::Session(own), Some(asked)) if asked == own => Some(own),
            (Scope::Session(_), Some(_)) => return Err(StoreError::OutOfScope),
        };
        let session = session.map(|id| id.to_string());
        let after = query.after.map(|id| id.to_string());
        let since = query.since.map(micros).transpose()?;
        let until = query.until.map(micros).transpose()?;
        let limit = query.limit.get();
        let page_len = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut statement = self.connection.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM records \
             WHERE (?1 IS NULL OR session_id = ?1) AND (?2 IS NULL OR started_at >= ?2) \
             AND (?3 IS NULL OR started_at < ?3) AND (?4 IS NULL OR instr(command, ?4) > 0) \
             AND (?5 IS NULL OR record_id > ?5) ORDER BY record_id LIMIT ?6"
        ))?;
        statement.bind_all(&[
            optional_text(session.as_deref()),
            since.map_or(Value::Null, Value::Integer),
            until.map_or(Value::Null, Value::Integer),
            optional_text(query.text.as_deref()),
            optional_text(after.as_deref()),
            // One extra row tells whether another page follows.
            Value::Integer(i64::from(limit) + 1),
        ])?;
        let mut records = Vec::new();
        while statement.step()? == Step::Row {
            records.push(read_record(&statement)?);
        }
        drop(statement);
        let more = records.len() > page_len;
        records.truncate(page_len);
        let next_cursor = if more {
            records.last().map(|record| record.record_id)
        } else {
            None
        };
        let records = records
            .into_iter()
            .map(|record| {
                let (stdout, stderr) = self.output_infos(record.record_id)?;
                Ok(StoredRecord { record, stdout, stderr })
            })
            .collect::<Result<_, StoreError>>()?;
        Ok(Page { records, next_cursor })
    }

    /// What is stored of each stream of `record_id`.
    fn output_infos(&self, record_id: RecordId) -> Result<(Option<OutputInfo>, Option<OutputInfo>), StoreError> {
        let mut infos = (None, None);
        let record_id = record_id.to_string();
        let mut statement = self
            .connection
            .prepare("SELECT stream, length(data), original, skipped, skipped_at FROM outputs WHERE record_id = ?1")?;
        statement.bind_all(&[Value::Text(&record_id)])?;
        while statement.step()? == Step::Row {
            let stream = text(&statement, 0)?.parse().map_err(|_| StoreError::Corrupt)?;
            let info = read_info(&statement, 1)?;
            match stream {
                OutputStream::Stdout => infos.0 = Some(info),
                OutputStream::Stderr => infos.1 = Some(info),
            }
        }
        Ok(infos)
    }

    /// A byte range of one stream of a record visible in `scope`, clamped to what is stored.
    ///
    /// # Errors
    ///
    /// [`StoreError::RecordNotFound`] if no such record is visible in `scope` (another session's record is
    /// indistinguishable from a missing one).
    pub(crate) fn output(&self, scope: Scope, request: &OutputRequest) -> Result<OutputRange, StoreError> {
        let record_id = request.record_id.to_string();
        let session = match scope {
            Scope::All => None,
            Scope::Session(own) => Some(own.to_string()),
        };
        let mut visible = self
            .connection
            .prepare("SELECT 1 FROM records WHERE record_id = ?1 AND (?2 IS NULL OR session_id = ?2)")?;
        visible.bind_all(&[Value::Text(&record_id), optional_text(session.as_deref())])?;
        if visible.step()? == Step::Done {
            return Err(StoreError::RecordNotFound);
        }
        drop(visible);

        let mut statement = self.connection.prepare(
            "SELECT length(data), original, skipped, skipped_at FROM outputs WHERE record_id = ?1 AND stream = ?2",
        )?;
        statement.bind_all(&[Value::Text(&record_id), Value::Text(request.stream.as_str())])?;
        if statement.step()? == Step::Done {
            // Output was not recorded for this stream: an empty range, with no sizes.
            return Ok(OutputRange {
                info: None,
                offset: 0,
                data: Vec::new(),
            });
        }
        let info = read_info(&statement, 0)?;
        drop(statement);

        let (offset, length) = clamp(info.stored, request.offset, request.length);
        let data = if length == 0 {
            Vec::new()
        } else {
            // `substr` on a blob counts bytes, from 1, and reads only the range rather than the whole blob.
            let mut statement = self
                .connection
                .prepare("SELECT substr(data, ?3, ?4) FROM outputs WHERE record_id = ?1 AND stream = ?2")?;
            statement.bind_all(&[
                Value::Text(&record_id),
                Value::Text(request.stream.as_str()),
                Value::Integer(count(offset)? + 1),
                Value::Integer(count(length)?),
            ])?;
            match statement.step()? {
                Step::Row => statement.column_blob(0)?.ok_or(StoreError::Corrupt)?,
                Step::Done => return Err(StoreError::Corrupt),
            }
        };
        if len_u64(data.len()) != length {
            return Err(StoreError::Corrupt);
        }
        Ok(OutputRange {
            info: Some(info),
            offset,
            data,
        })
    }
}

/// The text forms of a record's fields that need encoding before they are bound.
struct Encoded {
    record_id: String,
    session_id: String,
    pipestatus: Option<String>,
    secrets_injected: Option<String>,
    checkpoint_id: Option<String>,
    started_at: i64,
    ended_at: Option<i64>,
}

impl Encoded {
    fn new(record: &ExecutionRecord) -> Result<Self, StoreError> {
        let details = &record.details;
        // Secret names are stored one per line; a name that could split into two is refused, not mangled.
        if details
            .secrets_injected
            .iter()
            .any(|name| name.is_empty() || name.contains(['\n', '\0']))
        {
            return Err(StoreError::InvalidRecord("secrets_injected"));
        }
        let pipestatus = (!details.pipestatus.is_empty()).then(|| {
            details
                .pipestatus
                .iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        });
        let secrets_injected = (!details.secrets_injected.is_empty()).then(|| details.secrets_injected.join("\n"));
        Ok(Self {
            record_id: record.record_id.to_string(),
            session_id: record.session_id.to_string(),
            pipestatus,
            secrets_injected,
            checkpoint_id: details.checkpoint_id.map(|id| id.to_string()),
            started_at: micros(record.started_at)?,
            ended_at: record.ended_at.map(micros).transpose()?,
        })
    }

    /// The bound values, in [`RECORD_COLUMNS`] order.
    fn values<'a>(&'a self, record: &'a ExecutionRecord) -> [Value<'a>; 15] {
        let details = &record.details;
        [
            Value::Text(&self.record_id),
            Value::Text(&self.session_id),
            Value::Text(record.actor.kind().as_str()),
            optional_text(record.actor.agent_id().map(AgentId::as_str)),
            Value::Text(record.command.expose()),
            optional_text(details.rewritten_from.as_ref().map(|text| text.expose().as_str())),
            Value::Blob(record.cwd.as_path().as_os_str().as_bytes()),
            Value::Integer(self.started_at),
            self.ended_at.map_or(Value::Null, Value::Integer),
            record
                .exit_code
                .map_or(Value::Null, |code| Value::Integer(i64::from(code))),
            optional_text(self.pipestatus.as_deref()),
            optional_text(details.signal.as_deref()),
            optional_text(details.sandbox_profile.as_deref()),
            optional_text(self.secrets_injected.as_deref()),
            optional_text(self.checkpoint_id.as_deref()),
        ]
    }
}

/// Reads a row selected with [`RECORD_COLUMNS`]. Any value the engine could not have written is [`Corrupt`].
///
/// [`Corrupt`]: StoreError::Corrupt
fn read_record(statement: &Statement<'_>) -> Result<ExecutionRecord, StoreError> {
    let corrupt = |_| StoreError::Corrupt;
    let kind = match text(statement, 2)?.as_str() {
        "human" => ActorKind::Human,
        "agent" => ActorKind::Agent,
        _ => return Err(StoreError::Corrupt),
    };
    let agent_id = statement
        .column_text(3)?
        .map(|id| AgentId::new(&id))
        .transpose()
        .map_err(corrupt)?;
    let cwd = statement.column_blob(6)?.ok_or(StoreError::Corrupt)?;
    let pipestatus = statement
        .column_text(10)?
        .map(|text| text.split(' ').map(str::parse).collect::<Result<Vec<i32>, _>>())
        .transpose()
        .map_err(|_| StoreError::Corrupt)?
        .unwrap_or_default();
    let secrets_injected = statement
        .column_text(13)?
        .map(|text| text.split('\n').map(str::to_owned).collect())
        .unwrap_or_default();
    Ok(ExecutionRecord {
        record_id: text(statement, 0)?.parse().map_err(corrupt)?,
        session_id: text(statement, 1)?.parse::<SessionId>().map_err(corrupt)?,
        actor: Actor::from_parts(kind, agent_id).map_err(corrupt)?,
        command: Redacted::new(text(statement, 4)?),
        cwd: CanonicalPath::new(PathBuf::from(OsStr::from_bytes(&cwd))).map_err(corrupt)?,
        started_at: timestamp(statement.column_i64(7)?.ok_or(StoreError::Corrupt)?)?,
        ended_at: statement.column_i64(8)?.map(timestamp).transpose()?,
        exit_code: statement
            .column_i64(9)?
            .map(i32::try_from)
            .transpose()
            .map_err(|_| StoreError::Corrupt)?,
        details: RecordDetails {
            rewritten_from: statement.column_text(5)?.map(Redacted::new),
            pipestatus,
            signal: statement.column_text(11)?,
            sandbox_profile: statement.column_text(12)?,
            secrets_injected,
            checkpoint_id: statement
                .column_text(14)?
                .map(|id| id.parse::<CheckpointId>())
                .transpose()
                .map_err(corrupt)?,
        },
    })
}

/// Reads `stored, original, skipped, skipped_at` from four columns starting at `first`, checking the invariants.
fn read_info(statement: &Statement<'_>, first: usize) -> Result<OutputInfo, StoreError> {
    let column = |offset: usize| -> Result<u64, StoreError> {
        let value = statement.column_i64(first + offset)?.ok_or(StoreError::Corrupt)?;
        u64::try_from(value).map_err(|_| StoreError::Corrupt)
    };
    let info = OutputInfo {
        stored: column(0)?,
        original: column(1)?,
        skipped: column(2)?,
        skipped_at: column(3)?,
    };
    let consistent = info.stored.checked_add(info.skipped) == Some(info.original) && info.skipped_at <= info.stored;
    if consistent { Ok(info) } else { Err(StoreError::Corrupt) }
}

/// A non-null text column.
fn text(statement: &Statement<'_>, column: usize) -> Result<String, StoreError> {
    statement.column_text(column)?.ok_or(StoreError::Corrupt)
}

fn optional_text(text: Option<&str>) -> Value<'_> {
    text.map_or(Value::Null, Value::Text)
}

/// A timestamp as stored: microseconds since the epoch. Every valid timestamp fits in `i64`.
fn micros(at: Timestamp) -> Result<i64, StoreError> {
    i64::try_from(at.as_unix_micros()).map_err(|_| StoreError::Corrupt)
}

fn timestamp(micros: i64) -> Result<Timestamp, StoreError> {
    let micros = u64::try_from(micros).map_err(|_| StoreError::Corrupt)?;
    Timestamp::from_unix_micros(micros).map_err(|_| StoreError::Corrupt)
}

/// A byte count as stored. Counts above `i64::MAX` cannot occur for in-memory output.
fn count(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::Corrupt)
}
