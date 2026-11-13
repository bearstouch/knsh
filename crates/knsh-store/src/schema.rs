//! The versioned schema and its forward migrations (CLAUDE.md "Persistence").
//!
//! - The file is marked as ours with `PRAGMA application_id` ([`APPLICATION_ID`]) and carries its schema version in
//!   `PRAGMA user_version`. Both live in the database header, so they change atomically with the tables.
//! - [`migrate`] runs every missing migration, the version bump and the marking in one `BEGIN IMMEDIATE`
//!   transaction: a failure anywhere rolls all of it back and the file stays at its old version.
//! - A file with a newer version, another application id, or tables but no marking is refused before anything is
//!   written: it is reported, never adopted, migrated down or overwritten.
//!
//! The schema holds every field of `specs/05-models/execution-record.md`, most of them empty in phase 1. Agent-only
//! fields that are structured (`argv`, `decision`, `children`, …) are reserved text columns; later phases define
//! their encoding in a migration of their own.

use knsh_platform::sqlite::{Connection, Step};

use crate::error::StoreError;

/// `knsh` in ASCII: marks the file as a record store, so another application's database is never adopted.
pub(crate) const APPLICATION_ID: i64 = 0x6B6E_7368;

/// One forward migration: SQL that takes the schema from version `n` to `n + 1`, run inside the migration
/// transaction. The text is a constant of this crate, never built from values.
pub(crate) type Migration = &'static str;

/// Version 1: sessions, execution records and their capped output.
///
/// - `record_id` is the 26-character ULID text, which sorts in creation order, so `ORDER BY record_id` is creation
///   order and a stable pagination key.
/// - Times are UTC microseconds since the Unix epoch.
/// - `cwd` is stored as the path's raw bytes: a path need not be UTF-8.
/// - Output is one row per stream, referenced from the record by `(record_id, stream)`: the stored bytes are head
///   then tail, with `skipped` bytes dropped at offset `skipped_at` (FR-REC-06).
const V1: Migration = "
CREATE TABLE sessions (
    session_id        TEXT PRIMARY KEY NOT NULL,
    actor_kind        TEXT NOT NULL CHECK (actor_kind IN ('human', 'agent')),
    agent_id          TEXT,
    profile           TEXT NOT NULL,
    envelope          INTEGER NOT NULL,
    recording         INTEGER NOT NULL,
    parent_session_id TEXT,
    state             TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);
CREATE TABLE records (
    record_id          TEXT PRIMARY KEY NOT NULL,
    session_id         TEXT NOT NULL,
    actor_kind         TEXT NOT NULL CHECK (actor_kind IN ('human', 'agent')),
    agent_id           TEXT,
    attribution        TEXT,
    command            TEXT NOT NULL,
    rewritten_from     TEXT,
    argv               TEXT,
    cwd                BLOB NOT NULL,
    decision           TEXT,
    sandbox_profile    TEXT,
    secrets_injected   TEXT,
    started_at         INTEGER NOT NULL,
    ended_at           INTEGER,
    exit_code          INTEGER,
    pipestatus         TEXT,
    signal             TEXT,
    children           TEXT,
    files_changed      TEXT,
    network            TEXT,
    checkpoint_id      TEXT,
    irreversible       TEXT,
    sandbox_violations TEXT
);
CREATE INDEX records_by_session ON records (session_id, record_id);
CREATE INDEX records_by_start ON records (started_at);
CREATE TABLE outputs (
    record_id  TEXT NOT NULL REFERENCES records (record_id) ON DELETE CASCADE,
    stream     TEXT NOT NULL CHECK (stream IN ('stdout', 'stderr')),
    data       BLOB NOT NULL,
    original   INTEGER NOT NULL,
    skipped    INTEGER NOT NULL,
    skipped_at INTEGER NOT NULL,
    PRIMARY KEY (record_id, stream)
);
";

/// Every migration, in order: entry `n` takes the schema from version `n` to `n + 1`.
pub(crate) const MIGRATIONS: &[Migration] = &[V1];

/// The schema version this build writes and understands.
#[must_use]
pub fn current_version() -> i64 {
    version_after(MIGRATIONS)
}

/// The version reached by applying all of `migrations` to an empty file.
fn version_after(migrations: &[Migration]) -> i64 {
    // A slice of static SQL is never longer than `i64::MAX`.
    i64::try_from(migrations.len()).unwrap_or(i64::MAX)
}

/// Runs constant `sql` that yields one integer row, reading `NULL` as 0.
fn single_integer(connection: &Connection, sql: &str) -> Result<i64, StoreError> {
    let mut statement = connection.prepare(sql)?;
    match statement.step()? {
        Step::Row => Ok(statement.column_i64(0)?.unwrap_or(0)),
        Step::Done => Err(StoreError::Corrupt),
    }
}

/// Reads one integer pragma, such as `user_version`. `name` is a constant of this crate.
pub(crate) fn pragma(connection: &Connection, name: &'static str) -> Result<i64, StoreError> {
    single_integer(connection, &format!("PRAGMA {name}"))
}

/// Whether the file has any table, index, view or trigger.
fn has_schema(connection: &Connection) -> Result<bool, StoreError> {
    Ok(single_integer(connection, "SELECT count(*) FROM sqlite_master")? > 0)
}

/// Brings the database to [`current_version`], or refuses it.
///
/// # Errors
///
/// [`StoreError::NewerSchema`], [`StoreError::ForeignDatabase`] or a [`StoreError::Platform`] from SQLite. On any
/// error nothing was written: the transaction is rolled back.
pub(crate) fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    migrate_with(connection, MIGRATIONS)
}

/// [`migrate`] with an explicit migration list, so tests can make a migration fail.
pub(crate) fn migrate_with(connection: &mut Connection, migrations: &[Migration]) -> Result<(), StoreError> {
    let supported = version_after(migrations);
    // `BEGIN IMMEDIATE` takes the write lock before the version is read, so no other writer can migrate the file
    // between the check and the change.
    let transaction = connection.transaction()?;
    let application_id = pragma(&transaction, "application_id")?;
    let found = pragma(&transaction, "user_version")?;
    match application_id {
        APPLICATION_ID => {}
        // An unmarked file is ours to initialise only if it is empty; a database with tables is someone else's.
        0 if found == 0 && !has_schema(&transaction)? => {}
        _ => return Err(StoreError::ForeignDatabase),
    }
    if found > supported {
        // Dropping the transaction rolls it back; nothing has been written.
        return Err(StoreError::NewerSchema { found, supported });
    }
    // `found` is in `0..=supported` here, so it indexes the list.
    let pending = migrations
        .get(usize::try_from(found).map_err(|_| StoreError::Corrupt)?..)
        .unwrap_or(&[]);
    if pending.is_empty() && application_id == APPLICATION_ID {
        // Already current: end the transaction without writing.
        transaction.rollback()?;
        return Ok(());
    }
    for migration in pending {
        transaction.exec(migration)?;
    }
    // Pragmas take no bound parameters; both values are integers computed here, never input.
    transaction.exec(&format!(
        "PRAGMA user_version = {supported}; PRAGMA application_id = {APPLICATION_ID}"
    ))?;
    transaction.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use knsh_platform::sqlite::DEFAULT_BUSY_TIMEOUT;

    use super::*;
    use crate::testing::TempDir;

    fn open(dir: &TempDir) -> Connection {
        Connection::open(&knsh_platform::macos::RealFs::new(), &dir.db(), DEFAULT_BUSY_TIMEOUT).unwrap()
    }

    fn tables(connection: &Connection) -> Vec<String> {
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        let mut names = Vec::new();
        while statement.step().unwrap() == Step::Row {
            names.push(statement.column_text(0).unwrap().unwrap());
        }
        names
    }

    #[test]
    fn migrates_an_empty_file_to_the_current_version() {
        let dir = TempDir::new("migrate");
        let mut connection = open(&dir);
        migrate(&mut connection).unwrap();
        assert_eq!(pragma(&connection, "user_version").unwrap(), current_version());
        assert_eq!(pragma(&connection, "application_id").unwrap(), APPLICATION_ID);
        assert_eq!(tables(&connection), ["outputs", "records", "sessions"]);
        // Running again is a no-op.
        migrate(&mut connection).unwrap();
        assert_eq!(pragma(&connection, "user_version").unwrap(), current_version());
    }

    // Failure safety: a failing migration rolls back every earlier one in the same run, and the version.
    #[test]
    fn migration_failure_rolls_back() {
        let dir = TempDir::new("rollback");
        let mut connection = open(&dir);
        let migrations: &[Migration] = &["CREATE TABLE first (x INTEGER)", "CREATE TABLE broken ("];
        let error = migrate_with(&mut connection, migrations).unwrap_err();
        assert!(matches!(error, StoreError::Platform(_)), "{error:?}");
        assert_eq!(pragma(&connection, "user_version").unwrap(), 0);
        assert_eq!(pragma(&connection, "application_id").unwrap(), 0);
        assert_eq!(tables(&connection), Vec::<String>::new());

        // From version 1, a failing second migration keeps version 1 and its tables.
        migrate_with(&mut connection, &migrations[..1]).unwrap();
        let error = migrate_with(&mut connection, migrations).unwrap_err();
        assert!(matches!(error, StoreError::Platform(_)), "{error:?}");
        assert_eq!(pragma(&connection, "user_version").unwrap(), 1);
        assert_eq!(tables(&connection), ["first"]);
    }

    #[test]
    fn foreign_database_is_refused() {
        let dir = TempDir::new("foreign");
        let mut connection = open(&dir);
        connection.exec("CREATE TABLE theirs (x INTEGER)").unwrap();
        assert_eq!(migrate(&mut connection), Err(StoreError::ForeignDatabase));
        assert_eq!(tables(&connection), ["theirs"]);

        connection.exec("PRAGMA application_id = 7").unwrap();
        assert_eq!(migrate(&mut connection), Err(StoreError::ForeignDatabase));
    }
}
