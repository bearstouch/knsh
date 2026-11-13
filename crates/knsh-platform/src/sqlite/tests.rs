//! Tests against the real system SQLite, each in its own temporary directory (never the user's state).

use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::FileKind;
use crate::macos::RealFs;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("knsh-sqlite-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn db(&self) -> PathBuf {
        self.0.join("records.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open(path: &Path) -> Connection {
    Connection::open(&RealFs::new(), path, DEFAULT_BUSY_TIMEOUT).unwrap()
}

fn sqlite_code(result: Result<impl std::fmt::Debug, PlatformError>) -> SqliteCode {
    result.unwrap_err().sqlite_code().unwrap()
}

fn count(connection: &Connection, table: &str) -> i64 {
    // Table names are test literals, never values: values only ever travel as bound parameters.
    let mut statement = connection.prepare(&format!("SELECT count(*) FROM {table}")).unwrap();
    assert_eq!(statement.step().unwrap(), Step::Row);
    statement.column_i64(0).unwrap().unwrap()
}

// KNSH-010: values travel only as bound parameters, including text that would break SQL if formatted in.
#[test]
fn insert_and_query_with_bound_parameters() {
    let tmp = TempDir::new("bind");
    let db = open(&tmp.db());
    db.exec("CREATE TABLE r (id INTEGER PRIMARY KEY, name TEXT, exit INTEGER, note TEXT)")
        .unwrap();

    let hostile = "x'); DROP TABLE r; --";
    let changed = db
        .execute(
            "INSERT INTO r (name, exit, note) VALUES (?1, ?2, ?3)",
            &[Value::Text(hostile), Value::Integer(-126), Value::Null],
        )
        .unwrap();
    assert_eq!(changed, 1);
    assert_eq!(db.last_insert_rowid(), 1);
    db.execute(
        "INSERT INTO r (name, exit, note) VALUES (?, ?, ?)",
        &[Value::Text(""), Value::Integer(i64::MAX), Value::Text("é ✓")],
    )
    .unwrap();

    let mut query = db.prepare("SELECT name, exit, note FROM r WHERE id = ?").unwrap();
    assert_eq!(query.parameter_count(), 1);
    assert_eq!(query.column_count(), 3);
    query.bind_all(&[Value::Integer(1)]).unwrap();
    assert_eq!(query.step().unwrap(), Step::Row);
    assert_eq!(query.column_text(0).unwrap().as_deref(), Some(hostile));
    assert_eq!(query.column_i64(1).unwrap(), Some(-126));
    assert_eq!(query.column_type(2).unwrap(), ColumnType::Null);
    assert_eq!(query.column_text(2).unwrap(), None);
    assert_eq!(query.step().unwrap(), Step::Done);

    // The same statement is reused after `bind_all`, which resets it first.
    query.bind_all(&[Value::Integer(2)]).unwrap();
    assert_eq!(query.step().unwrap(), Step::Row);
    assert_eq!(query.column_text(0).unwrap().as_deref(), Some(""));
    assert_eq!(query.column_i64(1).unwrap(), Some(i64::MAX));
    assert_eq!(query.column_text(2).unwrap().as_deref(), Some("é ✓"));
    drop(query);
    assert_eq!(count(&db, "r"), 2, "the hostile text must not have run as SQL");
}

// KNSH-010: the transaction guard rolls back on drop unless committed (failure safety).
#[test]
fn transaction_rolls_back_on_drop() {
    let tmp = TempDir::new("tx");
    let mut db = open(&tmp.db());
    db.exec("CREATE TABLE t (v INTEGER)").unwrap();

    {
        let tx = db.transaction().unwrap();
        tx.execute("INSERT INTO t (v) VALUES (?)", &[Value::Integer(1)])
            .unwrap();
        assert_eq!(count(&tx, "t"), 1);
        // Dropped without commit, as on an early `?` return.
    }
    assert_eq!(count(&db, "t"), 0);
    assert!(!db.in_transaction());

    let tx = db.transaction().unwrap();
    tx.execute("INSERT INTO t (v) VALUES (?)", &[Value::Integer(2)])
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(count(&db, "t"), 1);

    let tx = db.transaction().unwrap();
    tx.execute("DELETE FROM t", &[]).unwrap();
    tx.rollback().unwrap();
    assert_eq!(count(&db, "t"), 1);

    // A committed transaction survives reopening the database.
    drop(db);
    assert_eq!(count(&open(&tmp.db()), "t"), 1);
}

// KNSH-010: every SQLite failure is a typed error carrying the (extended) result code, never message text.
#[test]
fn statement_error_returns_typed_code() {
    let tmp = TempDir::new("errors");
    let db = open(&tmp.db());
    db.exec("CREATE TABLE u (k TEXT PRIMARY KEY NOT NULL, v TEXT UNIQUE)")
        .unwrap();
    db.execute("INSERT INTO u VALUES (?, ?)", &[Value::Text("a"), Value::Text("1")])
        .unwrap();

    let error = db
        .execute("INSERT INTO u VALUES (?, ?)", &[Value::Text("b"), Value::Text("1")])
        .unwrap_err();
    assert_eq!(
        error,
        PlatformError::Sqlite {
            operation: Operation::Step,
            code: SqliteCode::CONSTRAINT_UNIQUE,
        }
    );
    assert!(error.sqlite_code().unwrap().is_constraint());
    // The message names the code only; SQLite's text ("UNIQUE constraint failed: u.v") is never included.
    assert_eq!(
        error.to_string(),
        "step statement failed: SQLITE_CONSTRAINT (code 2067)"
    );
    assert_eq!(
        sqlite_code(db.execute("INSERT INTO u VALUES (?, ?)", &[Value::Text("a"), Value::Null])),
        SqliteCode::CONSTRAINT_PRIMARYKEY
    );
    assert_eq!(
        sqlite_code(db.execute("INSERT INTO u VALUES (?, ?)", &[Value::Null, Value::Null])),
        SqliteCode::CONSTRAINT_NOTNULL
    );

    // Syntax errors, and misuse refused by the wrapper before SQLite could misbehave.
    assert_eq!(sqlite_code(db.prepare("SELEC 1")), SqliteCode::ERROR);
    assert_eq!(sqlite_code(db.prepare("")), SqliteCode::MISUSE);
    assert_eq!(sqlite_code(db.prepare("SELECT 1; DELETE FROM u")), SqliteCode::MISUSE);
    assert_eq!(sqlite_code(db.prepare("SELECT 1\0; DELETE FROM u")), SqliteCode::MISUSE);
    assert!(db.prepare("SELECT 1; \n").is_ok());
    assert_eq!(sqlite_code(db.exec("SELECT 1\0")), SqliteCode::MISUSE);
    assert_eq!(count(&db, "u"), 1, "nothing after a refused statement may run");

    let mut statement = db.prepare("SELECT k, v FROM u WHERE k = ?").unwrap();
    assert_eq!(sqlite_code(statement.bind_all(&[])), SqliteCode::RANGE);
    assert_eq!(sqlite_code(statement.bind(2, Value::Null)), SqliteCode::RANGE);
    assert_eq!(
        sqlite_code(statement.column_text(0)),
        SqliteCode::MISUSE,
        "no row is current"
    );
    statement.bind_all(&[Value::Text("a")]).unwrap();
    assert_eq!(statement.step().unwrap(), Step::Row);
    assert_eq!(
        sqlite_code(statement.bind(1, Value::Null)),
        SqliteCode::MISUSE,
        "bind while running"
    );
    assert_eq!(sqlite_code(statement.column_text(2)), SqliteCode::RANGE);
    assert_eq!(sqlite_code(statement.column_i64(0)), SqliteCode::MISMATCH);
    assert_eq!(sqlite_code(statement.column_blob(0)), SqliteCode::MISMATCH);
    assert_eq!(statement.step().unwrap(), Step::Done);
    assert_eq!(
        sqlite_code(statement.column_text(0)),
        SqliteCode::MISUSE,
        "no row after done"
    );
}

// KNSH-010, CLAUDE.md "Secrets and privacy": the database and its WAL files are owner-only, in WAL mode.
#[test]
fn database_file_created_owner_only() {
    let tmp = TempDir::new("mode");
    let fs = RealFs::new();
    let path = tmp.db();
    let db = Connection::open(&fs, &path, DEFAULT_BUSY_TIMEOUT).unwrap();
    db.exec("CREATE TABLE t (v INTEGER)").unwrap();
    db.execute("INSERT INTO t VALUES (?)", &[Value::Integer(1)]).unwrap();

    let mut mode = db.prepare("PRAGMA journal_mode").unwrap();
    assert_eq!(mode.step().unwrap(), Step::Row);
    assert_eq!(mode.column_text(0).unwrap().as_deref(), Some("wal"));
    drop(mode);

    for name in ["records.db", "records.db-wal", "records.db-shm"] {
        let meta = fs.metadata(&tmp.0.join(name)).unwrap();
        assert_eq!((meta.kind, meta.mode), (FileKind::File, 0o600), "{name}");
    }
    drop(db);

    // Reopening keeps the existing file and its contents.
    let db = open(&path);
    assert_eq!(count(&db, "t"), 1);
    assert_eq!(fs.metadata(&path).unwrap().mode, 0o600);
}

#[test]
fn open_refuses_symlinks_relative_paths_and_non_databases() {
    let tmp = TempDir::new("open");
    let fs = RealFs::new();
    let target = tmp.0.join("elsewhere.db");
    drop(open(&target));
    let link = tmp.0.join("link.db");
    symlink(&target, &link).unwrap();
    let error = Connection::open(&fs, &link, DEFAULT_BUSY_TIMEOUT).unwrap_err();
    assert_eq!(
        error,
        PlatformError::Sqlite {
            operation: Operation::DatabaseOpen,
            code: SqliteCode::from_raw(1550), // SQLITE_CANTOPEN_SYMLINK
        }
    );
    for bad in ["records.db", "/", "/tmp/x/"] {
        assert_eq!(
            Connection::open(&fs, Path::new(bad), DEFAULT_BUSY_TIMEOUT).unwrap_err(),
            PlatformError::InvalidPath,
            "{bad}"
        );
    }
    let missing_dir = tmp.0.join("missing/records.db");
    assert!(
        Connection::open(&fs, &missing_dir, DEFAULT_BUSY_TIMEOUT)
            .unwrap_err()
            .is_not_found()
    );

    // A file that is not a database is reported, never overwritten.
    let not_a_db = tmp.0.join("text.db");
    let text = b"this is not a database, just some text that is long enough";
    std::fs::write(&not_a_db, text).unwrap();
    let error = Connection::open(&fs, &not_a_db, DEFAULT_BUSY_TIMEOUT).unwrap_err();
    assert_eq!(
        error,
        PlatformError::Sqlite {
            operation: Operation::DatabaseConfigure,
            code: SqliteCode::from_raw(26), // SQLITE_NOTADB
        }
    );
    assert_eq!(std::fs::read(&not_a_db).unwrap(), text);
}

// KNSH-010: blobs hold command output byte for byte, including NUL and non-UTF-8 bytes.
#[test]
fn blob_round_trip_preserves_bytes() {
    let tmp = TempDir::new("blob");
    let db = open(&tmp.db());
    db.exec("CREATE TABLE o (id INTEGER PRIMARY KEY, data BLOB)").unwrap();

    let all_bytes: Vec<u8> = (0..=255u8).collect();
    let large: Vec<u8> = (0..1_000_000u32)
        .map(|n| (n.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let cases: [&[u8]; 4] = [&all_bytes, b"", b"\0\0\xff\xfe", &large];
    for data in cases {
        db.execute("INSERT INTO o (data) VALUES (?)", &[Value::Blob(data)])
            .unwrap();
        let id = db.last_insert_rowid();
        let mut query = db.prepare("SELECT data FROM o WHERE id = ?").unwrap();
        query.bind_all(&[Value::Integer(id)]).unwrap();
        assert_eq!(query.step().unwrap(), Step::Row);
        assert_eq!(query.column_type(0).unwrap(), ColumnType::Blob);
        assert_eq!(query.column_blob(0).unwrap().as_deref(), Some(data));
        assert_eq!(sqlite_code(query.column_text(0)), SqliteCode::MISMATCH);
    }
}

// A second writer waits for the busy timeout, then gets a typed `SQLITE_BUSY` instead of blocking forever.
#[test]
fn concurrent_writer_gets_busy_after_timeout() {
    let tmp = TempDir::new("busy");
    let mut first = open(&tmp.db());
    first.exec("CREATE TABLE t (v INTEGER)").unwrap();
    let mut second = Connection::open(&RealFs::new(), &tmp.db(), Duration::from_millis(50)).unwrap();

    let tx = first.transaction().unwrap();
    let code = sqlite_code(second.transaction());
    assert!(code.is_busy(), "{code}");
    tx.commit().unwrap();
    second.transaction().unwrap().commit().unwrap();
}

#[test]
fn connection_moves_to_another_thread() {
    let tmp = TempDir::new("send");
    let db = open(&tmp.db());
    let db = std::thread::spawn(move || {
        db.exec("CREATE TABLE t (v INTEGER)").unwrap();
        db
    })
    .join()
    .unwrap();
    assert_eq!(count(&db, "t"), 0);
}
