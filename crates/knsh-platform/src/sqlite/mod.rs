//! A minimal safe wrapper over the system SQLite library (KNSH-010).
//!
//! The record store (`knsh-store`) keeps execution records in SQLite without a third-party crate: the C API is
//! declared by hand in the private `ffi` module and linked against the system `libsqlite3` (supply chain: "Record
//! store — the system SQLite library, called directly"). The SQLite file is an internal format, not an API
//! (FR-REC-08); the schema belongs to KNSH-016.
//!
//! # Safety model
//!
//! This module and the `macos` backend are the only places in the crate that allow `unsafe`. The public API is
//! safe:
//!
//! - A [`Statement`] borrows its [`Connection`], so it cannot outlive it; dropping a statement finalizes it and
//!   dropping a connection closes it.
//! - Column readers check that a row is current, that the index is in range and that the stored type matches,
//!   and copy the value out before returning, so no pointer into SQLite's buffers escapes.
//! - Values reach SQL only as bound parameters ([`Value`]). There is no API that formats a value into SQL text.
//! - Every failure is a [`PlatformError::Sqlite`] carrying the extended result code ([`SqliteCode`]). SQLite's
//!   message text is never read, because it can quote SQL or values (NFR-PRIV-02). Nothing here panics.
//!
//! # Files
//!
//! [`Connection::open`] creates a missing database file through [`Fs::create_new`] with mode `0600` before SQLite
//! sees it, and opens it without `SQLITE_OPEN_CREATE`, so SQLite never creates the main file with its default
//! `0644`. The `-wal` and `-shm` files SQLite creates later copy the main file's mode. The directory is resolved to
//! canonical form and a symlink at the database file is refused (`SQLITE_OPEN_NOFOLLOW`). Every connection is
//! read-write and runs in WAL mode with `synchronous = FULL` and a busy timeout.

mod ffi;

#[cfg(test)]
mod tests;

use std::ffi::{CString, c_int};
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{self, NonNull};
use std::time::Duration;

use crate::error::{Operation, PlatformError, SqliteCode};
use crate::fs::{Fs, split_target};

/// Permission bits of a database file the engine creates: owner read and write only (CLAUDE.md "Secrets and
/// privacy").
pub const DATABASE_MODE: u32 = 0o600;

/// The busy timeout [`Connection::open`] callers use unless they have a reason not to.
pub const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Builds a [`PlatformError::Sqlite`] from a raw result code.
fn error(operation: Operation, code: c_int) -> PlatformError {
    refused(operation, SqliteCode::from_raw(code))
}

/// A refusal raised by this wrapper itself, for a call SQLite would treat as misuse or undefined.
fn refused(operation: Operation, code: SqliteCode) -> PlatformError {
    PlatformError::Sqlite { operation, code }
}

/// Maps a result code to `Ok` (`SQLITE_OK`) or the typed error.
fn check(operation: Operation, code: c_int) -> Result<(), PlatformError> {
    if code == ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(error(operation, code))
    }
}

/// A value bound to a statement parameter. The only way values reach SQL (no formatting into SQL text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Value<'a> {
    /// SQL `NULL`.
    Null,
    /// A 64-bit signed integer.
    Integer(i64),
    /// UTF-8 text. Copied by SQLite during the bind.
    Text(&'a str),
    /// Raw bytes, stored exactly. Copied by SQLite during the bind.
    Blob(&'a [u8]),
}

/// The storage class of a column in the current row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColumnType {
    /// A 64-bit signed integer.
    Integer,
    /// A floating-point number (never written by this wrapper, but SQLite may store one).
    Float,
    /// Text.
    Text,
    /// Raw bytes.
    Blob,
    /// SQL `NULL`.
    Null,
}

/// The outcome of [`Statement::step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    /// A result row is current; read it with the column readers.
    Row,
    /// The statement has finished. Stepping again starts it over.
    Done,
}

/// An open database connection. Dropping it closes the connection.
///
/// `Send` but not `Sync`: it may move to another thread, and statements borrow it, so it is used from one thread
/// at a time.
#[derive(Debug)]
pub struct Connection {
    raw: NonNull<ffi::Sqlite3>,
}

// SAFETY: the connection is opened with `SQLITE_OPEN_FULLMUTEX` (serialized mode) and `open` refuses a library
// built without thread safety, so SQLite permits using the handle from any thread. `Connection` is not `Sync`, so
// it is never used from two threads at once through the safe API anyway.
unsafe impl Send for Connection {}

impl Connection {
    /// Opens the read-write database at `path`, creating the file with mode `0600` through `fs` if it is missing.
    ///
    /// The path must be absolute, so SQLite never treats it as a `file:` URI or as `:memory:`. Its directory is
    /// resolved to canonical form first; a symlink at the database file itself is refused. The connection uses
    /// extended result codes, WAL mode with `synchronous = FULL`, and `busy_timeout` (how long a call waits for a
    /// lock held by another connection before failing with `SQLITE_BUSY`; rounded down to milliseconds and capped
    /// at `i32::MAX` milliseconds).
    ///
    /// There is no read-only mode: the record store is the single writer and readers go through it (FR-REC-08).
    /// A read-only connection also cannot open a WAL database whose last writer has closed.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`] for a relative path, one without a file name or one containing a NUL byte;
    /// an `Fs` error if the directory cannot be resolved or the file cannot be created; [`PlatformError::Sqlite`]
    /// with [`Operation::DatabaseOpen`] if SQLite cannot open it (for example `SQLITE_CANTOPEN_SYMLINK` for a
    /// symlink, `SQLITE_CANTOPEN` for a directory), or with [`Operation::DatabaseConfigure`] if a setting cannot be
    /// applied (for example `SQLITE_NOTADB` for a file that is not a database).
    pub fn open(fs: &dyn Fs, path: &Path, busy_timeout: Duration) -> Result<Self, PlatformError> {
        // `SQLITE_OPEN_NOFOLLOW` refuses a symlink in any component (`SQLITE_CANTOPEN_SYMLINK`), and macOS paths
        // often have one (`/var` -> `/private/var`). The directory is resolved first, so only a symlink at the
        // database file itself is refused (FR-POL-11).
        let (dir, name) = split_target(path)?;
        let path = fs.canonicalise(dir)?.as_path().join(name);
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| PlatformError::InvalidPath)?;

        // SAFETY: a pure query of a compile-time setting of the library.
        if unsafe { ffi::sqlite3_threadsafe() } == 0 {
            // `Connection: Send` relies on a thread-safe build.
            return Err(refused(Operation::DatabaseOpen, SqliteCode::MISUSE));
        }

        // Create the file owner-only before SQLite sees it. An existing file is kept as it is (`EEXIST`):
        // `create_new` never truncates or follows a symlink.
        match fs.create_new(&path, DATABASE_MODE) {
            Ok(()) => {}
            Err(error) if error.errno() == Some(libc::EEXIST) => {}
            Err(error) => return Err(error),
        }
        // No `SQLITE_OPEN_CREATE`: if the file vanished since it was created, fail rather than let SQLite create
        // it with its default mode. No `SQLITE_OPEN_URI`: the path is always a plain absolute path.
        let flags = ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_NOFOLLOW | ffi::SQLITE_OPEN_FULLMUTEX;

        let mut raw = ptr::null_mut();
        // SAFETY: `c_path` is a NUL-terminated string that outlives the call, `raw` is a valid out-pointer, and a
        // null VFS name selects the default VFS.
        let code = unsafe { ffi::sqlite3_open_v2(c_path.as_ptr(), &raw mut raw, flags, ptr::null()) };
        // SQLite returns no handle only when it could not allocate one.
        let raw = NonNull::new(raw).ok_or_else(|| refused(Operation::DatabaseOpen, SqliteCode::NOMEM))?;
        // From here on, dropping `connection` closes the handle, including on every error path below.
        let connection = Self { raw };
        if code != ffi::SQLITE_OK {
            // SAFETY: `raw` is the handle `sqlite3_open_v2` just returned; it stays valid until closed by `Drop`.
            let extended = unsafe { ffi::sqlite3_extended_errcode(connection.raw.as_ptr()) };
            return Err(error(Operation::DatabaseOpen, extended));
        }
        connection
            .configure(busy_timeout)
            // Report every failure here as configuration, keeping SQLite's code.
            .map_err(|error| match error.sqlite_code() {
                Some(code) => refused(Operation::DatabaseConfigure, code),
                None => error,
            })?;
        Ok(connection)
    }

    /// Enables extended result codes, the busy timeout, WAL mode and full synchronous commits.
    fn configure(&self, busy_timeout: Duration) -> Result<(), PlatformError> {
        // SAFETY: `self.raw` is an open connection handle.
        check(Operation::DatabaseConfigure, unsafe {
            ffi::sqlite3_extended_result_codes(self.raw.as_ptr(), 1)
        })?;
        let millis = c_int::try_from(busy_timeout.as_millis()).unwrap_or(c_int::MAX);
        // SAFETY: `self.raw` is an open connection handle.
        check(Operation::DatabaseConfigure, unsafe {
            ffi::sqlite3_busy_timeout(self.raw.as_ptr(), millis)
        })?;

        // The pragma returns the journal mode actually in effect. SQLite silently keeps the old mode when it
        // cannot switch, so the answer is checked. This is also the first read of the file, so a file that is not
        // a database fails here with `SQLITE_NOTADB`.
        let mut statement = self.prepare("PRAGMA journal_mode = WAL")?;
        let mode = match statement.step()? {
            Step::Row => statement.column_text(0)?,
            Step::Done => None,
        };
        drop(statement);
        if !mode.is_some_and(|mode| mode.eq_ignore_ascii_case("wal")) {
            return Err(refused(Operation::DatabaseConfigure, SqliteCode::ERROR));
        }
        // Some builds default WAL to `synchronous = NORMAL`, which may lose the last commits on power loss.
        self.exec("PRAGMA synchronous = FULL")
    }

    /// Runs SQL text that takes no parameters, such as schema statements. Several `;`-separated statements are
    /// allowed. Never pass values here: bind them with [`Connection::execute`] or [`Statement::bind`].
    ///
    /// # Errors
    ///
    /// [`PlatformError::Sqlite`] with [`Operation::Execute`]: `SQLITE_MISUSE` if `sql` contains a NUL byte,
    /// otherwise the code SQLite returned.
    pub fn exec(&self, sql: &str) -> Result<(), PlatformError> {
        // A NUL byte would silently cut the SQL short.
        let sql = CString::new(sql).map_err(|_| refused(Operation::Execute, SqliteCode::MISUSE))?;
        // SAFETY: `self.raw` is open, `sql` is NUL-terminated and outlives the call, there is no callback, and a
        // null error-message pointer tells SQLite not to allocate a message (which could quote the SQL).
        let code = unsafe {
            ffi::sqlite3_exec(
                self.raw.as_ptr(),
                sql.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        check(Operation::Execute, code)
    }

    /// Compiles exactly one SQL statement, with `?` or `?NNN` placeholders for its values.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Sqlite`] with [`Operation::Prepare`]: `SQLITE_TOOBIG` for SQL longer than `i32::MAX`
    /// bytes; `SQLITE_MISUSE` if `sql` holds no statement or more than one (anything but whitespace after the
    /// first, including a NUL byte); otherwise the code SQLite returned (for example `SQLITE_ERROR` for a syntax
    /// error).
    pub fn prepare(&self, sql: &str) -> Result<Statement<'_>, PlatformError> {
        let len = c_int::try_from(sql.len()).map_err(|_| refused(Operation::Prepare, SqliteCode::TOOBIG))?;
        let mut raw = ptr::null_mut();
        let mut tail = ptr::null();
        // SAFETY: `self.raw` is open; `sql` is valid for `len` bytes and outlives the call (SQLite does not keep
        // the pointer); `raw` and `tail` are valid out-pointers.
        let code = unsafe {
            ffi::sqlite3_prepare_v2(self.raw.as_ptr(), sql.as_ptr().cast(), len, &raw mut raw, &raw mut tail)
        };
        check(Operation::Prepare, code)?;
        // No statement and no error means the text was empty or only a comment.
        let raw = NonNull::new(raw).ok_or_else(|| refused(Operation::Prepare, SqliteCode::MISUSE))?;
        // From here on, dropping `statement` finalizes it, including on the error path below.
        let statement = Statement {
            raw,
            connection: PhantomData,
            on_row: false,
        };
        // `tail` points just past the first statement, inside `sql` or at its end. Anything after it but
        // whitespace is a second statement that would be silently ignored, so it is refused. Comparing addresses
        // needs no `unsafe`; an out-of-range offset (which SQLite never returns) is refused too.
        let consumed = tail.addr().wrapping_sub(sql.as_ptr().addr());
        match sql.as_bytes().get(consumed..) {
            Some(rest) if rest.iter().all(u8::is_ascii_whitespace) => Ok(statement),
            Some(_) | None => Err(refused(Operation::Prepare, SqliteCode::MISUSE)),
        }
    }

    /// Prepares one statement, binds `params` to it (exactly as many as it has placeholders), runs it to
    /// completion and returns the number of rows the last `INSERT`, `UPDATE` or `DELETE` changed. Result rows,
    /// if any, are discarded.
    ///
    /// # Errors
    ///
    /// As [`Connection::prepare`], [`Statement::bind_all`] and [`Statement::step`].
    pub fn execute(&self, sql: &str, params: &[Value<'_>]) -> Result<u64, PlatformError> {
        let mut statement = self.prepare(sql)?;
        statement.bind_all(params)?;
        while statement.step()? == Step::Row {}
        Ok(self.changes())
    }

    /// Rows changed by the most recent `INSERT`, `UPDATE` or `DELETE` on this connection.
    #[must_use]
    pub fn changes(&self) -> u64 {
        // SAFETY: `self.raw` is an open connection handle.
        let changes = unsafe { ffi::sqlite3_changes(self.raw.as_ptr()) };
        // SQLite never reports a negative count.
        u64::try_from(changes).unwrap_or(0)
    }

    /// The rowid of the most recent successful `INSERT` on this connection, or `0` if there was none.
    #[must_use]
    pub fn last_insert_rowid(&self) -> i64 {
        // SAFETY: `self.raw` is an open connection handle.
        unsafe { ffi::sqlite3_last_insert_rowid(self.raw.as_ptr()) }
    }

    /// Starts a transaction with `BEGIN IMMEDIATE`, taking the write lock up front so a later write cannot fail
    /// with `SQLITE_BUSY` halfway through.
    ///
    /// The guard rolls the transaction back when dropped unless [`Transaction::commit`] succeeded. It borrows the
    /// connection mutably and only hands out shared access, so transactions cannot nest.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Sqlite`] with [`Operation::Execute`], for example `SQLITE_BUSY` if another connection
    /// holds the write lock past the busy timeout.
    pub fn transaction(&mut self) -> Result<Transaction<'_>, PlatformError> {
        self.exec("BEGIN IMMEDIATE")?;
        Ok(Transaction {
            connection: self,
            finished: false,
        })
    }

    /// Whether a transaction is open (`sqlite3_get_autocommit` is false).
    fn in_transaction(&self) -> bool {
        // SAFETY: `self.raw` is an open connection handle.
        unsafe { ffi::sqlite3_get_autocommit(self.raw.as_ptr()) == 0 }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: `self.raw` is open and is not used after this. Every `Statement` borrows the connection, so all
        // of them were finalized already; `close_v2` would still defer the close safely if one were not. A close
        // error cannot be acted on in `drop`, and the handle is released either way.
        unsafe {
            ffi::sqlite3_close_v2(self.raw.as_ptr());
        }
    }
}

/// A prepared statement. Borrows its [`Connection`], so it cannot outlive it; dropping it finalizes it.
#[derive(Debug)]
pub struct Statement<'c> {
    raw: NonNull<ffi::Sqlite3Stmt>,
    /// Ties the statement's lifetime to its connection, so the connection cannot be closed while it exists.
    connection: PhantomData<&'c Connection>,
    /// Whether the last step returned a row, which makes the column readers valid.
    on_row: bool,
}

impl Statement<'_> {
    /// The number of parameters (placeholders) in the statement.
    #[must_use]
    pub fn parameter_count(&self) -> usize {
        // SAFETY: `self.raw` is a live statement handle.
        let count = unsafe { ffi::sqlite3_bind_parameter_count(self.raw.as_ptr()) };
        usize::try_from(count).unwrap_or(0)
    }

    /// Binds `value` to the parameter at `index` (1-based, as in SQLite). Text and blobs are copied by SQLite.
    ///
    /// Bind before the first step or after [`Statement::reset`] (which also clears earlier bindings).
    ///
    /// # Errors
    ///
    /// [`PlatformError::Sqlite`] with [`Operation::Bind`]: `SQLITE_RANGE` for an index out of range,
    /// `SQLITE_TOOBIG` for a value over SQLite's size limit, `SQLITE_MISUSE` if the statement has been stepped
    /// since the last reset.
    pub fn bind(&mut self, index: usize, value: Value<'_>) -> Result<(), PlatformError> {
        let index = c_int::try_from(index).map_err(|_| refused(Operation::Bind, SqliteCode::RANGE))?;
        let raw = self.raw.as_ptr();
        let code = match value {
            // SAFETY: `raw` is a live statement; SQLite range-checks `index` itself.
            Value::Null => unsafe { ffi::sqlite3_bind_null(raw, index) },
            // SAFETY: as above.
            Value::Integer(n) => unsafe { ffi::sqlite3_bind_int64(raw, index, n) },
            // SAFETY: `text` is valid UTF-8 for `text.len()` bytes during the call, and `SQLITE_TRANSIENT` makes
            // SQLite copy it before returning, so the borrow need not outlive the call. A Rust slice pointer is
            // never null, so an empty string binds as empty text, not `NULL`.
            Value::Text(text) => unsafe {
                ffi::sqlite3_bind_text64(
                    raw,
                    index,
                    text.as_ptr().cast(),
                    text.len() as u64,
                    ffi::SQLITE_TRANSIENT,
                    ffi::SQLITE_UTF8,
                )
            },
            // SAFETY: as for text: valid for `bytes.len()` bytes, copied before returning, never null.
            Value::Blob(bytes) => unsafe {
                ffi::sqlite3_bind_blob64(
                    raw,
                    index,
                    bytes.as_ptr().cast(),
                    bytes.len() as u64,
                    ffi::SQLITE_TRANSIENT,
                )
            },
        };
        check(Operation::Bind, code)
    }

    /// Resets the statement and binds `values` to parameters `1..=values.len()`. The count must match
    /// [`Statement::parameter_count`] exactly, so a forgotten parameter never silently binds as `NULL`.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Sqlite`] with [`Operation::Bind`]: `SQLITE_RANGE` if the count differs, otherwise as
    /// [`Statement::bind`].
    pub fn bind_all(&mut self, values: &[Value<'_>]) -> Result<(), PlatformError> {
        if values.len() != self.parameter_count() {
            return Err(refused(Operation::Bind, SqliteCode::RANGE));
        }
        self.reset();
        for (offset, value) in values.iter().enumerate() {
            self.bind(offset + 1, *value)?;
        }
        Ok(())
    }

    /// Runs the statement until the next result row or the end.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Sqlite`] with [`Operation::Step`] and the extended code, for example
    /// `SQLITE_CONSTRAINT_UNIQUE` or `SQLITE_BUSY`. The statement then needs [`Statement::reset`] before reuse.
    pub fn step(&mut self) -> Result<Step, PlatformError> {
        self.on_row = false;
        // SAFETY: `self.raw` is a live statement on an open connection (the borrow keeps it open).
        let code = unsafe { ffi::sqlite3_step(self.raw.as_ptr()) };
        match code {
            ffi::SQLITE_ROW => {
                self.on_row = true;
                Ok(Step::Row)
            }
            ffi::SQLITE_DONE => Ok(Step::Done),
            _ => Err(error(Operation::Step, code)),
        }
    }

    /// Rewinds the statement to before its first step and clears every binding (they read as `NULL` again).
    ///
    /// Infallible: `sqlite3_reset` only repeats the error of the last step, which [`Statement::step`] already
    /// returned.
    pub fn reset(&mut self) {
        self.on_row = false;
        // SAFETY: `self.raw` is a live statement handle. Both calls only report earlier errors, so their results
        // are ignored.
        unsafe {
            ffi::sqlite3_reset(self.raw.as_ptr());
            ffi::sqlite3_clear_bindings(self.raw.as_ptr());
        }
    }

    /// The number of columns in a result row (`0` for a statement that returns no rows).
    #[must_use]
    pub fn column_count(&self) -> usize {
        // SAFETY: `self.raw` is a live statement handle.
        let count = unsafe { ffi::sqlite3_column_count(self.raw.as_ptr()) };
        usize::try_from(count).unwrap_or(0)
    }

    /// Checks that a row is current and `column` is in range. Reading a column otherwise is undefined in SQLite.
    fn column_index(&self, column: usize) -> Result<c_int, PlatformError> {
        if !self.on_row {
            return Err(refused(Operation::Column, SqliteCode::MISUSE));
        }
        if column >= self.column_count() {
            return Err(refused(Operation::Column, SqliteCode::RANGE));
        }
        c_int::try_from(column).map_err(|_| refused(Operation::Column, SqliteCode::RANGE))
    }

    /// The storage class of `column` (0-based) in the current row.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Sqlite`] with [`Operation::Column`]: `SQLITE_MISUSE` if no row is current, `SQLITE_RANGE`
    /// for an index out of range.
    pub fn column_type(&self, column: usize) -> Result<ColumnType, PlatformError> {
        let index = self.column_index(column)?;
        // SAFETY: a row is current and `index` is in range (checked above).
        let kind = unsafe { ffi::sqlite3_column_type(self.raw.as_ptr(), index) };
        match kind {
            ffi::SQLITE_INTEGER => Ok(ColumnType::Integer),
            ffi::SQLITE_FLOAT => Ok(ColumnType::Float),
            ffi::SQLITE_TEXT => Ok(ColumnType::Text),
            ffi::SQLITE_BLOB => Ok(ColumnType::Blob),
            ffi::SQLITE_NULL => Ok(ColumnType::Null),
            _ => Err(refused(Operation::Column, SqliteCode::MISMATCH)),
        }
    }

    /// Reads an integer column: `None` for `NULL`. No conversion from other types is done.
    ///
    /// # Errors
    ///
    /// As [`Statement::column_type`], and `SQLITE_MISMATCH` if the column holds anything but an integer or `NULL`.
    pub fn column_i64(&self, column: usize) -> Result<Option<i64>, PlatformError> {
        match self.column_type(column)? {
            ColumnType::Null => Ok(None),
            ColumnType::Integer => {
                let index = self.column_index(column)?;
                // SAFETY: a row is current and `index` is in range (checked above); the value is an integer, so
                // no conversion happens.
                Ok(Some(unsafe { ffi::sqlite3_column_int64(self.raw.as_ptr(), index) }))
            }
            ColumnType::Float | ColumnType::Text | ColumnType::Blob => {
                Err(refused(Operation::Column, SqliteCode::MISMATCH))
            }
        }
    }

    /// Reads a text column into an owned string: `None` for `NULL`. No conversion from other types is done.
    ///
    /// # Errors
    ///
    /// As [`Statement::column_type`]; `SQLITE_MISMATCH` if the column is not text or `NULL`, or its bytes are not
    /// valid UTF-8; `SQLITE_NOMEM` if SQLite could not produce the value.
    pub fn column_text(&self, column: usize) -> Result<Option<String>, PlatformError> {
        match self.column_type(column)? {
            ColumnType::Null => Ok(None),
            ColumnType::Text => {
                let bytes = self.column_bytes(column, true)?;
                String::from_utf8(bytes)
                    .map(Some)
                    .map_err(|_| refused(Operation::Column, SqliteCode::MISMATCH))
            }
            ColumnType::Integer | ColumnType::Float | ColumnType::Blob => {
                Err(refused(Operation::Column, SqliteCode::MISMATCH))
            }
        }
    }

    /// Reads a blob column into owned bytes, exactly as stored: `None` for `NULL`. No conversion from other types
    /// is done.
    ///
    /// # Errors
    ///
    /// As [`Statement::column_type`], and `SQLITE_MISMATCH` if the column is not a blob or `NULL`.
    pub fn column_blob(&self, column: usize) -> Result<Option<Vec<u8>>, PlatformError> {
        match self.column_type(column)? {
            ColumnType::Null => Ok(None),
            ColumnType::Blob => self.column_bytes(column, false).map(Some),
            ColumnType::Integer | ColumnType::Float | ColumnType::Text => {
                Err(refused(Operation::Column, SqliteCode::MISMATCH))
            }
        }
    }

    /// Copies the bytes of a text (`text = true`) or blob column. The caller has checked the column's type, so
    /// SQLite converts nothing and the pointer stays valid until the next step, reset or finalize, all of which
    /// need `&mut self` and so cannot happen while this copy runs.
    fn column_bytes(&self, column: usize, text: bool) -> Result<Vec<u8>, PlatformError> {
        let index = self.column_index(column)?;
        let raw = self.raw.as_ptr();
        // SQLite's documented order: fetch the pointer first, then its length.
        let data: *const u8 = if text {
            // SAFETY: a row is current, `index` is in range and the column is text.
            unsafe { ffi::sqlite3_column_text(raw, index) }
        } else {
            // SAFETY: a row is current, `index` is in range and the column is a blob.
            unsafe { ffi::sqlite3_column_blob(raw, index).cast() }
        };
        // SAFETY: as above; `column_bytes` reports the length of the value just fetched.
        let len = unsafe { ffi::sqlite3_column_bytes(raw, index) };
        let len = usize::try_from(len).map_err(|_| refused(Operation::Column, SqliteCode::MISMATCH))?;
        if data.is_null() {
            // A zero-length blob is returned as a null pointer. Text is never null when the type is `TEXT`, so a
            // null pointer there (or a non-zero length) means SQLite failed to allocate.
            return if len == 0 && !text {
                Ok(Vec::new())
            } else {
                Err(refused(Operation::Column, SqliteCode::NOMEM))
            };
        }
        // SAFETY: `data` is non-null and points to `len` readable bytes owned by SQLite, valid until the next
        // step, reset or finalize (none can run while `&self` is borrowed). They are copied before returning.
        Ok(unsafe { std::slice::from_raw_parts(data, len) }.to_vec())
    }
}

impl Drop for Statement<'_> {
    fn drop(&mut self) {
        // SAFETY: `self.raw` is live and not used after this; the borrowed connection is still open. The result
        // only repeats the last step's error, which `step` already returned.
        unsafe {
            ffi::sqlite3_finalize(self.raw.as_ptr());
        }
    }
}

/// An open transaction. Rolls back when dropped unless [`Transaction::commit`] succeeded.
///
/// Dereferences to the [`Connection`] for statements inside the transaction. Those statements borrow the guard, so
/// they are all finalized before it commits or rolls back.
#[derive(Debug)]
pub struct Transaction<'c> {
    connection: &'c mut Connection,
    /// Set once `COMMIT` or `ROLLBACK` succeeded, so `Drop` has nothing left to undo.
    finished: bool,
}

impl Transaction<'_> {
    /// Commits the transaction.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Sqlite`] with [`Operation::Execute`], for example `SQLITE_BUSY` if readers block the
    /// commit past the busy timeout. The transaction is then rolled back when the guard drops, so on error
    /// nothing was written.
    pub fn commit(mut self) -> Result<(), PlatformError> {
        self.connection.exec("COMMIT")?;
        self.finished = true;
        Ok(())
    }

    /// Rolls the transaction back explicitly, reporting any error (dropping the guard does the same silently).
    ///
    /// # Errors
    ///
    /// [`PlatformError::Sqlite`] with [`Operation::Execute`].
    pub fn rollback(mut self) -> Result<(), PlatformError> {
        self.connection.exec("ROLLBACK")?;
        self.finished = true;
        Ok(())
    }
}

impl Deref for Transaction<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.connection
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        // SQLite rolls some failures back by itself (for example `SQLITE_FULL`); only roll back what is still open.
        if !self.finished && self.connection.in_transaction() {
            // Nothing can be reported from `drop`. If even the rollback fails, closing the connection discards the
            // transaction, so uncommitted changes are never kept.
            let _ = self.connection.exec("ROLLBACK");
        }
    }
}
