//! Hand-written declarations for the subset of the system SQLite C API this crate uses.
//!
//! Linked against the system `libsqlite3` (`/usr/lib/libsqlite3.dylib` on macOS, resolved through the SDK's
//! `libsqlite3.tbd`). There is no bundled copy, no build script and no download (NFR-SUP, supply chain). Every
//! declaration matches `sqlite3.h`; only functions available since SQLite 3.31 (macOS 14 ships 3.39 or later) are
//! used, because `SQLITE_OPEN_NOFOLLOW` needs 3.31.
//!
//! Nothing here is safe to call directly: the safe API is in the parent module.

use std::ffi::{c_char, c_int, c_uchar, c_void};

/// Opaque connection handle (`sqlite3`).
#[repr(C)]
pub(crate) struct Sqlite3 {
    _private: [u8; 0],
}

/// Opaque prepared statement handle (`sqlite3_stmt`).
#[repr(C)]
pub(crate) struct Sqlite3Stmt {
    _private: [u8; 0],
}

pub(crate) const SQLITE_OK: c_int = 0;
pub(crate) const SQLITE_ROW: c_int = 100;
pub(crate) const SQLITE_DONE: c_int = 101;

pub(crate) const SQLITE_OPEN_READWRITE: c_int = 0x0000_0002;
/// Serialized threading mode: the connection may be used from any one thread at a time (see `Connection: Send`).
pub(crate) const SQLITE_OPEN_FULLMUTEX: c_int = 0x0001_0000;
/// Refuse to open the database if its path is a symlink (SQLite 3.31+).
pub(crate) const SQLITE_OPEN_NOFOLLOW: c_int = 0x0100_0000;

pub(crate) const SQLITE_INTEGER: c_int = 1;
pub(crate) const SQLITE_FLOAT: c_int = 2;
pub(crate) const SQLITE_TEXT: c_int = 3;
pub(crate) const SQLITE_BLOB: c_int = 4;
pub(crate) const SQLITE_NULL: c_int = 5;

/// Text encoding argument of `sqlite3_bind_text64`.
pub(crate) const SQLITE_UTF8: c_uchar = 1;

/// The `SQLITE_TRANSIENT` destructor sentinel, `((sqlite3_destructor_type)-1)`: SQLite copies the bound bytes before
/// the bind call returns, so the Rust slice need not outlive the call.
///
/// The C parameter is a function pointer; it is declared here as a pointer-sized integer so the sentinel can be
/// passed without forging a function pointer. Both are passed in one general-purpose register on every Apple ABI
/// (arm64 and `x86_64`), so the call is identical.
pub(crate) const SQLITE_TRANSIENT: isize = -1;

#[link(name = "sqlite3")]
unsafe extern "C" {
    /// Non-zero if the library was built thread-safe.
    pub(crate) fn sqlite3_threadsafe() -> c_int;

    pub(crate) fn sqlite3_open_v2(
        filename: *const c_char,
        db: *mut *mut Sqlite3,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    pub(crate) fn sqlite3_close_v2(db: *mut Sqlite3) -> c_int;
    pub(crate) fn sqlite3_extended_result_codes(db: *mut Sqlite3, onoff: c_int) -> c_int;
    pub(crate) fn sqlite3_extended_errcode(db: *mut Sqlite3) -> c_int;
    pub(crate) fn sqlite3_busy_timeout(db: *mut Sqlite3, ms: c_int) -> c_int;
    pub(crate) fn sqlite3_exec(
        db: *mut Sqlite3,
        sql: *const c_char,
        callback: *const c_void,
        arg: *mut c_void,
        errmsg: *mut *mut c_char,
    ) -> c_int;
    pub(crate) fn sqlite3_get_autocommit(db: *mut Sqlite3) -> c_int;
    pub(crate) fn sqlite3_changes(db: *mut Sqlite3) -> c_int;
    pub(crate) fn sqlite3_last_insert_rowid(db: *mut Sqlite3) -> i64;

    pub(crate) fn sqlite3_prepare_v2(
        db: *mut Sqlite3,
        sql: *const c_char,
        n_byte: c_int,
        stmt: *mut *mut Sqlite3Stmt,
        tail: *mut *const c_char,
    ) -> c_int;
    pub(crate) fn sqlite3_finalize(stmt: *mut Sqlite3Stmt) -> c_int;
    pub(crate) fn sqlite3_reset(stmt: *mut Sqlite3Stmt) -> c_int;
    pub(crate) fn sqlite3_clear_bindings(stmt: *mut Sqlite3Stmt) -> c_int;
    pub(crate) fn sqlite3_step(stmt: *mut Sqlite3Stmt) -> c_int;

    pub(crate) fn sqlite3_bind_parameter_count(stmt: *mut Sqlite3Stmt) -> c_int;
    pub(crate) fn sqlite3_bind_null(stmt: *mut Sqlite3Stmt, index: c_int) -> c_int;
    pub(crate) fn sqlite3_bind_int64(stmt: *mut Sqlite3Stmt, index: c_int, value: i64) -> c_int;
    pub(crate) fn sqlite3_bind_text64(
        stmt: *mut Sqlite3Stmt,
        index: c_int,
        text: *const c_char,
        len: u64,
        destructor: isize,
        encoding: c_uchar,
    ) -> c_int;
    pub(crate) fn sqlite3_bind_blob64(
        stmt: *mut Sqlite3Stmt,
        index: c_int,
        data: *const c_void,
        len: u64,
        destructor: isize,
    ) -> c_int;

    pub(crate) fn sqlite3_column_count(stmt: *mut Sqlite3Stmt) -> c_int;
    pub(crate) fn sqlite3_column_type(stmt: *mut Sqlite3Stmt, column: c_int) -> c_int;
    pub(crate) fn sqlite3_column_int64(stmt: *mut Sqlite3Stmt, column: c_int) -> i64;
    pub(crate) fn sqlite3_column_text(stmt: *mut Sqlite3Stmt, column: c_int) -> *const c_uchar;
    pub(crate) fn sqlite3_column_blob(stmt: *mut Sqlite3Stmt, column: c_int) -> *const c_void;
    pub(crate) fn sqlite3_column_bytes(stmt: *mut Sqlite3Stmt, column: c_int) -> c_int;
}
