//! Checkpoint results on the wire (KNSH-084): the `-32004` error of an undo or redo that would overwrite work the
//! engine did not record (FR-CKP-20, `specs/06-api/errors.md`).

use knsh_core::RestoreConflict;
use knsh_json::{JsonError, Object, Value};

use crate::envelope::RpcError;
use crate::error_code::ErrorCode;

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

#[cfg(test)]
mod tests {
    use knsh_core::{CanonicalPath, ConflictReason};

    use super::*;

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
