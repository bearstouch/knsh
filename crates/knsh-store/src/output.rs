//! Output capping (FR-REC-06): at most a fixed number of bytes per stream, head and tail kept.
//!
//! A command can write gigabytes; the store keeps the start (where errors about arguments appear) and the end (where
//! the final error or summary appears) and counts what it dropped in between. The capping itself is
//! [`knsh_core::CappedOutput::recap`], shared with the supervisor, which caps while it reads (KNSH-053).

/// The default cap per stream: 1 MB (`specs/09-reference/defaults-and-limits.md`).
pub const DEFAULT_OUTPUT_CAP: usize = knsh_core::DEFAULT_OUTPUT_CAP;

/// A byte length as `u64`. Lengths of in-memory buffers always fit.
pub(crate) fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use knsh_core::{CappedOutput, OutputInfo, Redacted};

    use super::*;

    fn cap_output(output: &[u8], cap: usize) -> CappedOutput {
        CappedOutput::whole(Redacted::new(output.to_vec())).recap(cap)
    }

    #[test]
    fn output_within_cap_is_kept_whole() {
        for output in [&b""[..], b"hello", &[7u8; 16][..]] {
            let capped = cap_output(output, 16);
            assert_eq!(capped.data().expose(), output);
            assert_eq!(capped.info().skipped, 0);
            assert_eq!(capped.info().stored, capped.info().original);
            assert_eq!(capped.info().skipped_at, capped.info().stored);
        }
    }

    // FR-REC-06: beyond the cap, head and tail are kept with the skipped-byte count.
    #[test]
    fn output_over_cap_keeps_head_and_tail() {
        let output: Vec<u8> = (0..100u8).collect();
        let capped = cap_output(&output, 11);
        let mut expected: Vec<u8> = (0..5).collect();
        expected.extend(94..100);
        assert_eq!(capped.data().expose(), &expected);
        assert_eq!(
            capped.info(),
            OutputInfo {
                stored: 11,
                original: 100,
                skipped: 89,
                skipped_at: 5,
            }
        );

        // The default cap: exactly 1 MB stored from 3 MB written.
        let big = vec![b'x'; 3 * DEFAULT_OUTPUT_CAP];
        let capped = cap_output(&big, DEFAULT_OUTPUT_CAP);
        assert_eq!(capped.data().expose().len(), DEFAULT_OUTPUT_CAP);
        assert_eq!(capped.info().skipped, 2 * len_u64(DEFAULT_OUTPUT_CAP));
        assert_eq!(capped.info().stored + capped.info().skipped, capped.info().original);
    }
}
