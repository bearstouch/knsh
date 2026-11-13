//! Output capping (FR-REC-06): at most a fixed number of bytes per stream, head and tail kept.
//!
//! A command can write gigabytes; the store keeps the start (where errors about arguments appear) and the end (where
//! the final error or summary appears) and counts what it dropped in between.

use knsh_core::OutputInfo;

/// The default cap per stream: 1 MB (`specs/09-reference/defaults-and-limits.md`).
pub const DEFAULT_OUTPUT_CAP: usize = 1 << 20;

/// One stream as it will be stored: `data` is head then tail, `info` describes what was dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Capped {
    /// The stored bytes, at most the cap.
    pub(crate) data: Vec<u8>,
    /// Sizes and where the dropped bytes were.
    pub(crate) info: OutputInfo,
}

/// Caps `output` at `cap` bytes. Within the cap the output is kept whole; beyond it the first `cap / 2` and the
/// last `cap - cap / 2` bytes are kept, so exactly `cap` bytes are stored.
pub(crate) fn cap_output(output: &[u8], cap: usize) -> Capped {
    let original = len_u64(output.len());
    if output.len() <= cap {
        return Capped {
            data: output.to_vec(),
            info: OutputInfo {
                stored: original,
                original,
                skipped: 0,
                skipped_at: original,
            },
        };
    }
    let head_len = cap / 2;
    let tail_len = cap - head_len;
    // `output.len() > cap >= head_len + tail_len`, so both slices are in range and do not overlap.
    let head = output.get(..head_len).unwrap_or_default();
    let tail = output.get(output.len() - tail_len..).unwrap_or_default();
    let mut data = Vec::with_capacity(cap);
    data.extend_from_slice(head);
    data.extend_from_slice(tail);
    let stored = len_u64(data.len());
    Capped {
        data,
        info: OutputInfo {
            stored,
            original,
            skipped: original - stored,
            skipped_at: len_u64(head_len),
        },
    }
}

/// A byte length as `u64`. Lengths of in-memory buffers always fit.
pub(crate) fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_within_cap_is_kept_whole() {
        for output in [&b""[..], b"hello", &[7u8; 16][..]] {
            let capped = cap_output(output, 16);
            assert_eq!(capped.data, output);
            assert_eq!(capped.info.skipped, 0);
            assert_eq!(capped.info.stored, capped.info.original);
            assert_eq!(capped.info.skipped_at, capped.info.stored);
        }
    }

    // FR-REC-06: beyond the cap, head and tail are kept with the skipped-byte count.
    #[test]
    fn output_over_cap_keeps_head_and_tail() {
        let output: Vec<u8> = (0..100u8).collect();
        let capped = cap_output(&output, 11);
        let mut expected: Vec<u8> = (0..5).collect();
        expected.extend(94..100);
        assert_eq!(capped.data, expected);
        assert_eq!(
            capped.info,
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
        assert_eq!(capped.data.len(), DEFAULT_OUTPUT_CAP);
        assert_eq!(capped.info.skipped, 2 * len_u64(DEFAULT_OUTPUT_CAP));
        assert_eq!(capped.info.stored + capped.info.skipped, capped.info.original);
    }
}
