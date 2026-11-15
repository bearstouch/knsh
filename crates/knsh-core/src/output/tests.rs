//! Capture, capping and output modes (KNSH-053).

use super::*;

fn captured(chunks: &[&[u8]], cap: usize) -> CapturedStream {
    let mut capture = OutputCapture::new(cap);
    for chunk in chunks {
        capture.push(chunk);
    }
    capture.finish()
}

fn text(bytes: &Redacted<Vec<u8>>) -> &str {
    std::str::from_utf8(bytes.expose()).unwrap()
}

/// `n` numbered lines, `line 1\n` to `line n\n`.
fn numbered(n: usize) -> Vec<u8> {
    (1..=n).flat_map(|i| format!("line {i}\n").into_bytes()).collect()
}

#[test]
fn capture_within_cap_is_kept_whole_with_line_count() {
    let stream = captured(&[b"one\ntw", b"o\nthree"], 64);
    assert_eq!(stream.output.data().expose(), b"one\ntwo\nthree");
    assert_eq!(
        stream.output.info(),
        OutputInfo {
            stored: 13,
            original: 13,
            skipped: 0,
            skipped_at: 13,
        }
    );
    assert_eq!(stream.lines, 3, "a last line without a newline counts");
    assert_eq!(captured(&[b"a\n", b"b\n"], 64).lines, 2);
    assert_eq!(captured(&[], 64).lines, 0);
    assert_eq!(captured(&[b"\n"], 64).lines, 1);
}

// FR-REC-06: beyond the cap the head and the tail are kept, with the skipped size, whatever the chunking.
#[test]
fn keeps_head_and_tail_beyond_one_megabyte() {
    let written: Vec<u8> = (0..3 * DEFAULT_OUTPUT_CAP)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    for chunk_len in [1usize, 4096, 65_536, written.len()] {
        if chunk_len == 1 {
            // A byte at a time over 3 MB is slow in debug builds; a smaller cap checks the same ring logic.
            let small: Vec<u8> = (0..1000u32).map(|i| u8::try_from(i % 251).unwrap()).collect();
            let mut capture = OutputCapture::new(100);
            for byte in &small {
                capture.push(std::slice::from_ref(byte));
            }
            let stream = capture.finish();
            let mut expected = small[..50].to_vec();
            expected.extend_from_slice(&small[950..]);
            assert_eq!(stream.output.data().expose(), &expected);
            continue;
        }
        let mut capture = OutputCapture::new(DEFAULT_OUTPUT_CAP);
        for chunk in written.chunks(chunk_len) {
            capture.push(chunk);
        }
        let stream = capture.finish();
        let half = DEFAULT_OUTPUT_CAP / 2;
        let mut expected = written[..half].to_vec();
        expected.extend_from_slice(&written[written.len() - (DEFAULT_OUTPUT_CAP - half)..]);
        assert_eq!(stream.output.data().expose(), &expected, "chunks of {chunk_len}");
        assert_eq!(
            stream.output.info(),
            OutputInfo {
                stored: DEFAULT_OUTPUT_CAP as u64,
                original: written.len() as u64,
                skipped: 2 * DEFAULT_OUTPUT_CAP as u64,
                skipped_at: half as u64,
            }
        );
    }
}

// A capped stream re-capped smaller keeps a true head and tail of the original; one that fits is unchanged.
#[test]
fn recap_keeps_bytes_at_their_place() {
    let written: Vec<u8> = (0..100u8).collect();
    let stream = captured(&[&written], 40).output;
    assert_eq!(stream.clone().recap(40).data().expose(), stream.data().expose());
    let smaller = stream.recap(10);
    let mut expected: Vec<u8> = (0..5).collect();
    expected.extend(95..100);
    assert_eq!(smaller.data().expose(), &expected);
    assert_eq!(
        smaller.info(),
        OutputInfo {
            stored: 10,
            original: 100,
            skipped: 90,
            skipped_at: 5,
        }
    );
    // Whole output capped for the first time.
    let whole = CappedOutput::whole(Redacted::new(written)).recap(11);
    let mut expected: Vec<u8> = (0..5).collect();
    expected.extend(94..100);
    assert_eq!(whole.data().expose(), &expected);
    assert_eq!(whole.info().skipped_at, 5);
    assert_eq!(whole.info().stored + whole.info().skipped, 100);
}

// FR-OUT-01: `full` returns each stream as kept, so never more than the cap (1 MB) per stream.
#[test]
fn full_mode_caps_each_stream_at_one_megabyte() {
    let big = vec![b'x'; 2 * DEFAULT_OUTPUT_CAP];
    let stdout = captured(&[&big], DEFAULT_OUTPUT_CAP);
    let stderr = captured(&[b"warning\n"], DEFAULT_OUTPUT_CAP);
    let ShapedOutput::Full { stdout, stderr } = shape(OutputRequest::new(OutputMode::Full), &stdout, &stderr) else {
        panic!("full");
    };
    assert_eq!(stdout.bytes.expose().len(), DEFAULT_OUTPUT_CAP);
    assert_eq!(stdout.skipped, DEFAULT_OUTPUT_CAP as u64);
    assert_eq!(text(&stderr.bytes), "warning\n");
    assert_eq!(stderr.skipped, 0);
}

// FR-OUT-01: `truncate` returns the first `max_bytes` of each stream and counts the rest.
#[test]
fn truncate_returns_first_max_bytes() {
    let stdout = captured(&[b"0123456789"], 64);
    let stderr = captured(&[b"abc"], 64);
    let request = OutputRequest {
        max_bytes: 4,
        ..OutputRequest::new(OutputMode::Truncate)
    };
    let ShapedOutput::Truncate {
        stdout: out,
        stderr: err,
    } = shape(request, &stdout, &stderr)
    else {
        panic!("truncate");
    };
    assert_eq!(text(&out.bytes), "0123");
    assert_eq!(out.skipped, 6);
    assert_eq!(text(&err.bytes), "abc");
    assert_eq!(err.skipped, 0);
    // Past a gap the stream is not contiguous: only the head is returned.
    let long: Vec<u8> = (0..100u8).collect();
    let gapped = captured(&[&long], 20);
    let ShapedOutput::Truncate { stdout: out, .. } = shape(
        OutputRequest {
            max_bytes: 50,
            ..request
        },
        &gapped,
        &stderr,
    ) else {
        panic!("truncate");
    };
    assert_eq!(out.bytes.expose(), &(0..10u8).collect::<Vec<_>>());
    assert_eq!(out.skipped, 90);
}

// FR-OUT-01: `head_tail` returns the first and last `lines` lines and how many lines were skipped between them.
#[test]
fn head_tail_reports_skipped_line_count() {
    let stdout = captured(&[&numbered(10)], 1024);
    let stderr = captured(&[b"only\n"], 1024);
    let request = OutputRequest {
        lines: 2,
        ..OutputRequest::new(OutputMode::HeadTail)
    };
    let ShapedOutput::HeadTail {
        stdout: out,
        stderr: err,
    } = shape(request, &stdout, &stderr)
    else {
        panic!("head_tail");
    };
    assert_eq!(text(&out.head), "line 1\nline 2\n");
    assert_eq!(text(&out.tail), "line 9\nline 10\n");
    assert_eq!(out.skipped_lines, 6);
    // Few enough lines: all of them, nothing skipped, nothing repeated.
    assert_eq!(text(&err.head), "only\n");
    assert_eq!(text(&err.tail), "");
    assert_eq!(err.skipped_lines, 0);
    let five = captured(&[&numbered(5)], 1024);
    let ShapedOutput::HeadTail { stdout: out, .. } = shape(request, &five, &stderr) else {
        panic!("head_tail");
    };
    assert_eq!(text(&out.head), "line 1\nline 2\n");
    assert_eq!(text(&out.tail), "line 4\nline 5\n");
    assert_eq!(out.skipped_lines, 1);
    // Over the cap: head lines before the gap, tail lines after it.
    let many = captured(&[&numbered(10_000)], 4096);
    let ShapedOutput::HeadTail { stdout: out, .. } = shape(request, &many, &stderr) else {
        panic!("head_tail");
    };
    assert_eq!(text(&out.head), "line 1\nline 2\n");
    assert_eq!(text(&out.tail), "line 9999\nline 10000\n");
    assert_eq!(out.skipped_lines, 9996);
}

// FR-OUT-01: `errors_only` returns stderr whole and only the last 20 lines of stdout.
#[test]
fn errors_only_returns_last_twenty_stdout_lines() {
    let stdout = captured(&[&numbered(100)], 1 << 16);
    let stderr = captured(&[b"error: it broke\n"], 1 << 16);
    let ShapedOutput::ErrorsOnly {
        stderr,
        stdout_tail,
        stdout_skipped_lines,
    } = shape(OutputRequest::new(OutputMode::ErrorsOnly), &stdout, &stderr)
    else {
        panic!("errors_only");
    };
    assert_eq!(text(&stderr.bytes), "error: it broke\n");
    let expected = String::from_utf8(numbered(100)[numbered(80).len()..].to_vec()).unwrap();
    assert_eq!(text(&stdout_tail), expected);
    assert_eq!(stdout_skipped_lines, 80);
    // A short stdout comes back whole; a last line without a newline is a line.
    let short = captured(&[b"a\nb"], 64);
    let ShapedOutput::ErrorsOnly {
        stdout_tail,
        stdout_skipped_lines,
        ..
    } = shape(OutputRequest::new(OutputMode::ErrorsOnly), &short, &short)
    else {
        panic!("errors_only");
    };
    assert_eq!(text(&stdout_tail), "a\nb");
    assert_eq!(stdout_skipped_lines, 0);
}

// `ref` selects no bytes at all.
#[test]
fn ref_mode_selects_no_output() {
    let stream = captured(&[b"secret-free but still not returned\n"], 64);
    assert!(matches!(
        shape(OutputRequest::new(OutputMode::Ref), &stream, &stream),
        ShapedOutput::Ref
    ));
}

#[test]
fn last_lines_counts_edges() {
    assert_eq!(last_lines_of(b"", 3).lines, 0);
    assert_eq!(last_lines_of(b"\n", 3).bytes, b"\n");
    assert_eq!(last_lines_of(b"\n", 3).lines, 1);
    assert_eq!(last_lines_of(b"a\n\nb\n", 2).bytes, b"\nb\n");
    assert_eq!(last_lines_of(b"a\nb\nc", 2).bytes, b"b\nc");
    assert_eq!(first_lines(b"a\nb", 5).bytes, b"a\nb");
    assert_eq!(first_lines(b"a\nb", 5).lines, 2);
}

// FR-EVT-07: the phase 2 hook passes chunks through unchanged.
#[test]
fn no_redaction_passes_chunks_through() {
    assert_eq!(NoOutputRedaction.redact_chunk(b"\x00abc\xff").expose(), b"\x00abc\xff");
}
