//! The properties of the `redactor` fuzz target (KNSH-090, FR-SEC-10; `specs/07-testing/fuzzing.md`).
//!
//! Also compiled on stable by `crates/knsh-core/tests/fuzz_regressions.rs`, which includes it by path, so it depends
//! only on `knsh-core` and `std`. A failed property panics, which libFuzzer records as a crash.
//!
//! Input layout: one byte for the number of secrets (1 to 3), then per secret a length byte (1 to 8) and the value,
//! then one byte seeding the chunkings, then the stream. Inputs whose secrets hold a NUL are skipped: the check
//! replaces markers with NUL (see [`without_markers`]).

use knsh_core::{Redacted, Redactor, SecretName, redaction_marker};

/// `redactor`: never panics; the output is the same however the stream is chunked; no chunk leaves more than
/// [`Redactor::max_held_back`] bytes held back; and outside the markers the output holds no secret's exact value,
/// base64 (standard or URL-safe, padded or not) or hex (either case), nor, once percent-decoded, the value itself
/// (checked when no secret holds a `%`, since a marker can cut an escape in two).
pub fn redactor(data: &[u8]) {
    let Some((values, seed, stream)) = split(data) else {
        return;
    };
    let names: Vec<String> = (0..values.len()).map(|i| format!("s{i}")).collect();
    let redactor = Redactor::new(
        names
            .iter()
            .zip(&values)
            .map(|(name, value)| (SecretName::new(name).unwrap(), Redacted::new(*value))),
    )
    .unwrap();

    let expected = run(&redactor, &[stream]);
    let mut rng = seed | 1;
    for _ in 0..4 {
        let mut chunks = Vec::new();
        let mut at = 0;
        while at < stream.len() {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let len = 1 + usize::try_from(rng % 64).unwrap();
            let end = (at + len).min(stream.len());
            chunks.push(&stream[at..end]);
            at = end;
        }
        assert_eq!(run(&redactor, &chunks), expected, "chunking changed the output");
    }

    let plain = without_markers(&expected, &names);
    let check_decoded = values.iter().all(|value| !value.contains(&b'%'));
    let decoded = percent_decode(&plain);
    for value in &values {
        for form in forms(value) {
            assert!(!contains(&plain, &form), "a secret form survived redaction");
        }
        if check_decoded {
            assert!(
                !contains(&decoded, value),
                "a percent-encoded secret survived redaction"
            );
        }
    }
}

/// The secret values, the chunking seed and the stream of a fuzz input.
type Parts<'a> = (Vec<&'a [u8]>, u64, &'a [u8]);

fn split(data: &[u8]) -> Option<Parts<'_>> {
    let (&count, mut rest) = data.split_first()?;
    let mut values = Vec::new();
    for _ in 0..=count % 3 {
        let (&len, tail) = rest.split_first()?;
        let len = 1 + usize::from(len % 8);
        if tail.len() < len {
            return None;
        }
        let (value, tail) = tail.split_at(len);
        if value.contains(&0) {
            return None;
        }
        values.push(value);
        rest = tail;
    }
    let (&seed, stream) = rest.split_first()?;
    Some((values, u64::from(seed), stream))
}

fn run(redactor: &Redactor, chunks: &[&[u8]]) -> Vec<u8> {
    let mut stream = redactor.stream();
    let mut out = Vec::new();
    for chunk in chunks {
        out.extend_from_slice(stream.push(chunk).expose());
        assert!(
            stream.held_back() <= redactor.max_held_back(),
            "held back more than the bound"
        );
    }
    out.extend_from_slice(stream.finish().expose());
    out
}

/// Output with each marker replaced by a NUL, which no secret holds, so text on either side of a marker cannot join
/// into a secret form by accident.
fn without_markers(out: &[u8], names: &[String]) -> Vec<u8> {
    let mut text = out.to_vec();
    for name in names {
        let marker = redaction_marker(&SecretName::new(name).unwrap()).into_bytes();
        let mut i = 0;
        while i + marker.len() <= text.len() {
            if text[i..i + marker.len()] == marker[..] {
                text.splice(i..i + marker.len(), [0]);
            }
            i += 1;
        }
    }
    text
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// The literal forms of FR-SEC-10, written independently of the engine's encoders.
fn forms(value: &[u8]) -> Vec<Vec<u8>> {
    const STANDARD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut padded = Vec::new();
    for group in value.chunks(3) {
        let mut n = 0u32;
        for i in 0..3 {
            n = n << 8 | u32::from(group.get(i).copied().unwrap_or(0));
        }
        for i in 0..4 {
            padded.push(if i <= group.len() {
                STANDARD[(n >> (18 - 6 * i) & 63) as usize]
            } else {
                b'='
            });
        }
    }
    let unpadded: Vec<u8> = padded.iter().copied().filter(|&b| b != b'=').collect();
    let url = |form: &[u8]| -> Vec<u8> {
        form.iter()
            .map(|&b| match b {
                b'+' => b'-',
                b'/' => b'_',
                other => other,
            })
            .collect()
    };
    let lower: Vec<u8> = value.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect();
    vec![
        value.to_vec(),
        url(&padded),
        url(&unpadded),
        padded,
        unpadded,
        lower.to_ascii_uppercase(),
        lower,
    ]
}

/// One pass of `%HH` decoding, as a reader of the output would do.
fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let digit = |b: u8| char::from(b).to_digit(16);
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let escape = (bytes[i] == b'%')
            .then(|| Some((digit(*bytes.get(i + 1)?)?, digit(*bytes.get(i + 2)?)?)))
            .flatten();
        if let Some((high, low)) = escape {
            out.push(u8::try_from(high << 4 | low).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}
