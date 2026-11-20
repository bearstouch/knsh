//! The redaction engine (KNSH-090, FR-SEC-10).

use super::forms::{Alphabet, base64, hex};
use super::*;

fn redactor(secrets: &[(&str, &[u8])]) -> Redactor {
    Redactor::new(
        secrets
            .iter()
            .map(|(name, value)| (SecretName::new(name).unwrap(), Redacted::new(*value))),
    )
    .unwrap()
}

fn run(redactor: &Redactor, chunks: &[&[u8]]) -> Vec<u8> {
    let mut stream = redactor.stream();
    let mut out = Vec::new();
    for chunk in chunks {
        out.extend_from_slice(stream.push(chunk).expose());
        assert!(stream.held_back() <= redactor.max_held_back());
    }
    out.extend_from_slice(stream.finish().expose());
    out
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn whole(redactor: &Redactor, input: &str) -> String {
    text(redactor.redact(input.as_bytes()).expose())
}

const TOKEN: &[u8] = b"npm_s3cr3t+/?&= value";

fn token() -> Redactor {
    redactor(&[("npm-token", TOKEN)])
}

/// Every form FR-SEC-10 names, as literal text.
fn forms(value: &[u8]) -> Vec<Vec<u8>> {
    vec![
        value.to_vec(),
        base64(value, Alphabet::Standard, true),
        base64(value, Alphabet::Standard, false),
        base64(value, Alphabet::UrlSafe, true),
        base64(value, Alphabet::UrlSafe, false),
        hex(value, false),
        hex(value, true),
        percent_all(value, false),
        percent_reserved(value),
    ]
}

/// Every byte as `%HH`.
fn percent_all(value: &[u8], lower: bool) -> Vec<u8> {
    let encoded: String = value.iter().map(|b| format!("%{b:02X}")).collect::<Vec<_>>().concat();
    if lower {
        encoded.to_lowercase().into_bytes()
    } else {
        encoded.into_bytes()
    }
}

/// RFC 3986 style: unreserved bytes kept, the rest `%HH`.
fn percent_reserved(value: &[u8]) -> Vec<u8> {
    value
        .iter()
        .flat_map(|&b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                vec![b]
            } else {
                format!("%{b:02X}").into_bytes()
            }
        })
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// FR-SEC-10
#[test]
fn redacts_exact_value() {
    let r = token();
    let input = format!("token={} done\n", std::str::from_utf8(TOKEN).unwrap());
    assert_eq!(whole(&r, &input), "token=«redacted:npm-token» done\n");
    assert_eq!(whole(&r, "nothing secret here\n"), "nothing secret here\n");
}

// FR-SEC-10
#[test]
fn redacts_base64_and_url_safe_forms() {
    let r = token();
    for (alphabet, pad) in [
        (Alphabet::Standard, true),
        (Alphabet::Standard, false),
        (Alphabet::UrlSafe, true),
        (Alphabet::UrlSafe, false),
    ] {
        let form = text(&base64(TOKEN, alphabet, pad));
        // Ends with a newline: a trailing `b` would begin the base64 form and be redacted at the end.
        assert_eq!(
            whole(&r, &format!("a {form} b\n")),
            "a «redacted:npm-token» b\n",
            "{form}"
        );
    }
    // Padded wins over the unpadded prefix: no `=` is left behind.
    let padded = text(&base64(b"ab", Alphabet::Standard, true));
    assert_eq!(padded, "YWI=");
    assert_eq!(whole(&redactor(&[("k", b"ab")]), "x YWI= y"), "x «redacted:k» y");
    // Standard base64 inside a URL, its `+`, `/` and `=` escaped.
    let escaped = text(&base64(TOKEN, Alphabet::Standard, true))
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");
    assert_eq!(whole(&r, &format!("?t={escaped}&")), "?t=«redacted:npm-token»&");
}

// FR-SEC-10
#[test]
fn redacts_url_encoded_form() {
    let r = token();
    let reserved = text(&percent_reserved(TOKEN));
    assert_eq!(reserved, "npm_s3cr3t%2B%2F%3F%26%3D%20value");
    for encoded in [
        reserved.clone(),
        reserved.to_lowercase(),
        text(&percent_all(TOKEN, false)),
        text(&percent_all(TOKEN, true)),
        // Form encoding: space as `+` (and the value's own `+` escaped).
        "npm_s3cr3t%2B%2F%3F%26%3D+value".to_owned(),
        // Escapes mixed with literal bytes, as a hand-written URL may have them.
        "npm_s3cr3t+/%3F&=%20value".to_owned(),
    ] {
        assert_eq!(
            whole(&r, &format!("https://h/?q={encoded}#f")),
            "https://h/?q=«redacted:npm-token»#f",
            "{encoded}"
        );
    }
}

// FR-SEC-10
#[test]
fn escape_digits_read_as_text_still_match() {
    // `%b3` decodes to one byte, but a reader may also see `3a%3Db`: the URL-encoded `3a=b`.
    let r = redactor(&[("k", b"3a=b")]);
    assert_eq!(whole(&r, "x%b3a%3Db\n"), "x%b«redacted:k»\n");
    assert_eq!(whole(&r, "x%b3a%3Db"), "x%b«redacted:k»");
    let input = b"x%b3a%3Db\n";
    for split in 0..=input.len() {
        assert_eq!(text(&run(&r, &[&input[..split], &input[split..]])), "x%b«redacted:k»\n");
    }
    // Both digits of the escape begin the match.
    let r = redactor(&[("k", b"b3a/")]);
    assert_eq!(whole(&r, "%b3a%2F."), "%«redacted:k».");
}

// FR-SEC-10
#[test]
fn redacts_hex_upper_and_lower() {
    let r = token();
    for upper in [false, true] {
        let form = text(&hex(TOKEN, upper));
        assert_eq!(whole(&r, &format!("{form}\n")), "«redacted:npm-token»\n");
    }
    // A `%` just before a hex form does not hide it by eating its first two digits.
    let form = text(&hex(TOKEN, false));
    assert_eq!(whole(&r, &format!("%{form}")), "%«redacted:npm-token»");
}

// FR-SEC-10
#[test]
fn redacts_value_split_across_chunks() {
    let r = token();
    for form in forms(TOKEN) {
        let mut input = b"before ".to_vec();
        input.extend_from_slice(&form);
        input.extend_from_slice(b" after");
        let expected = b"before \xc2\xabredacted:npm-token\xc2\xbb after".to_vec();
        // Two chunks, split at every point.
        for split in 0..=input.len() {
            let (a, b) = input.split_at(split);
            assert_eq!(run(&r, &[a, b]), expected, "{} split at {split}", text(&form));
        }
        // Three chunks and one byte at a time.
        let third = input.len() / 3;
        assert_eq!(
            run(&r, &[&input[..third], &input[third..2 * third], &input[2 * third..]]),
            expected
        );
        let bytes: Vec<&[u8]> = input.chunks(1).collect();
        assert_eq!(run(&r, &bytes), expected);
    }
}

#[test]
fn stream_end_mid_match_emits_no_partial_secret() {
    let r = token();
    for form in forms(TOKEN) {
        for cut in 1..form.len() {
            if &form[..cut] == b"%" {
                // A bare `%` gives nothing away (checked below).
                continue;
            }
            let mut input = b"output: ".to_vec();
            input.extend_from_slice(&form[..cut]);
            let out = run(&r, &[&input]);
            assert_eq!(
                text(&out),
                "output: «redacted:npm-token»",
                "{} cut at {cut}",
                text(&form)
            );
            // The same cut reached through many chunks.
            let bytes: Vec<&[u8]> = input.chunks(3).collect();
            assert_eq!(run(&r, &bytes), out);
        }
    }
    // A `%` and one hex digit that could begin an escaped first byte (`n` is 0x6E).
    assert_eq!(whole(&r, "x %6"), "x «redacted:npm-token»");
    // A bare `%`, or one whose digit begins no secret byte, gives nothing away and is kept.
    assert_eq!(whole(&r, "100%"), "100%");
    assert_eq!(whole(&r, "x %0"), "x %0");
}

#[test]
fn overlapping_secrets_are_both_redacted_and_longest_wins() {
    let r = redactor(&[("short", b"1234xyz"), ("long", b"abcd1234")]);
    // Overlap: one span covering both, named after the longer match.
    assert_eq!(whole(&r, "<abcd1234xyz>"), "<«redacted:long»>");
    // Containment.
    let r = redactor(&[("inner", b"token"), ("outer", b"my-token-value")]);
    assert_eq!(
        whole(&r, "[my-token-value] [token]"),
        "[«redacted:outer»] [«redacted:inner»]"
    );
    // Equal lengths: the earlier match names the span.
    let r = redactor(&[("b", b"cdef"), ("a", b"abcd")]);
    assert_eq!(whole(&r, "abcdef"), "«redacted:a»");
    // Same, whatever the chunking.
    let input = b"--abcdef--abcd--cdef";
    let expected = run(&r, &[input]);
    for split in 0..=input.len() {
        assert_eq!(run(&r, &[&input[..split], &input[split..]]), expected);
    }
    // Adjacent matches are separate spans.
    assert_eq!(whole(&r, "abcdcdef"), "«redacted:a»«redacted:b»");
}

#[test]
fn held_back_bytes_are_bounded_by_the_longest_form() {
    let value = b"k3y!";
    let r = redactor(&[("k", value)]);
    // Longest decoded pattern: padded standard base64 (8), up to 24 raw bytes when every byte is `%HH`.
    assert_eq!(r.max_held_back(), 3 * 8 - 1);
    let mut stream = r.stream();
    // Text that is no prefix of anything is emitted at once.
    assert_eq!(stream.push(b"hello world ").expose(), b"hello world ");
    assert_eq!(stream.held_back(), 0);
    // A prefix is held, and released as soon as it cannot match any more.
    assert_eq!(stream.push(b"k3").expose(), b"");
    assert_eq!(stream.held_back(), 2);
    assert_eq!(stream.push(b"x").expose(), b"k3x");
    assert_eq!(stream.held_back(), 0);
    // A long run of near-misses never piles up.
    for _ in 0..10_000 {
        let _ = stream.push(b"k3yk3%6B%33");
        assert!(stream.held_back() <= r.max_held_back());
    }
}

#[test]
fn empty_redactor_passes_everything_through() {
    let r = Redactor::default();
    assert!(r.is_empty());
    assert_eq!(r.max_held_back(), 0);
    let mut stream = r.stream();
    assert_eq!(stream.push(b"abc%").expose(), b"abc%");
    assert_eq!(stream.finish().expose(), b"");
}

#[test]
fn refuses_empty_and_oversized_values() {
    let name = || SecretName::new("s").unwrap();
    assert_eq!(
        Redactor::new([(name(), Redacted::new(&b""[..]))]).unwrap_err(),
        CoreError::EmptySecretValue
    );
    let big = vec![b'x'; MAX_SECRET_VALUE_LEN + 1];
    assert_eq!(
        Redactor::new([(name(), Redacted::new(&big[..]))]).unwrap_err(),
        CoreError::RedactionTooLarge
    );
    let max = vec![b'x'; MAX_SECRET_VALUE_LEN];
    let many = (0..=MAX_REDACTION_BYTES / MAX_SECRET_VALUE_LEN).map(|_| (name(), Redacted::new(&max[..])));
    assert_eq!(Redactor::new(many).unwrap_err(), CoreError::RedactionTooLarge);
    let exactly = (0..MAX_REDACTION_BYTES / MAX_SECRET_VALUE_LEN).map(|_| (name(), Redacted::new(&max[..])));
    assert!(Redactor::new(exactly).is_ok());
}

#[test]
fn debug_names_secrets_but_never_values() {
    let r = token();
    let mut stream = r.stream();
    let _ = stream.push(b"npm_s3");
    for printed in [format!("{r:?}"), format!("{stream:?}")] {
        assert!(!printed.contains("s3cr3t") && !printed.contains("npm_s3"), "{printed}");
    }
    assert!(format!("{r:?}").contains("npm-token"));
    assert_eq!(r.secrets(), [SecretName::new("npm-token").unwrap()]);
}

#[test]
fn same_value_under_two_names_is_reported_under_the_first() {
    let r = redactor(&[("first", b"same-value"), ("second", b"same-value")]);
    assert_eq!(whole(&r, "same-value"), "«redacted:first»");
}

#[test]
fn redact_text_keeps_text_valid() {
    let r = redactor(&[("k", "é-key".as_bytes()), ("raw", &[0xa9, b'x'])]);
    assert_eq!(text_of(&r, "café-key!"), "caf«redacted:k»!");
    // A value cutting a character in half: the orphaned byte becomes U+FFFD, never a broken string.
    assert_eq!(text_of(&r, "©x"), "\u{fffd}«redacted:raw»");
}

fn text_of(r: &Redactor, input: &str) -> String {
    r.redact_text(input).into_inner()
}

/// Tiny deterministic generator (xorshift64*), so the property test needs no test-only crate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn bytes(&mut self, alphabet: &[u8], len: usize) -> Vec<u8> {
        (0..len).map(|_| alphabet[self.below(alphabet.len())]).collect()
    }
}

/// Output with each known marker replaced by a NUL, which no generated secret holds, so plain text on either side
/// of a marker cannot join into a secret by accident.
fn without_markers(out: &[u8], names: &[&str]) -> Vec<u8> {
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

/// One pass of `%HH` decoding, as a reader of the output would do.
fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let digit = |b: u8| char::from(b).to_digit(16);
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(&h), Some(&l)) = (bytes.get(i + 1), bytes.get(i + 2))
            && let (Some(h), Some(l)) = (digit(h), digit(l))
        {
            out.push(u8::try_from(h << 4 | l).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// Property (story note): for random chunkings of a stream holding secrets in every form, the output never holds a
/// secret form, is the same however the stream was chunked, and never holds back more than the bound.
#[test]
fn random_chunkings_never_leak_a_secret() {
    const NAMES: [&str; 3] = ["s0", "s1", "s2"];
    // Few distinct bytes, so secrets share prefixes and overlap; no `%` and no NUL (see `without_markers`).
    const ALPHABET: &[u8] = b"ab /+=3";
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..400 {
        let values: Vec<Vec<u8>> = NAMES
            .iter()
            .map(|_| {
                let len = 1 + rng.below(6);
                rng.bytes(ALPHABET, len)
            })
            .collect();
        let r = Redactor::new(
            NAMES
                .iter()
                .zip(&values)
                .map(|(name, value)| (SecretName::new(name).unwrap(), Redacted::new(&value[..]))),
        )
        .unwrap();
        let mut input = Vec::new();
        for _ in 0..12 {
            if rng.below(2) == 0 {
                let value = &values[rng.below(values.len())];
                let all = forms(value);
                input.extend_from_slice(&all[rng.below(all.len())]);
            } else {
                let len = rng.below(5);
                input.extend(rng.bytes(b"ab %3dDx\n", len));
            }
        }
        let expected = run(&r, &[&input]);
        for _ in 0..8 {
            let mut chunks = Vec::new();
            let mut at = 0;
            while at < input.len() {
                let len = 1 + rng.below(input.len() - at);
                chunks.push(&input[at..at + len]);
                at += len;
            }
            assert_eq!(run(&r, &chunks), expected, "chunking changed the output");
        }
        let plain = without_markers(&expected, &NAMES);
        let decoded = percent_decode(&plain);
        for value in &values {
            for form in forms(value) {
                assert!(
                    !contains(&plain, &form),
                    "leaked {:?} in {:?}",
                    text(&form),
                    text(&expected)
                );
            }
            assert!(
                !contains(&decoded, value),
                "leaked {value:?} percent-encoded in {:?}",
                text(&expected)
            );
        }
    }
}

/// Throughput (story acceptance criterion; result in `specs/07-testing/performance-validation.md`). Ignored: run
/// with `cargo test -p knsh-core --release --lib -- --ignored --nocapture redaction_throughput`.
#[test]
#[ignore = "measurement, run on demand in release"]
fn redaction_throughput() {
    let secrets: Vec<(String, Vec<u8>)> = (0..16)
        .map(|i| {
            (
                format!("secret-{i}"),
                format!("ghp_{i:02}Zx9Lm4Qa8Wt2Re7Yu1Io3Pk6Sd5Fg0Hj").into_bytes(),
            )
        })
        .collect();
    let r = Redactor::new(
        secrets
            .iter()
            .map(|(name, value)| (SecretName::new(name).unwrap(), Redacted::new(&value[..]))),
    )
    .unwrap();
    // Build-log-like text with a secret every 64 KiB, in 64 KiB chunks (a pipe read).
    let line = b"   Compiling some-crate v1.2.3 (/Users/dev/project/crates/some-crate) 100% done\n";
    let mut chunk = Vec::new();
    while chunk.len() < 64 * 1024 {
        chunk.extend_from_slice(line);
    }
    chunk.extend_from_slice(&secrets[3].1);
    let total = 256 * chunk.len();
    for (label, data) in [
        ("build log", chunk.clone()),
        ("random bytes", random_bytes(chunk.len())),
    ] {
        let start = std::time::Instant::now();
        let mut stream = r.stream();
        let mut out = 0;
        for _ in 0..256 {
            out += stream.push(&data).expose().len();
        }
        out += stream.finish().expose().len();
        let seconds = start.elapsed().as_secs_f64();
        #[allow(clippy::cast_precision_loss)]
        let mib = total as f64 / (1024.0 * 1024.0);
        println!(
            "{label}: {mib:.0} MiB in {seconds:.3} s = {:.0} MiB/s ({out} bytes out)",
            mib / seconds
        );
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = Rng(42);
    (0..len).map(|_| rng.next().to_le_bytes()[0]).collect()
}
