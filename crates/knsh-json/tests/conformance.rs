//! Conformance and round-trip tests for the strict JSON profile (`specs/06-api/wire-format.md#strict-json-profile`,
//! NFR-SEC-06, `specs/07-testing/fuzzing.md` "JSON writer": everything emitted conforms, round trip).

// The whole file is test code: this lets clippy's `allow-*-in-tests` settings (clippy.toml) cover the helpers too.
#![cfg(test)]

use std::fs;
use std::path::{Path, PathBuf};

use knsh_json::{MAX_DEPTH, Number, Object, Value, parse, write};

const LIMIT: usize = 1 << 20;

fn samples(kind: &str) -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples").join(kind);
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir).unwrap().map(|entry| entry.unwrap().path()).collect();
    paths.sort();
    paths
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read(&path).unwrap(),
            )
        })
        .collect()
}

#[test]
fn parses_rfc8259_conformance_samples() {
    let accept = samples("accept");
    let reject = samples("reject");
    assert!(accept.len() >= 20 && reject.len() >= 40, "sample set went missing");

    for (name, bytes) in &accept {
        let value = parse(bytes, LIMIT).unwrap_or_else(|error| panic!("{name} rejected: {error}"));
        // Every accepted sample also round-trips through the writer.
        let text = write(&value).unwrap();
        assert_eq!(
            parse(text.as_bytes(), LIMIT).as_ref(),
            Ok(&value),
            "{name} did not round-trip"
        );
    }
    for (name, bytes) in &reject {
        let error = parse(bytes, LIMIT).expect_err(&format!("{name} was accepted"));
        assert!(error.is_parse_error(), "{name}: {error:?} is not a parse error");
    }
}

#[test]
fn escape_samples_hold_escapes_not_decoded_characters() {
    // Guards the sample files themselves: an editor or tool that decodes `\uXXXX` would silently turn a reject
    // sample into a different test.
    let backslash_u = *b"\\u";
    for name in [
        "accept/string_surrogate_pair.json",
        "reject/unpaired_high.json",
        "reject/duplicate_key_escaped.json",
    ] {
        let bytes = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples").join(name)).unwrap();
        assert!(
            bytes.windows(2).any(|pair| pair == backslash_u),
            "{name} lost its escape"
        );
    }
}

/// Tiny deterministic generator (xorshift64*), so the round trip covers many shapes without a test-only crate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn random_string(rng: &mut Rng) -> String {
    const PIECES: [&str; 12] = [
        "a", "\"", "\\", "/", "\n", "\u{0}", "\u{1f}", "\u{7f}", "é", "😀", "\u{2028}", " ",
    ];
    (0..rng.below(6))
        .map(|_| PIECES[usize::try_from(rng.below(12)).unwrap()])
        .collect()
}

fn random_value(rng: &mut Rng, depth: usize) -> Value {
    // Choices 6 and 7 nest; leave them out at the depth limit so every generated value is writable.
    let choices = if depth < MAX_DEPTH { 8 } else { 6 };
    match rng.below(choices) {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 0),
        2 => {
            let limit = 1_u64 << 53;
            let magnitude = i64::try_from(rng.below(limit + 1)).unwrap();
            Value::int(if rng.below(2) == 0 { magnitude } else { -magnitude }).unwrap()
        }
        3 => {
            let text = format!(
                "{}{}.{}e{}",
                if rng.below(2) == 0 { "-" } else { "" },
                rng.below(1000),
                rng.next(),
                rng.below(500)
            );
            Value::from(Number::decimal(&text).unwrap())
        }
        4 => Value::String(random_string(rng)),
        5 => Value::int_string(i128::from(rng.next()) * if rng.below(2) == 0 { 1 } else { -1 }),
        6 => Value::Array((0..rng.below(4)).map(|_| random_value(rng, depth + 1)).collect()),
        _ => {
            let mut object = Object::new();
            for i in 0..rng.below(4) {
                // Suffix keeps keys unique; the duplicate rule is tested separately.
                let _ = object.insert(format!("{}{i}", random_string(rng)), random_value(rng, depth + 1));
            }
            Value::Object(object)
        }
    }
}

#[test]
fn round_trip_holds_for_generated_values() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..2000 {
        let value = random_value(&mut rng, 0);
        let text = write(&value).unwrap();
        assert_eq!(parse(text.as_bytes(), LIMIT), Ok(value), "{text}");
    }
}
