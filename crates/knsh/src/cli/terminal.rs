//! Terminal-safe output for text that came from recorded commands (KNSH-023).
//!
//! Records and events carry text the engine did not author: the command lines people and agents typed, their working
//! directories, and anything else a recorded process put there. Printed raw, such text could hold escape sequences
//! that move the cursor, rewrite earlier lines, change the window title, set the clipboard (OSC 52) or reorder what
//! the reader sees (bidirectional overrides). Everything `knsh history` and `knsh events` print from the engine goes
//! through this module first:
//!
//! - [`escape_text`] for the human form: every control character becomes a visible escape, so one record stays one
//!   line and nothing reaches the terminal as a control;
//! - [`write_json_line`] for `--json`: strict JSON in which every character a terminal could act on is a `\u` escape,
//!   so the line is both valid JSON and safe to show.

use std::fmt::Write as _;

use knsh_json::{JsonError, Value};

/// Whether `c` must never reach a terminal as itself.
///
/// The C0 controls, DEL and the C1 controls (`char::is_control`, Unicode category Cc) include ESC and the 8-bit CSI
/// and OSC introducers that start terminal sequences. The bidirectional embedding, override and isolate controls
/// (U+202A to U+202E, U+2066 to U+2069) and the marks U+200E, U+200F and U+061C display nothing but can make a line
/// read differently from its bytes, so they are shown too.
fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// `text` with every unsafe character replaced by a visible escape: `\n`, `\t`, `\r`, `\e` for the common ones,
/// `\xHH` for other C0 controls and DEL, `\u{H…}` for the rest. A backslash is doubled, so the escaped form is
/// unambiguous: `\n` in the output always means a line feed in the command, `\\n` a backslash and an `n`.
#[must_use]
pub fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\u{1b}' => out.push_str("\\e"),
            // Writing to a String cannot fail.
            '\0'..='\u{1f}' | '\u{7f}' => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c if is_unsafe(c) => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// `value` as one line of compact JSON, followed by a line feed, in which every unsafe character is escaped.
///
/// `knsh_json::write` already escapes U+0000 to U+001F, as JSON requires; DEL, the C1 controls and the bidirectional
/// controls are valid raw in a JSON string but not safe on a terminal, so they are written as `\uXXXX` here. The
/// result parses back to the same value. Every unsafe character is outside ASCII's printable range, so it can only
/// occur inside a string, where a `\u` escape is always valid.
///
/// # Errors
///
/// [`JsonError::TooDeep`] if `value` nests deeper than the strict profile allows.
pub fn write_json_line(value: &Value) -> Result<String, JsonError> {
    let compact = knsh_json::write(value)?;
    let mut out = String::with_capacity(compact.len() + 1);
    for c in compact.chars() {
        if is_unsafe(c) {
            // Every unsafe character left after the writer is in the Basic Multilingual Plane: one `\u` escape.
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use knsh_json::Object;

    use super::*;

    #[test]
    fn escape_text_makes_controls_visible() {
        assert_eq!(escape_text("ls -la"), "ls -la");
        assert_eq!(escape_text("a\nb\tc\rd"), "a\\nb\\tc\\rd");
        assert_eq!(escape_text("\u{1b}[2J\u{7}"), "\\e[2J\\x07");
        assert_eq!(escape_text("x\u{7f}\u{9b}31m"), "x\\x7f\\u{9b}31m");
        assert_eq!(escape_text("abc\u{202e}fed"), "abc\\u{202e}fed");
        assert_eq!(escape_text(r"a\nb"), r"a\\nb", "a literal backslash is doubled");
        assert_eq!(escape_text("é 😀"), "é 😀", "printable Unicode is kept");
    }

    #[test]
    fn json_lines_escape_every_unsafe_character_and_round_trip() {
        let text = "\u{1b}]52;c;AAAA\u{7}\u{7f}\u{9b}\u{2066}x\n";
        let value = Value::from(Object::new().with("command", text).unwrap());
        let line = write_json_line(&value).unwrap();
        assert!(line.ends_with('\n'));
        let body = line.trim_end_matches('\n');
        assert!(!body.contains('\n'), "one value per line");
        assert!(body.chars().all(|c| !is_unsafe(c)), "{body:?}");
        assert!(
            body.contains(r"\u007f") && body.contains(r"\u009b") && body.contains(r"\u2066"),
            "{body}"
        );
        assert_eq!(knsh_json::parse(body.as_bytes(), 1 << 16).unwrap(), value);
    }
}
