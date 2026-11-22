//! Turning the bytes a terminal sends into keys (KNSH-107): UTF-8 characters, control characters, `ESC` followed
//! by a character (Meta), and the `CSI` and `SS3` sequences of cursor and editing keys that xterm-compatible
//! terminals send (macOS Terminal, iTerm2). Readline reads its key sequences from `terminfo` and `.inputrc`; this
//! decoder knows the common sequences directly (`.inputrc` is out of scope).
//!
//! A lone `ESC` is ambiguous until the next byte arrives: the caller waits a short time ([`ESCAPE_TIMEOUT`]) and
//! then calls [`KeyDecoder::timeout`], as readline's `keyseq-timeout`.

use std::time::Duration;

/// How long a lone `ESC` waits for the rest of a sequence before it is the Escape key (readline's default
/// `keyseq-timeout` is 500 ms; terminals send a sequence's bytes together, so less is enough and vi mode feels
/// quicker).
pub const ESCAPE_TIMEOUT: Duration = Duration::from_millis(100);

/// Longest escape sequence kept: anything longer is not a key this decoder knows and is dropped.
const MAX_SEQUENCE: usize = 16;

/// One key the user pressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// A printable character.
    Char(char),
    /// A control character, by its letter: `Control(b'A')` is Ctrl-A (byte 1). Also `@`, `[`, `\`, `]`, `^`
    /// and `_` for bytes 0 and 27 to 31. Tab, Enter and Backspace have keys of their own.
    Control(u8),
    /// `ESC` followed by a character (Meta-x, Alt-x with "Option as Meta").
    Meta(char),
    /// Return (carriage return or newline).
    Enter,
    /// Tab.
    Tab,
    /// The Backspace key (`DEL`, 127).
    Backspace,
    /// Meta-Backspace (`ESC DEL` or `ESC Ctrl-H`).
    MetaBackspace,
    /// The forward Delete key.
    Delete,
    /// Escape on its own.
    Escape,
    /// Cursor up.
    Up,
    /// Cursor down.
    Down,
    /// Cursor left.
    Left,
    /// Cursor right.
    Right,
    /// A word left (Ctrl-Left or Alt-Left).
    WordLeft,
    /// A word right (Ctrl-Right or Alt-Right).
    WordRight,
    /// Home.
    Home,
    /// End.
    End,
    /// A sequence the decoder does not know.
    Unknown,
}

/// Where the decoder is within a key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum State {
    /// Between keys.
    #[default]
    Ground,
    /// After `ESC`.
    Escape,
    /// After `ESC [` (or `ESC O`, `ss3`), collecting parameter bytes.
    Sequence {
        /// `true` after `ESC O`.
        ss3: bool,
        /// Parameter and intermediate bytes so far.
        params: Vec<u8>,
    },
    /// Inside a sequence too long to be a key this decoder knows: its bytes are dropped up to its final byte.
    Discard,
    /// Inside a UTF-8 character: the bytes so far and how many in all, with `meta` when `ESC` came before it.
    Utf8 {
        /// The bytes so far.
        bytes: Vec<u8>,
        /// Its length.
        len: usize,
        /// It follows `ESC`.
        meta: bool,
    },
}

/// A streaming decoder of terminal input into [`Key`]s.
#[derive(Debug, Clone, Default)]
pub struct KeyDecoder {
    state: State,
}

/// The length of a UTF-8 sequence starting with `byte`, or `None` for a byte that cannot start one.
fn utf8_len(byte: u8) -> Option<usize> {
    match byte {
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

/// The key of a single byte below 128 that is not `ESC`.
fn ascii_key(byte: u8) -> Key {
    match byte {
        b'\r' | b'\n' => Key::Enter,
        b'\t' => Key::Tab,
        0x7F => Key::Backspace,
        0 => Key::Control(b'@'),
        1..=26 => Key::Control(b'A' + byte - 1),
        28..=31 => Key::Control(b'\\' + byte - 28),
        _ => Key::Char(char::from(byte)),
    }
}

/// The key a complete `CSI` (`ss3: false`) or `SS3` sequence names, from its parameters and final byte.
fn sequence_key(ss3: bool, params: &[u8], last: u8) -> Key {
    let text = String::from_utf8_lossy(params);
    let mut numbers = text.split(';').map(|part| part.parse::<u32>().unwrap_or(0));
    let first = numbers.next().unwrap_or(0);
    let modifier = numbers.next().unwrap_or(1);
    // xterm's modifiers: 3 is Alt, 5 is Ctrl.
    let word = matches!(modifier, 3 | 5 | 9);
    match (last, ss3) {
        (b'A', _) => Key::Up,
        (b'B', _) => Key::Down,
        (b'C', _) if word => Key::WordRight,
        (b'D', _) if word => Key::WordLeft,
        (b'C', _) => Key::Right,
        (b'D', _) => Key::Left,
        (b'H', _) => Key::Home,
        (b'F', _) => Key::End,
        (b'~', false) => match first {
            1 | 7 => Key::Home,
            4 | 8 => Key::End,
            3 => Key::Delete,
            _ => Key::Unknown,
        },
        _ => Key::Unknown,
    }
}

impl KeyDecoder {
    /// A decoder between keys.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a lone `ESC` (or the start of a sequence) waits for more bytes: the caller then waits at most
    /// [`ESCAPE_TIMEOUT`] before [`KeyDecoder::timeout`].
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self.state, State::Escape | State::Sequence { .. } | State::Discard)
    }

    /// The key that ends with `byte`, if one does.
    pub fn feed(&mut self, byte: u8) -> Option<Key> {
        match std::mem::take(&mut self.state) {
            State::Ground => self.ground(byte, false),
            State::Escape => match byte {
                b'[' => {
                    self.state = State::Sequence {
                        ss3: false,
                        params: Vec::new(),
                    };
                    None
                }
                b'O' => {
                    self.state = State::Sequence {
                        ss3: true,
                        params: Vec::new(),
                    };
                    None
                }
                0x7F | 0x08 => Some(Key::MetaBackspace),
                0x1B => {
                    // `ESC ESC`: the first is Escape on its own; the second starts again.
                    self.state = State::Escape;
                    Some(Key::Escape)
                }
                _ => self.ground(byte, true),
            },
            State::Sequence { ss3, mut params } => {
                if (0x40..=0x7E).contains(&byte) && !(ss3 && params.is_empty() && byte == b'[') {
                    Some(sequence_key(ss3, &params, byte))
                } else if !(0x20..=0x3F).contains(&byte) {
                    // Not a sequence this decoder knows: dropped.
                    Some(Key::Unknown)
                } else if params.len() >= MAX_SEQUENCE {
                    self.state = State::Discard;
                    None
                } else {
                    params.push(byte);
                    self.state = State::Sequence { ss3, params };
                    None
                }
            }
            State::Discard => {
                if (0x40..=0x7E).contains(&byte) || !(0x20..=0x3F).contains(&byte) {
                    Some(Key::Unknown)
                } else {
                    self.state = State::Discard;
                    None
                }
            }
            State::Utf8 { mut bytes, len, meta } => {
                if byte & 0xC0 != 0x80 {
                    // A broken character is dropped; the byte starts a key of its own.
                    return self.ground(byte, false);
                }
                bytes.push(byte);
                if bytes.len() < len {
                    self.state = State::Utf8 { bytes, len, meta };
                    return None;
                }
                let ch = std::str::from_utf8(&bytes).ok().and_then(|text| text.chars().next());
                match ch {
                    Some(ch) if meta => Some(Key::Meta(ch)),
                    Some(ch) => Some(Key::Char(ch)),
                    None => Some(Key::Unknown),
                }
            }
        }
    }

    /// No more bytes came after a pending `ESC`: it is the Escape key. A sequence cut short is dropped.
    pub fn timeout(&mut self) -> Option<Key> {
        match std::mem::take(&mut self.state) {
            State::Escape => Some(Key::Escape),
            State::Sequence { .. } | State::Discard => Some(Key::Unknown),
            other => {
                self.state = other;
                None
            }
        }
    }

    /// `byte` between keys (`meta` after `ESC`).
    fn ground(&mut self, byte: u8, meta: bool) -> Option<Key> {
        if byte == 0x1B {
            self.state = State::Escape;
            return None;
        }
        if byte < 0x80 {
            let key = ascii_key(byte);
            return Some(match (meta, key) {
                (true, Key::Char(ch)) => Key::Meta(ch),
                (true, Key::Control(_)) => Key::Unknown,
                (true, Key::Enter) => Key::Meta('\r'),
                (true, Key::Tab) => Key::Meta('\t'),
                (_, key) => key,
            });
        }
        match utf8_len(byte) {
            Some(len) => {
                self.state = State::Utf8 {
                    bytes: vec![byte],
                    len,
                    meta,
                };
                None
            }
            None => Some(Key::Unknown),
        }
    }
}

/// Every key in `bytes`, for tests and pasted text: a trailing lone `ESC` is the Escape key.
#[must_use]
pub fn decode_all(bytes: &[u8]) -> Vec<Key> {
    let mut decoder = KeyDecoder::new();
    let mut keys: Vec<Key> = bytes.iter().filter_map(|&byte| decoder.feed(byte)).collect();
    keys.extend(decoder.timeout());
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-107: control characters, UTF-8, Meta and the cursor keys' sequences.
    #[test]
    fn bytes_become_keys() {
        assert_eq!(
            decode_all(b"a\x01\x7f\r\t"),
            [Key::Char('a'), Key::Control(b'A'), Key::Backspace, Key::Enter, Key::Tab]
        );
        assert_eq!(decode_all("日é".as_bytes()), [Key::Char('日'), Key::Char('é')]);
        assert_eq!(decode_all(b"\x1bf\x1b\x7f"), [Key::Meta('f'), Key::MetaBackspace]);
        assert_eq!(
            decode_all(b"\x1b[A\x1b[B\x1bOC\x1b[D\x1b[3~\x1b[H\x1b[4~\x1b[1;5C\x1b[1;3D"),
            [
                Key::Up,
                Key::Down,
                Key::Right,
                Key::Left,
                Key::Delete,
                Key::Home,
                Key::End,
                Key::WordRight,
                Key::WordLeft
            ]
        );
        assert_eq!(decode_all(b"\x1b"), [Key::Escape]);
        assert_eq!(decode_all(b"\x1b\x1bx"), [Key::Escape, Key::Meta('x')]);
        assert_eq!(decode_all(b"\x1b[999999999999999999999z"), [Key::Unknown]);
        assert_eq!(decode_all(b"\xff\xe6\x97"), [Key::Unknown]);
    }

    #[test]
    fn lone_escape_waits_for_the_timeout() {
        let mut decoder = KeyDecoder::new();
        assert_eq!(decoder.feed(0x1b), None);
        assert!(decoder.is_pending());
        assert_eq!(decoder.timeout(), Some(Key::Escape));
        assert!(!decoder.is_pending());
        assert_eq!(decoder.timeout(), None);
    }
}
