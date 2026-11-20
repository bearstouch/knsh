//! The redaction engine: replaces secret values and their encodings with `«redacted:<name>»` in a stream of bytes
//! (KNSH-090, FR-SEC-10; `specs/03-functional-requirements/secrets.md#redaction`).
//!
//! # What is matched
//!
//! For each secret value: the exact bytes; base64 in the standard and URL-safe alphabets, with and without padding;
//! hex in lower and upper case; and any percent-encoding of the value (any subset of bytes written as `%HH` with
//! digits of either case, and `+` for a space). Base64 and hex are matched literally in the raw bytes. Percent
//! encodings are matched by decoding `%HH` as the bytes arrive and looking for the value (and for its standard base64
//! forms, whose `+`, `/` and `=` URLs escape) in the decoded bytes. Both views use a linear-time [`automaton`]. The one
//! extra cost is a side reading after each `%HH` escape whose digits may also be text: it lives only while it could
//! still begin a match, so ordinary output keeps a constant cost per byte. Output built from a secret's own text
//! (an agent that already knows the secret) can keep many alive, up to the longest decoded pattern.
//!
//! # Streaming
//!
//! [`RedactStream`] takes chunks cut wherever the pipe's reads happened to end. It holds back only the trailing bytes
//! that could still begin a match: those that are a prefix of some pattern (or a `%` or `%H` not yet decoded). That
//! is at most [`Redactor::max_held_back`] bytes, one less than three times the longest decoded pattern, which bounds
//! memory per stream whatever the command writes. Bytes no future match can reach are emitted at once.
//!
//! # Overlaps and the end of a stream
//!
//! Matches that overlap (two secrets, or two forms of one) are merged into one redacted span, so no byte of either
//! is emitted; the marker names the secret of the longest match among them (ties: the earlier match). When a stream
//! ends while its last bytes are a prefix of a pattern, those bytes are redacted too: a stream cut mid-secret never
//! emits part of it. The price is that a stream ending with a byte that begins some secret's form also ends with a
//! marker.
//!
//! # Limits (documented, `specs/03-functional-requirements/secrets.md`)
//!
//! Transformed values (a substring, another encoding, base64 of the value inside a longer base64 text) and files the
//! command writes are not redacted. Redaction is a convenience, not a control.

mod automaton;
mod forms;
#[cfg(test)]
mod tests;

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

use automaton::{Automaton, Builder};
use forms::{Alphabet, base64, hex, hex_digit, wipe};

use crate::{CoreError, MAX_SECRET_VALUE_LEN, Redacted, SecretName};

/// The most secret-value bytes one [`Redactor`] holds, summed over its secrets (256 KiB).
///
/// Each value byte becomes about fifteen automaton nodes (its forms in two views), so this bounds a redactor near
/// 110 MB in the worst case, and about 400 MB briefly while it is built; real tokens are tens to thousands of bytes
/// (`specs/09-reference/defaults-and-limits.md`).
pub const MAX_REDACTION_BYTES: usize = 256 * 1024;

/// The marker that replaces a secret named `name`: `«redacted:<name>»` (FR-SEC-10, `specs/05-models/secret.md`).
#[must_use]
pub fn redaction_marker(name: &SecretName) -> String {
    format!("«redacted:{name}»")
}

/// A fixed set of secrets to redact. Cheap to clone: clones share the automata, so every output path of a session
/// can hold the same instance and see the same secret set (KNSH-091).
///
/// # Invariants
///
/// - Holds 0 to [`MAX_REDACTION_BYTES`] bytes of secret values, each 1 to [`MAX_SECRET_VALUE_LEN`] bytes.
/// - `Debug` prints the secret names only, never a value or an encoding of one.
/// - The automata, which spell out every encoded form, are overwritten when the last clone is dropped (best effort:
///   safe Rust has no volatile write).
#[derive(Clone)]
pub struct Redactor {
    inner: Arc<Inner>,
}

struct Inner {
    names: Vec<SecretName>,
    /// `«redacted:<name>»` per secret, in the order of `names`.
    markers: Vec<Vec<u8>>,
    /// Exact value, base64 (four variants) and hex (two cases), in the raw bytes.
    raw: Automaton,
    /// Exact value, value with `+` for space and standard base64, in the percent-decoded bytes.
    decoded: Automaton,
    /// Longest pattern of `decoded`: how many decoded bytes' raw starts a stream must remember.
    longest_decoded: usize,
}

impl Redactor {
    /// Builds a redactor for `secrets`. Secrets are tried in the order given: a pattern shared by two secrets (the
    /// same value under two names) is reported under the first.
    ///
    /// # Errors
    ///
    /// - [`CoreError::EmptySecretValue`] if a value is empty: it would match everywhere.
    /// - [`CoreError::RedactionTooLarge`] if a value is over [`MAX_SECRET_VALUE_LEN`] bytes or the values together
    ///   are over [`MAX_REDACTION_BYTES`]. Nothing is built, so the caller decides what an unredactable secret
    ///   means; on an agent's path that is a refusal (fail closed).
    pub fn new<'a, I>(secrets: I) -> Result<Self, CoreError>
    where
        I: IntoIterator<Item = (SecretName, Redacted<&'a [u8]>)>,
    {
        let mut names = Vec::new();
        let mut total = 0usize;
        let mut raw = Builder::new();
        let mut decoded = Builder::new();
        for (name, value) in secrets {
            let value: &[u8] = value.expose();
            if value.is_empty() {
                return Err(CoreError::EmptySecretValue);
            }
            total = total.saturating_add(value.len());
            if value.len() > MAX_SECRET_VALUE_LEN || total > MAX_REDACTION_BYTES {
                return Err(CoreError::RedactionTooLarge);
            }
            // At most MAX_REDACTION_BYTES secrets, each at least one byte.
            let id = u32::try_from(names.len()).map_err(|_| CoreError::RedactionTooLarge)?;
            raw.insert(value, id);
            decoded.insert(value, id);
            for (alphabet, pad) in [
                (Alphabet::Standard, true),
                (Alphabet::Standard, false),
                (Alphabet::UrlSafe, true),
                (Alphabet::UrlSafe, false),
            ] {
                let form = base64(value, alphabet, pad);
                raw.insert(&form, id);
                if matches!(alphabet, Alphabet::Standard) {
                    decoded.insert(&form, id);
                }
                wipe(form);
            }
            for upper in [false, true] {
                let form = hex(value, upper);
                raw.insert(&form, id);
                wipe(form);
            }
            if value.contains(&b' ') {
                let form: Vec<u8> = value.iter().map(|&b| if b == b' ' { b'+' } else { b }).collect();
                decoded.insert(&form, id);
                wipe(form);
            }
            names.push(name);
        }
        let raw = raw.build();
        let decoded = decoded.build();
        let longest_decoded = decoded.longest() as usize;
        let markers = names.iter().map(|name| redaction_marker(name).into_bytes()).collect();
        Ok(Self {
            inner: Arc::new(Inner {
                names,
                markers,
                raw,
                decoded,
                longest_decoded,
            }),
        })
    }

    /// The secrets this redactor replaces, in the order given to [`new`](Self::new).
    #[must_use]
    pub fn secrets(&self) -> &[SecretName] {
        &self.inner.names
    }

    /// Whether `other` is a clone of this redactor (the same instance, not merely the same names): only then is a
    /// value known to be in one known to be in the other (KNSH-092 checks the line's redactor holds what it injects).
    #[must_use]
    pub fn is_same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Whether there is nothing to redact: every stream passes through unchanged.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.names.is_empty()
    }

    /// The most bytes a [`RedactStream`] ever holds back: one less than the longest raw pattern, or three times the
    /// longest decoded pattern less one (each decoded byte is at most three raw bytes, `%HH`), whichever is larger.
    #[must_use]
    pub fn max_held_back(&self) -> usize {
        let raw = (self.inner.raw.longest() as usize).saturating_sub(1);
        let decoded = (3 * self.inner.longest_decoded).saturating_sub(1);
        raw.max(decoded)
    }

    /// A new stream, for one output stream of one command.
    #[must_use]
    pub fn stream(&self) -> RedactStream {
        RedactStream {
            inner: Arc::clone(&self.inner),
            state: State::default(),
        }
    }

    /// `bytes` with every secret replaced: a whole stream at once, ending at the end of `bytes`.
    #[must_use]
    pub fn redact(&self, bytes: &[u8]) -> Redacted<Vec<u8>> {
        let mut stream = self.stream();
        let mut out = stream.push(bytes).into_inner();
        out.extend_from_slice(stream.finish().expose());
        Redacted::new(out)
    }

    /// `text` with every secret replaced. A secret value need not be UTF-8 nor align with characters; a character
    /// a match cut through becomes U+FFFD.
    #[must_use]
    pub fn redact_text(&self, text: &str) -> Redacted<String> {
        let bytes = self.redact(text.as_bytes()).into_inner();
        Redacted::new(match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
        })
    }
}

impl Default for Redactor {
    /// A redactor with no secrets: every stream passes through unchanged.
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                names: Vec::new(),
                markers: Vec::new(),
                raw: Builder::new().build(),
                decoded: Builder::new().build(),
                longest_decoded: 0,
            }),
        }
    }
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor").field("secrets", &self.inner.names).finish()
    }
}

/// One output stream being redacted. Feed it with [`push`](Self::push) and end it with [`finish`](Self::finish);
/// the concatenation of everything returned is the redacted stream, the same however the input was chunked.
///
/// # Invariants
///
/// - After every `push`, at most [`Redactor::max_held_back`] bytes are held back.
/// - No returned byte is part of a match, nor of a prefix of one that the stream ended on.
/// - The held-back bytes are overwritten as they are dropped and when the stream is dropped (best effort).
pub struct RedactStream {
    inner: Arc<Inner>,
    state: State,
}

impl RedactStream {
    /// Reads `chunk` and returns the bytes that are now final, already redacted.
    #[must_use]
    pub fn push(&mut self, chunk: &[u8]) -> Redacted<Vec<u8>> {
        let inner = &*self.inner;
        if inner.names.is_empty() {
            return Redacted::new(chunk.to_vec());
        }
        let decode = !inner.decoded.is_empty();
        for &byte in chunk {
            self.state.read(inner, byte, decode);
        }
        let mut out = Vec::with_capacity(chunk.len());
        let limit = self.state.frontier(inner);
        self.state.emit_until(inner, limit, &mut out);
        Redacted::new(out)
    }

    /// Ends the stream and returns the held-back bytes, redacted. Trailing bytes that begin a secret's form are
    /// replaced by its marker, so a stream cut mid-secret never emits part of it.
    #[must_use]
    pub fn finish(mut self) -> Redacted<Vec<u8>> {
        let inner = &*self.inner;
        let mut out = Vec::new();
        if inner.names.is_empty() {
            return Redacted::new(out);
        }
        if let Some((start, secret)) = self.state.tail(inner) {
            let end = self.state.pos;
            self.state.add(start, end, secret);
        }
        let end = self.state.pos;
        self.state.emit_until(inner, end, &mut out);
        Redacted::new(out)
    }

    /// How many bytes are held back now.
    #[must_use]
    pub fn held_back(&self) -> usize {
        self.state.pending.len()
    }
}

impl fmt::Debug for RedactStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactStream")
            .field("held_back", &self.held_back())
            .finish()
    }
}

impl Drop for RedactStream {
    fn drop(&mut self) {
        self.state.pending.iter_mut().for_each(|b| *b = 0);
        std::hint::black_box(&mut self.state.pending);
    }
}

/// A `%` read but not yet decoded.
#[derive(Clone, Copy, Default)]
enum Partial {
    #[default]
    None,
    /// `%` at raw offset `start`.
    Percent { start: u64 },
    /// `%` and one hex digit (`digit`, worth `nibble`).
    High { start: u64, digit: u8, nibble: u8 },
}

impl Partial {
    const fn start(self) -> Option<u64> {
        match self {
            Self::None => None,
            Self::Percent { start } | Self::High { start, .. } => Some(start),
        }
    }
}

/// The decoded view read with one escape's two hex digits taken as text.
#[derive(Clone, Copy)]
struct Side {
    state: u32,
    /// Raw offset of the first digit (the second follows it).
    digits_at: u64,
    /// Decoded bytes read after the escape.
    read: u32,
}

/// The match a redacted span is named after.
#[derive(Clone, Copy)]
struct Best {
    len: u64,
    start: u64,
    secret: u32,
}

impl Best {
    /// Longest wins; then the earlier; then the secret given first. Total, so merging is order-independent.
    fn beats(self, other: Self) -> bool {
        (self.len, std::cmp::Reverse(self.start), std::cmp::Reverse(self.secret))
            > (
                other.len,
                std::cmp::Reverse(other.start),
                std::cmp::Reverse(other.secret),
            )
    }
}

/// A span of raw offsets `[start, end)` to replace with one marker.
#[derive(Clone, Copy)]
struct Region {
    start: u64,
    end: u64,
    best: Best,
}

/// Everything a stream remembers. Offsets are absolute positions in the raw stream.
#[derive(Default)]
struct State {
    /// Raw bytes read so far.
    pos: u64,
    /// Offset of `pending[0]`: everything before it is decided (emitted or redacted).
    base: u64,
    pending: VecDeque<u8>,
    raw_node: u32,
    dec_node: u32,
    /// Raw start offsets of the last decoded bytes, at most the longest decoded pattern of them.
    dec_starts: VecDeque<u64>,
    partial: Partial,
    /// Readings where the digits of a recent escape are text (see `spawn_side`). Each lives while its live prefix
    /// still reaches back into its escape, so there are never more than the longest decoded pattern of them.
    sides: Vec<Side>,
    /// Sorted by `start` and disjoint. The first may begin before `base` when its head was already dropped.
    regions: VecDeque<Region>,
}

impl State {
    fn read(&mut self, inner: &Inner, byte: u8, decode: bool) {
        let at = self.pos;
        self.pending.push_back(byte);
        self.pos += 1;
        self.raw_node = inner.raw.step(self.raw_node, byte);
        if let Some(pattern) = inner.raw.output(self.raw_node) {
            self.add(self.pos - u64::from(pattern.len), self.pos, pattern.secret);
        }
        if decode {
            self.decode(inner, byte, at);
        }
    }

    /// Advances the percent decoder by raw byte `byte` at offset `at`.
    fn decode(&mut self, inner: &Inner, byte: u8, at: u64) {
        match self.partial {
            Partial::None => {
                if byte == b'%' {
                    self.partial = Partial::Percent { start: at };
                } else {
                    self.feed(inner, byte, at, at + 1);
                }
            }
            Partial::Percent { start } => {
                if let Some(nibble) = hex_digit(byte) {
                    self.partial = Partial::High {
                        start,
                        digit: byte,
                        nibble,
                    };
                } else {
                    // Not an escape: the `%` is a literal byte, and `byte` starts afresh (it may be another `%`).
                    self.partial = Partial::None;
                    self.feed(inner, b'%', start, start + 1);
                    self.decode(inner, byte, at);
                }
            }
            Partial::High { start, digit, nibble } => {
                self.partial = Partial::None;
                if let Some(low) = hex_digit(byte) {
                    self.feed(inner, nibble << 4 | low, start, at + 1);
                    self.spawn_side(inner, start, [digit, byte]);
                } else {
                    self.feed(inner, b'%', start, start + 1);
                    self.feed(inner, digit, start + 1, start + 2);
                    self.decode(inner, byte, at);
                }
            }
        }
    }

    /// Reads one decoded byte whose raw bytes are `[start, end)`.
    fn feed(&mut self, inner: &Inner, byte: u8, start: u64, end: u64) {
        self.dec_starts.push_back(start);
        if self.dec_starts.len() > inner.longest_decoded {
            self.dec_starts.pop_front();
        }
        self.dec_node = inner.decoded.step(self.dec_node, byte);
        if let Some(pattern) = inner.decoded.output(self.dec_node) {
            let start = self.decoded_start(pattern.len);
            self.add(start, end, pattern.secret);
        }
        let mut i = 0;
        while i < self.sides.len() {
            let mut side = self.sides[i];
            side.state = inner.decoded.step(side.state, byte);
            side.read += 1;
            if let Some(pattern) = inner.decoded.output(side.state) {
                let start = self.side_start(side, pattern.len);
                self.add(start, end, pattern.secret);
            }
            // Once its live prefix lies wholly after the escape, the main view sees the same text.
            if inner.decoded.live_prefix(side.state).0 > side.read {
                self.sides[i] = side;
                i += 1;
            } else {
                self.sides.swap_remove(i);
            }
        }
    }

    /// After the escape `%` `digits` at raw offset `start`: a reader may also take the two digits as text, so a
    /// match may begin at either of them and run on into the decoded bytes that follow (for a value without `%`,
    /// only the first escape of a match can be read that way). Tracked as a side state over that text.
    fn spawn_side(&mut self, inner: &Inner, start: u64, digits: [u8; 2]) {
        let state = inner
            .decoded
            .step(inner.decoded.step(automaton::ROOT, digits[0]), digits[1]);
        // A match inside the two digits alone is literal text, which the raw view already sees.
        if inner.decoded.live_prefix(state).0 > 0 {
            self.sides.push(Side {
                state,
                digits_at: start + 1,
                read: 0,
            });
        }
    }

    /// Raw offset where the last `len` bytes of `side`'s text begin.
    fn side_start(&self, side: Side, len: u32) -> u64 {
        if len <= side.read {
            self.decoded_start(len)
        } else {
            // `len - read` is 1 or 2: the match begins on one of the two digits.
            (side.digits_at + 2).saturating_sub(u64::from(len - side.read))
        }
    }

    /// Raw offset where the last `len` decoded bytes begin. The ring always holds them (it keeps the longest
    /// pattern's worth); if it ever did not, everything held back is taken, which over-redacts rather than leaks.
    fn decoded_start(&self, len: u32) -> u64 {
        self.dec_starts
            .len()
            .checked_sub(len as usize)
            .and_then(|i| self.dec_starts.get(i).copied())
            .unwrap_or(self.base)
    }

    /// Records a match `[start, end)` of `secret`, merging it with every region it overlaps.
    fn add(&mut self, start: u64, end: u64, secret: u32) {
        let mut region = Region {
            start,
            end,
            best: Best {
                len: end - start,
                start,
                secret,
            },
        };
        // Regions are sorted and disjoint, so the ones overlapping [start, end) are contiguous.
        let lo = self.regions.partition_point(|r| r.end <= start);
        let hi = self.regions.partition_point(|r| r.start < end);
        if lo < hi {
            for other in self.regions.drain(lo..hi) {
                region.start = region.start.min(other.start);
                region.end = region.end.max(other.end);
                if other.best.beats(region.best) {
                    region.best = other.best;
                }
            }
        }
        self.regions.insert(lo, region);
    }

    /// The earliest raw offset a match not yet seen could start at: before it, everything is final.
    fn frontier(&self, inner: &Inner) -> u64 {
        let (raw_live, _) = inner.raw.live_prefix(self.raw_node);
        let mut limit = self.pos - u64::from(raw_live);
        if !inner.decoded.is_empty() {
            let (dec_live, _) = inner.decoded.live_prefix(self.dec_node);
            if dec_live > 0 {
                limit = limit.min(self.decoded_start(dec_live));
            }
            if let Some(start) = self.partial.start() {
                limit = limit.min(start);
            }
            for &side in &self.sides {
                let (live, _) = inner.decoded.live_prefix(side.state);
                limit = limit.min(self.side_start(side, live));
            }
        }
        limit.max(self.base)
    }

    /// At the end of the stream: where the trailing prefix of a pattern starts, and its secret.
    fn tail(&self, inner: &Inner) -> Option<(u64, u32)> {
        let mut tail = None;
        let (raw_live, owner) = inner.raw.live_prefix(self.raw_node);
        if raw_live > 0 {
            tail = Some((self.pos - u64::from(raw_live), owner));
        }
        if !inner.decoded.is_empty() {
            let (dec_live, owner) = inner.decoded.live_prefix(self.dec_node);
            let decoded = if dec_live > 0 {
                Some((self.decoded_start(dec_live), owner))
            } else if let Partial::High { start, nibble, .. } = self.partial {
                // `%H` already gives away half of a secret's first byte.
                inner
                    .decoded
                    .first_byte_with_high_nibble(nibble)
                    .map(|owner| (start, owner))
            } else {
                None
            };
            let sides = self.sides.iter().map(|&side| {
                let (live, owner) = inner.decoded.live_prefix(side.state);
                (self.side_start(side, live), owner)
            });
            for candidate in decoded.into_iter().chain(sides) {
                if tail.is_none_or(|(start, _)| candidate.0 < start) {
                    tail = Some(candidate);
                }
            }
        }
        tail
    }

    /// Emits every byte before `limit`, replacing regions that end by then with their marker.
    fn emit_until(&mut self, inner: &Inner, limit: u64, out: &mut Vec<u8>) {
        while self.base < limit {
            let before = self.base;
            match self.regions.front().copied() {
                Some(region) if region.start < limit => {
                    if region.start > self.base {
                        self.take(region.start - self.base, out);
                    }
                    if region.end <= limit {
                        self.skip(region.end - self.base);
                        out.extend_from_slice(&inner.markers[region.best.secret as usize]);
                        self.regions.pop_front();
                    } else {
                        // Still open: a later match may extend it. Its bytes are never emitted, so drop them now.
                        self.skip(limit - self.base);
                    }
                }
                _ => self.take(limit - self.base, out),
            }
            // `pending` always holds [base, pos) and `limit <= pos`, so every turn moves on; never spin if not.
            if self.base == before {
                break;
            }
        }
    }

    fn take(&mut self, n: u64, out: &mut Vec<u8>) {
        let n = usize::try_from(n).unwrap_or(usize::MAX).min(self.pending.len());
        out.extend(self.pending.drain(..n));
        self.base += n as u64;
    }

    fn skip(&mut self, n: u64) {
        let n = usize::try_from(n).unwrap_or(usize::MAX).min(self.pending.len());
        self.pending.range_mut(..n).for_each(|b| *b = 0);
        self.pending.drain(..n);
        self.base += n as u64;
    }
}
