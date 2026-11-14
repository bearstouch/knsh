//! The lexer: one pass over an agent command line, producing [`Token`]s with exact spans (KNSH-028).
//!
//! It follows bash's own tokeniser (`parse.y`, `read_token` and `read_token_word`) where the two could disagree:
//!
//! - A line continuation (`\` newline) is removed everywhere except inside single quotes, ANSI-C quotes and
//!   comments, so it can split an operator (`&\` newline `&` is `&&`) or a `$(` without changing it. Its bytes stay
//!   in the token or segment that contains them, so spans still tile the input.
//! - `<(` and `>(` start a process substitution even in the middle of a word (`a<(b)` is one word).
//! - `$((` is arithmetic only if it closes with `))`; otherwise it is a command substitution starting with a subshell
//!   (`$( (a) )`), as in bash.
//! - The end of `$( … )` is found by lexing its body as commands, so quotes, comments and nested substitutions in
//!   it are honoured, and `)` after a `case` pattern does not close it (bash 4 and later).
//! - Inside backticks, only a backslash protects the next character; the first other backtick closes them.
//! - Inside `$( … )`, `<( … )` and `>( … )`, a comment that bash 3.2 and later versions read differently is refused
//!   ([`LexError::AmbiguousComment`]), so neither reading can hide a command the other runs.
//!
//! Out of scope (later stories): here-document bodies (KNSH-031; a body is refused, see
//! [`LexError::HereDocumentBody`]), the special lexing inside `[[ … ]]` and `(( … ))` (left to the parser, which
//! has the spans), and compound array assignments `a=( … )`, which arrive as a word, `(`, words and `)`.

use std::collections::HashSet;

use crate::error::{Construct, LexError};
use crate::limits::{MAX_INPUT_LEN, MAX_NESTING_DEPTH};
use crate::token::{
    IoNumber, Operator, Redirection, RedirectionOperator, ReservedWord, Segment, SegmentKind, Span, Token, TokenKind,
    Word,
};

/// Splits a command line into tokens.
///
/// Pure: no I/O and no global state. The spans of the returned tokens concatenate to `input` exactly, and the
/// segments of each word tile that word's span.
///
/// # Errors
///
/// - [`LexError::InputTooLarge`] when `input` is longer than [`MAX_INPUT_LEN`], checked before anything is read.
/// - [`LexError::Unterminated`] when a quote or substitution is still open at the end.
/// - [`LexError::NestingTooDeep`] when quotes and substitutions nest deeper than [`MAX_NESTING_DEPTH`].
/// - [`LexError::HereDocumentBody`] when a here-document body follows (not lexed until KNSH-031).
/// - [`LexError::AmbiguousComment`] when a comment inside a substitution would end differently in bash 3.2.
///
/// On error no tokens are returned: a partial token list would invite a guess.
///
/// # Example
///
/// ```
/// use knsh_bash::{Operator, TokenKind, lex};
///
/// let tokens = lex("ls -l | wc")?;
/// let kinds: Vec<_> = tokens.iter().map(|token| &token.kind).collect();
/// assert!(matches!(kinds[4], TokenKind::Operator(Operator::Pipe)));
/// assert_eq!(tokens.iter().map(|token| token.span.len()).sum::<usize>(), "ls -l | wc".len());
/// # Ok::<(), knsh_bash::LexError>(())
/// ```
pub fn lex(input: &str) -> Result<Vec<Token>, LexError> {
    if input.len() > MAX_INPUT_LEN {
        return Err(LexError::InputTooLarge {
            len: input.len(),
            limit: MAX_INPUT_LEN,
        });
    }
    let mut lexer = Lexer::new(input.as_bytes());
    let mut tokens = Vec::new();
    while let Some(token) = lexer.next_token()? {
        tokens.push(token);
    }
    Ok(tokens)
}

/// How a `$` is read: outside double quotes `$'…'` and `$"…"` are quotes; inside them they are a literal `$`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quoting {
    Unquoted,
    InDoubleQuotes,
}

/// Lexer state. Works on bytes: every byte bash treats specially is ASCII, and UTF-8 never uses ASCII values inside
/// a multi-byte character, so splitting only at ASCII bytes keeps spans on character boundaries.
struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    /// How many quotes and substitutions enclose `pos`; bounded by [`MAX_NESTING_DEPTH`].
    depth: usize,
    /// The first `<<` or `<<-` whose body has not started yet.
    pending_here_document: Option<Span>,
    /// Starts of `$((` already found not to close with `))`. Without this, nested failing `$((` would be rescanned
    /// once per enclosing one, which is exponential in the nesting depth.
    not_arithmetic: HashSet<usize>,
    /// How many `$( … )`, `<( … )` and `>( … )` bodies enclose `pos`, and how many of those are process
    /// substitutions. Comments in them are read differently by bash 3.2 (see [`Lexer::comment`]).
    substitutions: usize,
    process_substitutions: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            depth: 0,
            pending_here_document: None,
            not_arithmetic: HashSet::new(),
            substitutions: 0,
            process_substitutions: 0,
        }
    }

    // ---- Reading primitives -------------------------------------------------------------------------------------

    fn byte(&self, at: usize) -> Option<u8> {
        self.src.get(at).copied()
    }

    fn peek(&self) -> Option<u8> {
        self.byte(self.pos)
    }

    fn is_continuation(&self, at: usize) -> bool {
        self.byte(at) == Some(b'\\') && self.byte(at + 1) == Some(b'\n')
    }

    /// The first byte at or after `at` that is not part of a line continuation, with its offset. This is what bash
    /// reads next, since it removes continuations before tokenising.
    fn logical(&self, mut at: usize) -> Option<(usize, u8)> {
        while self.is_continuation(at) {
            at += 2;
        }
        self.byte(at).map(|byte| (at, byte))
    }

    /// Consumes the next logical byte (and any continuations before it) if it is `want`.
    fn eat_logical(&mut self, want: u8) -> bool {
        match self.logical(self.pos) {
            Some((at, byte)) if byte == want => {
                self.pos = at + 1;
                true
            }
            _ => false,
        }
    }

    /// Length of the UTF-8 character whose first byte is at `at` (1 at the end of the input, so callers advance).
    fn char_len(&self, at: usize) -> usize {
        match self.byte(at) {
            Some(byte) if byte >= 0xF0 => 4,
            Some(byte) if byte >= 0xE0 => 3,
            Some(byte) if byte >= 0xC0 => 2,
            Some(_) | None => 1,
        }
    }

    /// Skips a backslash and the character it quotes, clamped to the end of the input.
    fn skip_escape(&mut self) {
        self.pos = (self.pos + 1 + self.char_len(self.pos + 1)).min(self.src.len());
    }

    fn unterminated(&self, construct: Construct, start: usize) -> LexError {
        LexError::Unterminated {
            construct,
            span: Span::new(start, self.src.len()),
        }
    }

    /// Enters a nested construct whose opening delimiter is `opener`; fails past [`MAX_NESTING_DEPTH`].
    fn enter(&mut self, opener: Span) -> Result<(), LexError> {
        self.depth += 1;
        if self.depth > MAX_NESTING_DEPTH {
            return Err(LexError::NestingTooDeep {
                span: opener,
                limit: MAX_NESTING_DEPTH,
            });
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    // ---- Tokens -------------------------------------------------------------------------------------------------

    /// The next token, or `None` at the end of the input.
    fn next_token(&mut self) -> Result<Option<Token>, LexError> {
        let start = self.pos;
        let Some(first) = self.peek() else {
            return Ok(None);
        };
        let kind = match first {
            b' ' | b'\t' => self.blank(),
            b'\\' if self.is_continuation(start) => self.blank(),
            b'\n' => {
                self.pos += 1;
                // The lines after a here-document operator are its body, not commands.
                if let Some(operator) = self.pending_here_document {
                    return Err(LexError::HereDocumentBody { span: operator });
                }
                TokenKind::Newline
            }
            b'#' => self.comment()?,
            b'|' => self.pipe_operator(),
            b';' => self.semicolon_operator(),
            b'(' => {
                self.pos += 1;
                TokenKind::Operator(Operator::LeftParen)
            }
            b')' => {
                self.pos += 1;
                TokenKind::Operator(Operator::RightParen)
            }
            b'&' => self.ampersand_operator(),
            b'<' | b'>' if !self.opens_process_substitution(start) => self.redirection(None),
            _ => self.word_or_io_number(start)?,
        };
        let span = Span::new(start, self.pos);
        if let TokenKind::Redirection(Redirection {
            operator: RedirectionOperator::HereDocument | RedirectionOperator::HereDocumentStripTabs,
            ..
        }) = kind
        {
            self.pending_here_document.get_or_insert(span);
        }
        Ok(Some(Token { kind, span }))
    }

    /// Spaces, tabs and line continuations.
    fn blank(&mut self) -> TokenKind {
        loop {
            match self.peek() {
                Some(b' ' | b'\t') => self.pos += 1,
                Some(b'\\') if self.is_continuation(self.pos) => self.pos += 2,
                _ => return TokenKind::Blank,
            }
        }
    }

    /// From `#` to the end of the line. Continuations are not removed in comments, so a `\` before the newline does
    /// not extend the comment (checked against bash 3.2).
    ///
    /// Inside a substitution, bash 3.2 (`/bin/bash` on macOS) disagrees with later versions, which read the body
    /// with the full grammar: it starts a comment in `$( … )` only after a blank or a newline (`$(a;#) b` closes at
    /// the `)` and runs `b`; so does `$(#) $(b)`), and in `<( … )` or `>( … )` not at all. A comment that 3.2 would
    /// not read as one is refused, whichever reading is right, because either could hide a command the other runs.
    fn comment(&mut self) -> Result<TokenKind, LexError> {
        let start = self.pos;
        if self.process_substitutions > 0 || (self.substitutions > 0 && !self.follows_blank(start)) {
            return Err(LexError::AmbiguousComment {
                span: Span::new(start, start + 1),
            });
        }
        while let Some(byte) = self.peek() {
            if byte == b'\n' {
                break;
            }
            self.pos += 1;
        }
        Ok(TokenKind::Comment)
    }

    /// Whether the logical byte before `at` (skipping line continuations, as bash removes them) is a blank or a
    /// newline. An escaped backslash before a newline (`\\` newline) is taken as a continuation, which only ever
    /// refuses more.
    fn follows_blank(&self, mut at: usize) -> bool {
        loop {
            match at.checked_sub(1).and_then(|before| self.byte(before)) {
                Some(b'\n') if at >= 2 && self.byte(at - 2) == Some(b'\\') => at -= 2,
                Some(b' ' | b'\t' | b'\n') => return true,
                Some(_) | None => return false,
            }
        }
    }

    fn pipe_operator(&mut self) -> TokenKind {
        self.pos += 1;
        TokenKind::Operator(if self.eat_logical(b'|') {
            Operator::Or
        } else if self.eat_logical(b'&') {
            Operator::PipeAmpersand
        } else {
            Operator::Pipe
        })
    }

    fn semicolon_operator(&mut self) -> TokenKind {
        self.pos += 1;
        TokenKind::Operator(if self.eat_logical(b';') {
            if self.eat_logical(b'&') {
                Operator::DoubleSemicolonAmpersand
            } else {
                Operator::DoubleSemicolon
            }
        } else if self.eat_logical(b'&') {
            Operator::SemicolonAmpersand
        } else {
            Operator::Semicolon
        })
    }

    /// `&&`, `&`, or the redirections `&>` and `&>>`.
    fn ampersand_operator(&mut self) -> TokenKind {
        self.pos += 1;
        if self.eat_logical(b'&') {
            TokenKind::Operator(Operator::And)
        } else if self.eat_logical(b'>') {
            let operator = if self.eat_logical(b'>') {
                RedirectionOperator::AppendAll
            } else {
                RedirectionOperator::OutputAll
            };
            TokenKind::Redirection(Redirection { fd: None, operator })
        } else {
            TokenKind::Operator(Operator::Background)
        }
    }

    /// A redirection operator starting at `<` or `>` (longest match), with the number read before it, if any.
    fn redirection(&mut self, fd: Option<IoNumber>) -> TokenKind {
        let first = self.peek();
        self.pos += 1;
        let operator = if first == Some(b'<') {
            if self.eat_logical(b'<') {
                if self.eat_logical(b'<') {
                    RedirectionOperator::HereString
                } else if self.eat_logical(b'-') {
                    RedirectionOperator::HereDocumentStripTabs
                } else {
                    RedirectionOperator::HereDocument
                }
            } else if self.eat_logical(b'&') {
                RedirectionOperator::DuplicateInput
            } else if self.eat_logical(b'>') {
                RedirectionOperator::ReadWrite
            } else {
                RedirectionOperator::Input
            }
        } else if self.eat_logical(b'>') {
            RedirectionOperator::Append
        } else if self.eat_logical(b'&') {
            RedirectionOperator::DuplicateOutput
        } else if self.eat_logical(b'|') {
            RedirectionOperator::Clobber
        } else {
            RedirectionOperator::Output
        };
        TokenKind::Redirection(Redirection { fd, operator })
    }

    /// A word, or the file-descriptor number of a redirection when the word is all digits and `<` or `>` follows.
    fn word_or_io_number(&mut self, start: usize) -> Result<TokenKind, LexError> {
        let word = self.word()?;
        if matches!(self.peek(), Some(b'<' | b'>'))
            && let Some(fd) = self.io_number(&word, Span::new(start, self.pos))
        {
            return Ok(self.redirection(Some(fd)));
        }
        Ok(TokenKind::Word(word))
    }

    /// The word at `span` as a file-descriptor number, if it is made only of unquoted digits (line continuations
    /// allowed, as bash removes them first). Its value is `None` above `i32::MAX`.
    fn io_number(&self, word: &Word, span: Span) -> Option<IoNumber> {
        let mut value: Option<u32> = Some(0);
        let mut digits = 0usize;
        for &byte in self.unquoted_text(&word.segments)?.flatten() {
            if !byte.is_ascii_digit() {
                return None;
            }
            digits += 1;
            value = value
                .and_then(|value| value.checked_mul(10))
                .and_then(|value| value.checked_add(u32::from(byte - b'0')))
                .filter(|&value| i32::try_from(value).is_ok());
        }
        (digits > 0).then_some(IoNumber { span, value })
    }

    /// The reserved word a word spells, if it is made only of unquoted text. Quoting any part (`'if'`, `\if`) makes
    /// it an ordinary word, as in bash.
    fn reserved_word(&self, segments: &[Segment]) -> Option<ReservedWord> {
        let mut text = [0u8; ReservedWord::MAX_LEN];
        let mut len = 0;
        for bytes in self.unquoted_text(segments)? {
            text.get_mut(len..len + bytes.len())?.copy_from_slice(bytes);
            len += bytes.len();
        }
        ReservedWord::from_text(text.get(..len)?)
    }

    /// The text of a word made only of unquoted text, as bash reads it: the bytes of each literal segment, with line
    /// continuations left out. `None` if any segment is quoted or an expansion.
    fn unquoted_text<'s>(&self, segments: &'s [Segment]) -> Option<impl Iterator<Item = &'a [u8]> + use<'a, 's>> {
        if !segments.iter().all(|segment| segment.kind.is_unquoted_text()) {
            return None;
        }
        let src = self.src;
        Some(
            segments
                .iter()
                .filter(|segment| segment.kind == SegmentKind::Literal)
                .filter_map(move |segment| src.get(segment.span.range())),
        )
    }

    // ---- Words --------------------------------------------------------------------------------------------------

    /// A word: segments up to the first unquoted metacharacter. The caller guarantees the first byte is not one.
    fn word(&mut self) -> Result<Word, LexError> {
        let mut segments = SegmentList::default();
        while let Some(byte) = self.peek() {
            let at = self.pos;
            let segment = match byte {
                b'\\' if self.is_continuation(at) => Some(self.line_continuation()),
                b'\\' => {
                    self.skip_escape();
                    Some(Segment {
                        kind: SegmentKind::Escape,
                        span: Span::new(at, self.pos),
                        body: Span::new(at + 1, self.pos),
                    })
                }
                b'\'' => Some(self.single_quoted()?),
                b'"' => Some(self.double_quoted(at, at + 1, Construct::DoubleQuote)?),
                b'`' => Some(self.backtick()?),
                // A `$` that starts nothing is a literal character.
                b'$' => self.dollar(Quoting::Unquoted)?,
                b'<' | b'>' if self.opens_process_substitution(at) => Some(self.process_substitution()?),
                // Unquoted metacharacters end the word.
                b' ' | b'\t' | b'\n' | b'|' | b'&' | b';' | b'(' | b')' | b'<' | b'>' => break,
                _ => None,
            };
            self.push_segment_or_literal(&mut segments, segment);
        }
        let segments = segments.finish(self.pos);
        let reserved = self.reserved_word(&segments);
        Ok(Word { segments, reserved })
    }

    /// Appends `segment`, or, when there is none, takes the byte at `pos` as literal text.
    fn push_segment_or_literal(&mut self, segments: &mut SegmentList, segment: Option<Segment>) {
        if let Some(segment) = segment {
            segments.push(segment);
        } else {
            segments.literal_byte(self.pos);
            self.pos += 1;
        }
    }

    /// `\` newline at `pos`.
    fn line_continuation(&mut self) -> Segment {
        let at = self.pos;
        self.pos += 2;
        Segment {
            kind: SegmentKind::LineContinuation,
            span: Span::new(at, self.pos),
            body: Span::new(self.pos, self.pos),
        }
    }

    /// `'…'`: no escapes; ends at the next `'`.
    fn single_quoted(&mut self) -> Result<Segment, LexError> {
        let start = self.pos;
        let body_start = start + 1;
        let Some(close) = self.find_byte(body_start, b'\'') else {
            return Err(self.unterminated(Construct::SingleQuote, start));
        };
        self.pos = close + 1;
        Ok(Segment {
            kind: SegmentKind::SingleQuoted,
            span: Span::new(start, self.pos),
            body: Span::new(body_start, close),
        })
    }

    fn find_byte(&self, from: usize, want: u8) -> Option<usize> {
        let rest = self.src.get(from..)?;
        rest.iter().position(|&byte| byte == want).map(|offset| from + offset)
    }

    /// Reads from `pos` to the first `close` not protected by a backslash, returns its offset and leaves `pos` just
    /// past it. Continuations are not removed. Fails as an unterminated `construct` opened at `start`.
    fn until_unescaped(&mut self, close: u8, construct: Construct, start: usize) -> Result<usize, LexError> {
        loop {
            match self.peek() {
                None => return Err(self.unterminated(construct, start)),
                Some(b'\\') => self.skip_escape(),
                Some(byte) if byte == close => break,
                Some(_) => self.pos += 1,
            }
        }
        let close_at = self.pos;
        self.pos += 1;
        Ok(close_at)
    }

    /// `$'…'` starting at `start`, body from `body_start`: a backslash protects the next character, so `\'` does
    /// not close it.
    fn ansi_c(&mut self, start: usize, body_start: usize) -> Result<Segment, LexError> {
        self.pos = body_start;
        let close = self.until_unescaped(b'\'', Construct::AnsiCQuote, start)?;
        Ok(Segment {
            kind: SegmentKind::AnsiC,
            span: Span::new(start, self.pos),
            body: Span::new(body_start, close),
        })
    }

    /// `"…"` or `$"…"` (by `construct`) starting at `start`, body from `body_start`, with its inner segments.
    fn double_quoted(&mut self, start: usize, body_start: usize, construct: Construct) -> Result<Segment, LexError> {
        self.enter(Span::new(start, body_start))?;
        self.pos = body_start;
        let mut segments = SegmentList::default();
        let close = loop {
            let at = self.pos;
            let Some(byte) = self.peek() else {
                return Err(self.unterminated(construct, start));
            };
            let segment = match byte {
                b'"' => break at,
                b'\\' if self.is_continuation(at) => Some(self.line_continuation()),
                // Inside double quotes a backslash escapes only `$`, `` ` ``, `"` and `\`; before anything else it
                // is a literal character.
                b'\\' if matches!(self.byte(at + 1), Some(b'$' | b'`' | b'"' | b'\\')) => {
                    self.pos += 2;
                    Some(Segment {
                        kind: SegmentKind::Escape,
                        span: Span::new(at, at + 2),
                        body: Span::new(at + 1, at + 2),
                    })
                }
                b'`' => Some(self.backtick()?),
                b'$' => self.dollar(Quoting::InDoubleQuotes)?,
                _ => None,
            };
            self.push_segment_or_literal(&mut segments, segment);
        };
        let segments = segments.finish(close);
        self.pos = close + 1;
        self.leave();
        let kind = if construct == Construct::LocaleQuote {
            SegmentKind::Locale(segments)
        } else {
            SegmentKind::DoubleQuoted(segments)
        };
        Ok(Segment {
            kind,
            span: Span::new(start, self.pos),
            body: Span::new(body_start, close),
        })
    }

    /// `` `…` ``: a backslash protects the next character; the first other backtick closes it. Bash does not track
    /// quotes inside backticks when finding the end (`` `echo '`'` `` closes at the second backtick).
    fn backtick(&mut self) -> Result<Segment, LexError> {
        let start = self.pos;
        self.pos += 1;
        let close = self.until_unescaped(b'`', Construct::Backtick, start)?;
        Ok(Segment {
            kind: SegmentKind::Backtick,
            span: Span::new(start, self.pos),
            body: Span::new(start + 1, close),
        })
    }

    // ---- Dollar forms -------------------------------------------------------------------------------------------

    /// The construct a `$` at `pos` starts, or `None` (without consuming anything) when the `$` is literal.
    fn dollar(&mut self, quoting: Quoting) -> Result<Option<Segment>, LexError> {
        let start = self.pos;
        let Some((next_at, next)) = self.logical(start + 1) else {
            return Ok(None);
        };
        let segment = match next {
            b'(' => match self.logical(next_at + 1) {
                Some((second_at, b'(')) if !self.not_arithmetic.contains(&start) => {
                    self.arithmetic(start, next_at + 1, second_at + 1)?
                }
                _ => self.command_substitution(start, next_at + 1, Construct::CommandSubstitution)?,
            },
            b'{' => self.parameter_expansion(start, next_at + 1)?,
            b'[' => self.legacy_arithmetic(start, next_at + 1)?,
            b'\'' if quoting == Quoting::Unquoted => self.ansi_c(start, next_at + 1)?,
            b'"' if quoting == Quoting::Unquoted => self.double_quoted(start, next_at + 1, Construct::LocaleQuote)?,
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                self.pos = next_at + 1;
                while let Some((at, byte)) = self.logical(self.pos) {
                    if !(byte.is_ascii_alphanumeric() || byte == b'_') {
                        break;
                    }
                    self.pos = at + 1;
                }
                parameter(start, next_at, self.pos)
            }
            b'0'..=b'9' | b'@' | b'*' | b'#' | b'?' | b'-' | b'$' | b'!' => {
                self.pos = next_at + 1;
                parameter(start, next_at, self.pos)
            }
            _ => return Ok(None),
        };
        Ok(Some(segment))
    }

    /// `$(…)`, `<(…)` or `>(…)` opening at `start`, body from `body_start`. The body is lexed as commands, so the end
    /// is the first `)` that closes no `(` of the body and no `case` pattern.
    fn command_substitution(
        &mut self,
        start: usize,
        body_start: usize,
        construct: Construct,
    ) -> Result<Segment, LexError> {
        self.enter(Span::new(start, body_start))?;
        self.pos = body_start;
        self.substitutions += 1;
        let process = construct == Construct::ProcessSubstitution;
        if process {
            self.process_substitutions += 1;
        }
        let mut parens = 0usize;
        // The `case` blocks open in the body, each as the number of open `(` where it started. While the innermost
        // one is open at the current level, a `)` there ends a pattern, not a subshell or the body.
        let mut open_cases: Vec<usize> = Vec::new();
        let mut command_start = true;
        let body_end = loop {
            let Some(token) = self.next_token()? else {
                return Err(self.unterminated(construct, start));
            };
            match token.kind {
                TokenKind::Operator(Operator::RightParen) => {
                    if open_cases.last() == Some(&parens) {
                        command_start = true;
                    } else if parens > 0 {
                        parens -= 1;
                        command_start = false;
                    } else {
                        break token.span.start;
                    }
                }
                TokenKind::Operator(Operator::LeftParen) => {
                    parens += 1;
                    command_start = true;
                }
                TokenKind::Operator(
                    Operator::Pipe
                    | Operator::PipeAmpersand
                    | Operator::Or
                    | Operator::And
                    | Operator::Background
                    | Operator::Semicolon
                    | Operator::DoubleSemicolon
                    | Operator::SemicolonAmpersand
                    | Operator::DoubleSemicolonAmpersand,
                )
                | TokenKind::Newline => command_start = true,
                TokenKind::Word(word) => {
                    let reserved = if command_start { word.reserved } else { None };
                    match reserved {
                        Some(ReservedWord::Case) => open_cases.push(parens),
                        Some(ReservedWord::Esac) if open_cases.last() == Some(&parens) => {
                            open_cases.pop();
                        }
                        Some(_) | None => {}
                    }
                    command_start = reserved.is_some_and(ReservedWord::starts_command);
                }
                TokenKind::Redirection(_) => command_start = false,
                TokenKind::Blank | TokenKind::Comment => {}
            }
        };
        self.substitutions -= 1;
        if process {
            self.process_substitutions -= 1;
        }
        self.leave();
        let kind = match construct {
            Construct::ProcessSubstitution if self.byte(start) == Some(b'<') => SegmentKind::InputProcessSubstitution,
            Construct::ProcessSubstitution => SegmentKind::OutputProcessSubstitution,
            Construct::SingleQuote
            | Construct::DoubleQuote
            | Construct::AnsiCQuote
            | Construct::LocaleQuote
            | Construct::Backtick
            | Construct::CommandSubstitution
            | Construct::ParameterExpansion
            | Construct::ArithmeticExpansion => SegmentKind::CommandSubstitution,
        };
        Ok(Segment {
            kind,
            span: Span::new(start, self.pos),
            body: Span::new(body_start, body_end),
        })
    }

    /// Whether a `<` or `>` at `at` starts a process substitution (`(` follows).
    fn opens_process_substitution(&self, at: usize) -> bool {
        matches!(self.logical(at + 1), Some((_, b'(')))
    }

    fn process_substitution(&mut self) -> Result<Segment, LexError> {
        let start = self.pos;
        let Some((paren_at, _)) = self.logical(start + 1) else {
            return Err(self.unterminated(Construct::ProcessSubstitution, start));
        };
        self.command_substitution(start, paren_at + 1, Construct::ProcessSubstitution)
    }

    /// `$((…))` opening at `start`; `inner_paren` is just after the first `(`, `body_start` after the second. If the
    /// parenthesis matching the second `(` is not directly followed by `)`, this is a command substitution starting
    /// with a subshell, and it is lexed again as one.
    fn arithmetic(&mut self, start: usize, inner_paren: usize, body_start: usize) -> Result<Segment, LexError> {
        let body_end = self.expansion_body(start, body_start, Construct::ArithmeticExpansion, Some(b'('), b')')?;
        if !self.eat_logical(b')') {
            self.not_arithmetic.insert(start);
            return self.command_substitution(start, inner_paren, Construct::CommandSubstitution);
        }
        Ok(Segment {
            kind: SegmentKind::Arithmetic,
            span: Span::new(start, self.pos),
            body: Span::new(body_start, body_end),
        })
    }

    /// `$[…]`, the legacy arithmetic form; nested `[` and `]` are matched.
    fn legacy_arithmetic(&mut self, start: usize, body_start: usize) -> Result<Segment, LexError> {
        let close = self.expansion_body(start, body_start, Construct::ArithmeticExpansion, Some(b'['), b']')?;
        Ok(Segment {
            kind: SegmentKind::Arithmetic,
            span: Span::new(start, self.pos),
            body: Span::new(body_start, close),
        })
    }

    /// `${…}`: closes at the first `}` outside quotes and nested expansions. Like bash, a bare `{` inside does not
    /// nest (`${x:-{a}b}` closes after `a`), and quotes count even when the expansion is inside double quotes.
    fn parameter_expansion(&mut self, start: usize, body_start: usize) -> Result<Segment, LexError> {
        let close = self.expansion_body(start, body_start, Construct::ParameterExpansion, None, b'}')?;
        Ok(Segment {
            kind: SegmentKind::ParameterExpansion,
            span: Span::new(start, self.pos),
            body: Span::new(body_start, close),
        })
    }

    /// Reads the body of `${…}`, `$((…))` or `$[…]` (a `construct` opened at `start`) from `body_start` to the
    /// `close` byte that ends it, returns that byte's offset and leaves `pos` just past it. Each `open` byte (if any)
    /// nests and must be matched by a `close` first. Escapes, quotes and nested expansions are skipped, so their
    /// characters cannot end the body.
    fn expansion_body(
        &mut self,
        start: usize,
        body_start: usize,
        construct: Construct,
        open: Option<u8>,
        close: u8,
    ) -> Result<usize, LexError> {
        self.enter(Span::new(start, body_start))?;
        self.pos = body_start;
        let mut nested = 0usize;
        let body_end = loop {
            let Some(byte) = self.peek() else {
                return Err(self.unterminated(construct, start));
            };
            if Some(byte) == open {
                nested += 1;
                self.pos += 1;
            } else if byte == close {
                if nested == 0 {
                    break self.pos;
                }
                nested -= 1;
                self.pos += 1;
            } else if !self.skip_quoted_or_expansion()? {
                self.pos += 1;
            }
        };
        self.pos = body_end + 1;
        self.leave();
        Ok(body_end)
    }

    /// Inside `${…}`, `$((…))` and `$[…]`: skips an escape, a quote or a nested expansion at `pos` so that its
    /// characters cannot close the enclosing construct. Returns whether anything was skipped.
    fn skip_quoted_or_expansion(&mut self) -> Result<bool, LexError> {
        match self.peek() {
            Some(b'\\') => self.skip_escape(),
            Some(b'\'') => {
                self.single_quoted()?;
            }
            Some(b'"') => {
                self.double_quoted(self.pos, self.pos + 1, Construct::DoubleQuote)?;
            }
            Some(b'`') => {
                self.backtick()?;
            }
            Some(b'$') => {
                if self.dollar(Quoting::Unquoted)?.is_none() {
                    self.pos += 1;
                }
            }
            Some(_) | None => return Ok(false),
        }
        Ok(true)
    }
}

/// A `$name` or special-parameter segment from `start` (the `$`) to `end`, its name starting at `name_start`.
fn parameter(start: usize, name_start: usize, end: usize) -> Segment {
    Segment {
        kind: SegmentKind::Parameter,
        span: Span::new(start, end),
        body: Span::new(name_start, end),
    }
}

/// The segments of a word or a double-quoted body as they are read. Consecutive literal bytes are merged into one
/// [`SegmentKind::Literal`] segment, ended by the next other segment or by [`SegmentList::finish`].
#[derive(Default)]
struct SegmentList {
    segments: Vec<Segment>,
    /// Where the literal run being read started, if one is open.
    literal_start: Option<usize>,
}

impl SegmentList {
    /// Takes the byte at `at` as literal text, starting a literal run if none is open.
    fn literal_byte(&mut self, at: usize) {
        self.literal_start.get_or_insert(at);
    }

    /// Ends any open literal run where `segment` starts, then appends `segment`.
    fn push(&mut self, segment: Segment) {
        self.end_literal(segment.span.start);
        self.segments.push(segment);
    }

    /// Ends any open literal run at `end` and returns the segments.
    fn finish(mut self, end: usize) -> Vec<Segment> {
        self.end_literal(end);
        self.segments
    }

    fn end_literal(&mut self, end: usize) {
        if let Some(start) = self.literal_start.take() {
            let span = Span::new(start, end);
            self.segments.push(Segment {
                kind: SegmentKind::Literal,
                span,
                body: span,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(tokens: &[Token]) -> Vec<&Word> {
        tokens
            .iter()
            .filter_map(|token| match &token.kind {
                TokenKind::Word(word) => Some(word),
                _ => None,
            })
            .collect()
    }

    fn operators(tokens: &[Token]) -> Vec<Operator> {
        tokens
            .iter()
            .filter_map(|token| match token.kind {
                TokenKind::Operator(operator) => Some(operator),
                _ => None,
            })
            .collect()
    }

    fn redirections(tokens: &[Token]) -> Vec<Redirection> {
        tokens
            .iter()
            .filter_map(|token| match token.kind {
                TokenKind::Redirection(redirection) => Some(redirection),
                _ => None,
            })
            .collect()
    }

    /// The single word of `input`, which must lex to exactly one token.
    fn only_word(input: &str) -> Word {
        let tokens = lex(input).unwrap();
        assert_eq!(tokens.len(), 1, "{input:?} gave {tokens:#?}");
        match &tokens[0].kind {
            TokenKind::Word(word) => word.clone(),
            other => panic!("{input:?} is not a word: {other:?}"),
        }
    }

    fn kinds(segments: &[Segment]) -> Vec<&SegmentKind> {
        segments.iter().map(|segment| &segment.kind).collect()
    }

    fn text(input: &str, span: Span) -> &str {
        span.text(input).unwrap()
    }

    // ---- Story unit tests (KNSH-028) ----

    #[test]
    fn lexes_single_quoted_word_without_escapes() {
        // Decision 6 (every quoting form): nothing inside single quotes is special, not even a backslash.
        let input = r"'a\b'";
        let word = only_word(input);
        assert_eq!(kinds(&word.segments), [&SegmentKind::SingleQuoted]);
        assert_eq!(text(input, word.segments[0].body), r"a\b");
    }

    #[test]
    fn lexes_ansi_c_quoting() {
        let input = r"$'\n\x41'";
        let word = only_word(input);
        assert_eq!(kinds(&word.segments), [&SegmentKind::AnsiC]);
        assert_eq!(text(input, word.segments[0].body), r"\n\x41");
        // An escaped quote does not close it.
        let input = r"$'it\'s'";
        assert_eq!(text(input, only_word(input).segments[0].body), r"it\'s");
    }

    #[test]
    fn lexes_double_quotes_with_nested_dollar() {
        // FR-LC-02: the substitution inside the quotes keeps its own span, to be parsed recursively.
        let input = r#""a $(b "c") d""#;
        let word = only_word(input);
        let SegmentKind::DoubleQuoted(inner) = &word.segments[0].kind else {
            panic!("not double quoted: {word:?}");
        };
        assert_eq!(
            kinds(inner),
            [
                &SegmentKind::Literal,
                &SegmentKind::CommandSubstitution,
                &SegmentKind::Literal
            ]
        );
        assert_eq!(text(input, inner[1].span), r#"$(b "c")"#);
        assert_eq!(text(input, inner[1].body), r#"b "c""#);
        assert_eq!(text(input, inner[2].span), " d");
    }

    #[test]
    fn lexes_line_continuation_as_nothing() {
        let input = "ec\\\nho";
        let word = only_word(input);
        assert_eq!(
            kinds(&word.segments),
            [
                &SegmentKind::Literal,
                &SegmentKind::LineContinuation,
                &SegmentKind::Literal
            ]
        );
        assert!(word.segments[1].body.is_empty());
        // Between words it is blank space.
        let tokens = lex("a \\\nb").unwrap();
        assert_eq!(words(&tokens).len(), 2);
        assert_eq!(tokens[1].kind, TokenKind::Blank);
    }

    #[test]
    fn splits_all_control_operators() {
        let tokens = lex("a||b&&c;d&e|f").unwrap();
        assert_eq!(
            operators(&tokens),
            [
                Operator::Or,
                Operator::And,
                Operator::Semicolon,
                Operator::Background,
                Operator::Pipe
            ]
        );
        assert_eq!(words(&tokens).len(), 6);
        let tokens = lex("a |& b ;; c ;& d ;;& (e)").unwrap();
        assert_eq!(
            operators(&tokens),
            [
                Operator::PipeAmpersand,
                Operator::DoubleSemicolon,
                Operator::SemicolonAmpersand,
                Operator::DoubleSemicolonAmpersand,
                Operator::LeftParen,
                Operator::RightParen
            ]
        );
    }

    #[test]
    fn recognises_redirection_operators_with_fd_numbers() {
        let input = "cmd 2>&1 &>all >|clobber <<<here 10<in 3<>rw >>app <&0 <<-EOF";
        let tokens = lex(input).unwrap();
        let found: Vec<(Option<Option<u32>>, RedirectionOperator)> = redirections(&tokens)
            .iter()
            .map(|redirection| (redirection.fd.map(|fd| fd.value), redirection.operator))
            .collect();
        assert_eq!(
            found,
            [
                (Some(Some(2)), RedirectionOperator::DuplicateOutput),
                (None, RedirectionOperator::OutputAll),
                (None, RedirectionOperator::Clobber),
                (None, RedirectionOperator::HereString),
                (Some(Some(10)), RedirectionOperator::Input),
                (Some(Some(3)), RedirectionOperator::ReadWrite),
                (None, RedirectionOperator::Append),
                (None, RedirectionOperator::DuplicateInput),
                (None, RedirectionOperator::HereDocumentStripTabs),
            ]
        );
        // The redirection token covers the number; its target is the next word.
        let two = tokens.iter().find(|token| text(input, token.span) == "2>&").unwrap();
        assert!(matches!(two.kind, TokenKind::Redirection(_)));
        assert_eq!(
            words(&tokens)
                .iter()
                .map(|word| text(input, word.segments[0].span))
                .collect::<Vec<_>>(),
            ["cmd", "1", "all", "clobber", "here", "in", "rw", "app", "0", "EOF"]
        );
        let input = "a &>>log <<EOF";
        let found: Vec<_> = redirections(&lex(input).unwrap()).iter().map(|r| r.operator).collect();
        assert_eq!(
            found,
            [RedirectionOperator::AppendAll, RedirectionOperator::HereDocument]
        );
    }

    #[test]
    fn rejects_unterminated_single_quote() {
        let error = lex("echo 'abc").unwrap_err();
        assert_eq!(
            error,
            LexError::Unterminated {
                construct: Construct::SingleQuote,
                span: Span::new(5, 9)
            }
        );
    }

    #[test]
    fn spans_round_trip_to_source() {
        // Property over random inputs (FR-LC-02, NFR-SEC-05): token spans tile the input exactly, segments tile each
        // word, and every error span lies inside the input. A small xorshift generator keeps it dependency-free and
        // reproducible; the alphabet is weighted towards characters bash treats specially.
        const PIECES: &[&str] = &[
            "a", "b", "1", "2", " ", "\t", "\n", "\\", "\\\n", "'", "\"", "`", "$", "$(", "$((", "${", "$[", "$'",
            "$\"", "(", ")", "{", "}", "[", "]", "<", ">", "<(", ">(", "|", "&", ";", "#", "-", "=", "é", "case",
            "esac", "in", "<<", "2>",
        ];
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut accepted = 0;
        for _ in 0..20_000 {
            let len = usize::try_from(next() % 24).unwrap();
            let input: String = (0..len)
                .map(|_| PIECES[usize::try_from(next() % PIECES.len() as u64).unwrap()])
                .collect();
            match lex(&input) {
                Ok(tokens) => {
                    accepted += 1;
                    let mut end = 0;
                    for token in &tokens {
                        assert_eq!(token.span.start, end, "gap or overlap in {input:?}");
                        assert!(token.span.end > token.span.start, "empty token in {input:?}");
                        end = token.span.end;
                        if let TokenKind::Word(word) = &token.kind {
                            assert_tiles(&input, &word.segments, token.span);
                        }
                    }
                    assert_eq!(end, input.len(), "tokens do not reach the end of {input:?}");
                    let rebuilt: String = tokens.iter().map(|token| text(&input, token.span)).collect();
                    assert_eq!(rebuilt, input);
                }
                Err(error) => {
                    if let Some(span) = error.span() {
                        assert!(span.text(&input).is_some(), "error span outside {input:?}: {error:?}");
                    }
                }
            }
        }
        assert!(
            accepted > 2_000,
            "too few random inputs accepted ({accepted}) for the property to mean much"
        );
    }

    /// Segments tile `span` in order, and double-quoted bodies are tiled by their inner segments.
    fn assert_tiles(input: &str, segments: &[Segment], span: Span) {
        let mut end = span.start;
        for segment in segments {
            assert_eq!(segment.span.start, end, "segment gap in {input:?}");
            assert!(segment.span.text(input).is_some() && segment.body.text(input).is_some());
            assert!(segment.body.start >= segment.span.start && segment.body.end <= segment.span.end);
            end = segment.span.end;
            if let SegmentKind::DoubleQuoted(inner) | SegmentKind::Locale(inner) = &segment.kind {
                assert_tiles(input, inner, segment.body);
            }
        }
        assert_eq!(end, span.end, "segments do not cover the word in {input:?}");
    }

    #[test]
    fn comment_ends_at_newline_only_at_word_start() {
        let tokens = lex("a#b").unwrap();
        assert_eq!(tokens.len(), 1);
        let tokens = lex("a #b\nc").unwrap();
        let found: Vec<_> = tokens.iter().map(|token| &token.kind).collect();
        assert!(matches!(
            found[..],
            [
                TokenKind::Word(_),
                TokenKind::Blank,
                TokenKind::Comment,
                TokenKind::Newline,
                TokenKind::Word(_)
            ]
        ));
        assert_eq!(tokens[2].span, Span::new(2, 4));
        // After an operator a word may start, so `#` comments there too.
        assert!(
            lex("a;#b")
                .unwrap()
                .iter()
                .any(|token| token.kind == TokenKind::Comment)
        );
        // A continuation does not extend a comment (bash 3.2: `# c \` newline `b` runs `b`).
        let tokens = lex("a # c \\\nb").unwrap();
        assert_eq!(words(&tokens).len(), 2);
    }

    // ---- Further behaviour ----

    #[test]
    fn rejects_every_unterminated_construct_with_its_span() {
        for (input, construct, start) in [
            ("a \"b", Construct::DoubleQuote, 2),
            ("$'a", Construct::AnsiCQuote, 0),
            ("x $\"a", Construct::LocaleQuote, 2),
            ("`a", Construct::Backtick, 0),
            ("a $(b", Construct::CommandSubstitution, 2),
            ("a $(b ')'", Construct::CommandSubstitution, 2),
            ("<(a", Construct::ProcessSubstitution, 0),
            ("${a", Construct::ParameterExpansion, 0),
            ("$((1+", Construct::ArithmeticExpansion, 0),
            ("$[1", Construct::ArithmeticExpansion, 0),
            ("\"$(a 'b\"", Construct::SingleQuote, 5),
        ] {
            let error = lex(input).unwrap_err();
            assert_eq!(
                error,
                LexError::Unterminated {
                    construct,
                    span: Span::new(start, input.len())
                },
                "{input:?}"
            );
        }
    }

    #[test]
    fn rejects_input_over_the_limit_before_reading_it() {
        // An unterminated quote would be found if the input were read; the size check comes first.
        let input = format!("'{}", " ".repeat(MAX_INPUT_LEN));
        assert_eq!(
            lex(&input).unwrap_err(),
            LexError::InputTooLarge {
                len: MAX_INPUT_LEN + 1,
                limit: MAX_INPUT_LEN
            }
        );
        let input = "a".repeat(MAX_INPUT_LEN);
        assert_eq!(lex(&input).unwrap().len(), 1);
    }

    #[test]
    fn bounds_nesting_depth() {
        let nested = |depth: usize| format!("{}x{}", "$(".repeat(depth), ")".repeat(depth));
        assert!(lex(&nested(MAX_NESTING_DEPTH)).is_ok());
        let error = lex(&nested(MAX_NESTING_DEPTH + 1)).unwrap_err();
        let opener = 2 * MAX_NESTING_DEPTH;
        assert_eq!(
            error,
            LexError::NestingTooDeep {
                span: Span::new(opener, opener + 2),
                limit: MAX_NESTING_DEPTH
            }
        );
        // Quotes count as levels too.
        assert!(lex(&"\"$(".repeat(MAX_NESTING_DEPTH)).is_err());
    }

    #[test]
    fn nested_failing_arithmetic_stays_linear() {
        // Each `$((` here is found not to be arithmetic only after its nested `$((` were read, then falls back to a
        // command substitution; without the memo the innermost would be read 2^30 times.
        let depth = 30;
        let input = format!("{}1{}", "$((".repeat(depth), ") x)".repeat(depth));
        assert!(lex(&input).is_ok());
    }

    #[test]
    fn marks_reserved_word_candidates_only_when_unquoted() {
        assert_eq!(only_word("if").reserved, Some(ReservedWord::If));
        assert_eq!(only_word("{").reserved, Some(ReservedWord::LeftBrace));
        assert_eq!(only_word("!").reserved, Some(ReservedWord::Bang));
        assert_eq!(only_word("[[").reserved, Some(ReservedWord::DoubleLeftBracket));
        assert_eq!(only_word("i\\\nf").reserved, Some(ReservedWord::If));
        assert_eq!(only_word("'if'").reserved, None);
        assert_eq!(only_word("\\if").reserved, None);
        assert_eq!(only_word("iff").reserved, None);
        assert_eq!(only_word("functions").reserved, None);
        // `{` and `}` are words, not operators: brace expansion and `{}` stay whole.
        assert_eq!(only_word("{}").reserved, None);
        assert_eq!(only_word("{a,b}").reserved, None);
        // Candidates in argument position are still marked; the parser decides by position.
        let tokens = lex("echo if").unwrap();
        assert_eq!(words(&tokens)[1].reserved, Some(ReservedWord::If));
    }

    #[test]
    fn line_continuation_joins_operators_and_dollar_forms() {
        // Bash removes `\` newline before tokenising, so these are `&&`, `$(` and `2>`.
        let tokens = lex("a &\\\n& b").unwrap();
        assert_eq!(operators(&tokens), [Operator::And]);
        let input = "$\\\n(x)";
        let word = only_word(input);
        assert_eq!(kinds(&word.segments), [&SegmentKind::CommandSubstitution]);
        assert_eq!(text(input, word.segments[0].body), "x");
        let found = redirections(&lex("a 2\\\n>f").unwrap());
        assert_eq!(found[0].fd.map(|fd| fd.value), Some(Some(2)));
    }

    #[test]
    fn io_number_only_for_unquoted_digits() {
        assert!(redirections(&lex("a \"2\">f").unwrap())[0].fd.is_none());
        assert!(redirections(&lex("a a2>f").unwrap())[0].fd.is_none());
        assert!(redirections(&lex("a 2 >f").unwrap())[0].fd.is_none());
        // Bash 3.2 still takes an out-of-range number as a descriptor (and fails at run time).
        let found = redirections(&lex("a 99999999999>f").unwrap());
        assert_eq!(found[0].fd.map(|fd| fd.value), Some(None));
        let found = redirections(&lex("a 2147483647>f").unwrap());
        assert_eq!(found[0].fd.map(|fd| fd.value), Some(Some(2_147_483_647)));
    }

    #[test]
    fn lexes_dollar_forms() {
        // A `$` that starts nothing (here, at the end) is literal; `$12` is `$1` then `2`.
        let input = "$a$_b1${c:-'}'}$((1+(2)))$[3]$?$12$@$";
        let word = only_word(input);
        let found: Vec<_> = word
            .segments
            .iter()
            .map(|segment| (&segment.kind, text(input, segment.span)))
            .collect();
        assert_eq!(
            found,
            [
                (&SegmentKind::Parameter, "$a"),
                (&SegmentKind::Parameter, "$_b1"),
                (&SegmentKind::ParameterExpansion, "${c:-'}'}"),
                (&SegmentKind::Arithmetic, "$((1+(2)))"),
                (&SegmentKind::Arithmetic, "$[3]"),
                (&SegmentKind::Parameter, "$?"),
                (&SegmentKind::Parameter, "$1"),
                (&SegmentKind::Literal, "2"),
                (&SegmentKind::Parameter, "$@"),
                (&SegmentKind::Literal, "$"),
            ]
        );
    }

    #[test]
    fn closes_parameter_expansion_at_first_brace() {
        // Bash: `${x:-{a}b}` is `${x:-{a}` followed by `b}`.
        let input = "${x:-{a}b}";
        let word = only_word(input);
        assert_eq!(text(input, word.segments[0].span), "${x:-{a}");
        assert_eq!(text(input, word.segments[1].span), "b}");
    }

    #[test]
    fn arithmetic_that_does_not_close_is_a_subshell_substitution() {
        let input = "$( (a) )";
        let word = only_word(input);
        assert_eq!(kinds(&word.segments), [&SegmentKind::CommandSubstitution]);
        let input = "$((a) | b)";
        let word = only_word(input);
        assert_eq!(kinds(&word.segments), [&SegmentKind::CommandSubstitution]);
        assert_eq!(text(input, word.segments[0].body), "(a) | b");
    }

    #[test]
    fn finds_end_of_command_substitution_by_lexing_its_body() {
        // A quoted or commented `)` and a `case` pattern do not close the substitution.
        for input in [
            "$(echo ')')",
            "$(echo \")\")",
            "$(echo \\))",
            "$(echo a # )\n)",
            "$(case x in a) b;; esac)",
            "$(case x in (a) b;; esac)",
            "$(if a; then case x in a|b) c;; esac; fi)",
            "$(echo $(a) `b)`)",
        ] {
            let word = only_word(input);
            assert_eq!(kinds(&word.segments), [&SegmentKind::CommandSubstitution], "{input:?}");
        }
        // `case` as an argument opens nothing.
        let input = "$(echo case) x";
        assert_eq!(words(&lex(input).unwrap()).len(), 2);
    }

    #[test]
    fn refuses_comments_that_bash_3_2_reads_as_commands() {
        // FR-LC-02: bash 3.2 starts a comment in `$( … )` only after a blank or a newline, and never in `<( … )`;
        // later versions start one at any token start. Checked against /bin/bash 3.2: each of these runs the part
        // marked `x` that the full grammar reads as a comment, so the line is refused rather than lexed either way.
        for (input, at) in [
            ("echo $(a;#) ; x\n)", 9),
            ("echo $(#) $(x)\n)", 7),
            ("echo \"$(a&#) $(x)\n)\"", 10),
            ("echo $(a;\\\n#) ; x\n)", 11),
            ("echo $( (#) ; x\n))", 9),
            ("cat <(a #) $(x)\n)", 8),
            ("cat <(a $(b #) $(x)\n))", 12),
        ] {
            assert_eq!(
                lex(input).unwrap_err(),
                LexError::AmbiguousComment {
                    span: Span::new(at, at + 1)
                },
                "{input:?}"
            );
        }
        // Both versions read a comment after a blank or newline (or a continuation after one), and at top level.
        for input in [
            "echo $(a #) x\n)",
            "echo $(a\t#)\n)",
            "echo $(a\n#) x\n)",
            "echo $(a \\\n#)\n)",
            "a;#b",
        ] {
            assert!(lex(input).is_ok(), "{input:?}");
        }
    }

    #[test]
    fn case_patterns_close_only_at_their_own_parenthesis_level() {
        // A `case` inside a subshell inside `$( … )`: its pattern `)` must not close the subshell (bash 4+).
        let input = "$( (case x in a) b;; esac) ; c ) d";
        let tokens = lex(input).unwrap();
        let found = words(&tokens);
        assert_eq!(found.len(), 2, "{tokens:#?}");
        assert_eq!(text(input, found[0].segments[0].body), " (case x in a) b;; esac) ; c ");
    }

    #[test]
    fn lexes_backticks_and_process_substitutions() {
        let input = r"`a \` b`";
        let word = only_word(input);
        assert_eq!(kinds(&word.segments), [&SegmentKind::Backtick]);
        assert_eq!(text(input, word.segments[0].body), r"a \` b");
        // Process substitution, even in the middle of a word (bash 3.2: `a<(true)` is one word).
        let input = "a<(b)>(c)";
        let word = only_word(input);
        assert_eq!(
            kinds(&word.segments),
            [
                &SegmentKind::Literal,
                &SegmentKind::InputProcessSubstitution,
                &SegmentKind::OutputProcessSubstitution
            ]
        );
    }

    #[test]
    fn lexes_escapes_and_locale_quotes() {
        let input = "\\é\\ $\"a $b\" \"\\x \\$\"";
        let tokens = lex(input).unwrap();
        let found = words(&tokens);
        assert_eq!(found.len(), 2);
        assert_eq!(text(input, found[0].segments[0].body), "é");
        assert_eq!(text(input, found[0].segments[1].body), " ");
        let SegmentKind::Locale(inner) = &found[0].segments[2].kind else {
            panic!("not a locale quote: {:?}", found[0]);
        };
        assert_eq!(kinds(inner), [&SegmentKind::Literal, &SegmentKind::Parameter]);
        // In double quotes `\x` is literal and `\$` is an escape; `$'` is not a quote there.
        let SegmentKind::DoubleQuoted(inner) = &found[1].segments[0].kind else {
            panic!("not double quoted: {:?}", found[1]);
        };
        assert_eq!(kinds(inner), [&SegmentKind::Literal, &SegmentKind::Escape]);
        let word = only_word("\"$'x'\"");
        let SegmentKind::DoubleQuoted(inner) = &word.segments[0].kind else {
            panic!("not double quoted: {word:?}");
        };
        assert_eq!(kinds(inner), [&SegmentKind::Literal]);
        // A backslash at the very end escapes nothing.
        let word = only_word("a\\");
        assert_eq!(kinds(&word.segments), [&SegmentKind::Literal, &SegmentKind::Escape]);
        assert!(word.segments[1].body.is_empty());
    }

    #[test]
    fn refuses_here_document_bodies_until_they_are_supported() {
        // KNSH-031 reads bodies; until then a body must never be lexed as commands.
        let error = lex("cat <<EOF\nrm -rf /\nEOF").unwrap_err();
        assert_eq!(error, LexError::HereDocumentBody { span: Span::new(4, 6) });
        let error = lex("x=$(cat <<EOF\nbody\nEOF\n)").unwrap_err();
        assert!(matches!(error, LexError::HereDocumentBody { .. }));
        // A here-string has no body.
        assert!(lex("cat <<<word\nls").is_ok());
    }

    #[test]
    fn errors_do_not_echo_input() {
        // NFR-PRIV-02: messages carry offsets and limits only.
        let error = lex("echo 'sk-secret").unwrap_err();
        assert!(!error.to_string().contains("secret"));
    }
}
