//! Reading `[[ … ]]` (KNSH-102): the conditional expression inside the span the parser keeps opaque.
//!
//! The parser ends the construct at the first `]]` word and keeps it whole, as it keeps `(( … ))` (it reads no
//! commands, only words and operators). Its text is lexed again here with the same lexer ([`knsh_bash::lex`]), so
//! word boundaries, quotes and expansions are found exactly as for any command, then read with bash 5.2's grammar
//! (`parse.y`, `cond_expr`):
//!
//! ```text
//! expr := and ( '||' expr )?       and := term ( '&&' and )?
//! term := '(' expr ')' | '!' term | unary-op word | word binary-op word | word
//! ```
//!
//! Operators are recognised on the word as written, so a quoted `"-f"` or `"=="` is an ordinary word, as in bash. A
//! word alone is `-n word`. The right side of `=~` is read as bash's lexer reads a regular expression: `(` … `)` (with
//! blanks inside) and `|` are part of the word; the right side of `==`, `=` and `!=` may hold extended-glob groups
//! (`@(a|b)`) whatever `extglob` says. Anything else bash would report as a syntax error before running the script
//! (`[[ -f ]]`, `[[ a b ]]`, an unbalanced `(` in a regular expression) is refused with
//! [`Unsupported::Conditional`]: the parser cannot report it as bash does, and nothing must run.

use knsh_bash::{Operator, RedirectionOperator, ReservedWord, Span, TokenKind, lex};

use crate::error::{InterpError, Unsupported};
use crate::eval::test::{is_binary_operator, is_unary_operator};

/// How one operand of a conditional is expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperandKind {
    /// A string: expansions, quote removal, no splitting or pathname expansion.
    String,
    /// The right side of `==`, `=` or `!=`: a pattern, extended-glob groups included.
    Pattern,
    /// The right side of `=~`: a POSIX extended regular expression, quoted characters matching themselves.
    Regex,
}

/// One word of a conditional: where it is written in the script and how it is expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Operand {
    /// The word as written (for a regular expression, every token it gathered).
    pub(crate) span: Span,
    /// How it is expanded.
    pub(crate) kind: OperandKind,
}

/// A conditional expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expr {
    /// `! expr`.
    Not(Box<Expr>),
    /// `expr && expr`, the right side evaluated only when the left is true.
    And(Box<Expr>, Box<Expr>),
    /// `expr || expr`, the right side evaluated only when the left is false.
    Or(Box<Expr>, Box<Expr>),
    /// `-op word` (and a word alone, as `-n word`).
    Unary {
        /// The operator, `-f` and so on.
        op: String,
        /// Its argument.
        operand: Operand,
    },
    /// `word op word`.
    Binary {
        /// The operator: `=`, `==`, `!=`, `=~`, `<`, `>` or a `-xx` one.
        op: String,
        /// The left word.
        left: Operand,
        /// The right word.
        right: Operand,
    },
}

impl Expr {
    /// Every operand, in source order.
    pub(crate) fn operands(&self, out: &mut Vec<Operand>) {
        match self {
            Self::Not(inner) => inner.operands(out),
            Self::And(left, right) | Self::Or(left, right) => {
                left.operands(out);
                right.operands(out);
            }
            Self::Unary { operand, .. } => out.push(*operand),
            Self::Binary { left, right, .. } => {
                out.push(*left);
                out.push(*right);
            }
        }
    }
}

/// A `[[ … ]]` read from its span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Conditional {
    /// The expression.
    pub(crate) expr: Expr,
    /// The closing `]]`. Anything after it in the construct's span is a redirection.
    pub(crate) close: Span,
}

/// Deepest nesting of `(`, `!`, `&&` and `||` read: the same bound as the parser's nesting, so a conditional nested
/// past it is refused rather than recursed into without limit.
const MAX_DEPTH: usize = knsh_bash::MAX_NESTING_DEPTH;

/// A token of the conditional, with its span in the script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token<'a> {
    /// A word, with its text as written.
    Word(&'a str, Span),
    /// `&&`.
    And(Span),
    /// `||`.
    Or(Span),
    /// `(`.
    Open(Span),
    /// `)`.
    Close(Span),
    /// `|`, only part of a regular expression or a pattern group.
    Pipe(Span),
    /// `<` or `>`, written alone.
    Compare(&'a str, Span),
    /// Blanks between tokens.
    Blank,
}

impl Token<'_> {
    const fn span(self) -> Option<Span> {
        match self {
            Self::Word(_, span)
            | Self::And(span)
            | Self::Or(span)
            | Self::Open(span)
            | Self::Close(span)
            | Self::Pipe(span)
            | Self::Compare(_, span) => Some(span),
            Self::Blank => None,
        }
    }
}

/// Reads the `[[ … ]]` that `span` covers in `source`.
///
/// # Errors
///
/// [`InterpError::Unsupported`] with [`Unsupported::Conditional`] (at `span`) for anything bash's parser would
/// reject or read differently; [`InterpError::SourceMismatch`] if `span` does not index `source`.
pub(crate) fn parse(source: &str, span: Span) -> Result<Conditional, InterpError> {
    let refuse = || InterpError::Unsupported {
        feature: Unsupported::Conditional,
        span,
    };
    let text = span.text(source).ok_or(InterpError::SourceMismatch { span })?;
    let lexed = lex(text).map_err(|_| refuse())?;
    let at = |inner: Span| Span::new(span.start + inner.start, span.start + inner.end);
    let mut tokens = Vec::new();
    let mut close = None;
    let mut opened = false;
    for token in &lexed {
        let token_span = at(token.span);
        let written = token_span
            .text(source)
            .ok_or(InterpError::SourceMismatch { span: token_span })?;
        let next = match &token.kind {
            TokenKind::Word(word) if !opened => {
                if word.reserved != Some(ReservedWord::DoubleLeftBracket) {
                    return Err(refuse());
                }
                opened = true;
                continue;
            }
            TokenKind::Blank if !opened => continue,
            TokenKind::Word(word) if word.reserved == Some(ReservedWord::DoubleRightBracket) => {
                close = Some(token_span);
                break;
            }
            TokenKind::Word(_) => Token::Word(written, token_span),
            TokenKind::Blank => Token::Blank,
            TokenKind::Operator(Operator::And) => Token::And(token_span),
            TokenKind::Operator(Operator::Or) => Token::Or(token_span),
            TokenKind::Operator(Operator::LeftParen) => Token::Open(token_span),
            TokenKind::Operator(Operator::RightParen) => Token::Close(token_span),
            TokenKind::Operator(Operator::Pipe) => Token::Pipe(token_span),
            TokenKind::Redirection(redirection)
                if redirection.fd.is_none()
                    && matches!(
                        redirection.operator,
                        RedirectionOperator::Input | RedirectionOperator::Output
                    ) =>
            {
                Token::Compare(written, token_span)
            }
            TokenKind::Operator(_)
            | TokenKind::Redirection(_)
            | TokenKind::Newline
            | TokenKind::Comment
            | TokenKind::HereDocumentBody(_) => return Err(refuse()),
        };
        tokens.push(next);
    }
    let close = close.ok_or_else(refuse)?;
    let mut reader = Reader {
        tokens: &tokens,
        pos: 0,
        depth: 0,
    };
    let expr = reader.expr().ok_or_else(refuse)?;
    reader.skip_blanks();
    if reader.pos != tokens.len() {
        return Err(refuse());
    }
    Ok(Conditional { expr, close })
}

/// The recursive reader over the tokens between `[[` and `]]`. Every method returns `None` for a syntax error.
struct Reader<'t, 'a> {
    tokens: &'t [Token<'a>],
    pos: usize,
    depth: usize,
}

impl<'a> Reader<'_, 'a> {
    fn skip_blanks(&mut self) {
        while matches!(self.tokens.get(self.pos), Some(Token::Blank)) {
            self.pos += 1;
        }
    }

    /// The next token that is not a blank, without taking it.
    fn peek(&mut self) -> Option<Token<'a>> {
        self.skip_blanks();
        self.tokens.get(self.pos).copied()
    }

    fn enter(&mut self) -> Option<()> {
        self.depth += 1;
        (self.depth <= MAX_DEPTH).then_some(())
    }

    fn expr(&mut self) -> Option<Expr> {
        self.enter()?;
        let left = self.and()?;
        let result = if let Some(Token::Or(_)) = self.peek() {
            self.pos += 1;
            Expr::Or(Box::new(left), Box::new(self.expr()?))
        } else {
            left
        };
        self.depth -= 1;
        Some(result)
    }

    fn and(&mut self) -> Option<Expr> {
        self.enter()?;
        let left = self.term()?;
        let result = if let Some(Token::And(_)) = self.peek() {
            self.pos += 1;
            Expr::And(Box::new(left), Box::new(self.and()?))
        } else {
            left
        };
        self.depth -= 1;
        Some(result)
    }

    fn term(&mut self) -> Option<Expr> {
        self.enter()?;
        let result = match self.peek()? {
            Token::Open(_) => {
                self.pos += 1;
                let inner = self.expr()?;
                let Token::Close(_) = self.peek()? else {
                    return None;
                };
                self.pos += 1;
                inner
            }
            Token::Word("!", _) => {
                self.pos += 1;
                Expr::Not(Box::new(self.term()?))
            }
            Token::Word(word, _) if is_unary_operator(word) => {
                self.pos += 1;
                let Token::Word(_, operand) = self.peek()? else {
                    return None;
                };
                self.pos += 1;
                Expr::Unary {
                    op: (*word).to_owned(),
                    operand: Operand {
                        span: operand,
                        kind: OperandKind::String,
                    },
                }
            }
            Token::Word(_, left) => {
                self.pos += 1;
                let left = Operand {
                    span: left,
                    kind: OperandKind::String,
                };
                self.binary_rest(left)?
            }
            Token::And(_) | Token::Or(_) | Token::Close(_) | Token::Pipe(_) | Token::Compare(..) | Token::Blank => {
                return None;
            }
        };
        self.depth -= 1;
        Some(result)
    }

    /// After the left word: a binary operator and the right word, or nothing (`-n left`).
    fn binary_rest(&mut self, left: Operand) -> Option<Expr> {
        let op = match self.peek() {
            None | Some(Token::And(_) | Token::Or(_) | Token::Close(_)) => {
                return Some(Expr::Unary {
                    op: "-n".to_owned(),
                    operand: left,
                });
            }
            Some(Token::Word(op, _)) if is_binary_operator(op) || op == "=~" => op,
            Some(Token::Compare(op, _)) => op,
            Some(_) => return None,
        };
        self.pos += 1;
        self.skip_blanks();
        let kind = match op {
            "=~" => OperandKind::Regex,
            "=" | "==" | "!=" => OperandKind::Pattern,
            _ => OperandKind::String,
        };
        let span = match kind {
            OperandKind::String => match self.tokens.get(self.pos) {
                Some(Token::Word(_, span)) => {
                    self.pos += 1;
                    *span
                }
                _ => return None,
            },
            OperandKind::Pattern | OperandKind::Regex => self.gathered(kind)?,
        };
        Some(Expr::Binary {
            op: op.to_owned(),
            left,
            right: Operand { span, kind },
        })
    }

    /// The word on the right of `=~` (or of a pattern operator) as bash's lexer reads it: adjacent tokens, a `(`
    /// taking everything up to its matching `)` with blanks, and (in a regular expression) `|`. A pattern's `(`
    /// must follow one of the extended-glob characters `?*+@!`.
    fn gathered(&mut self, kind: OperandKind) -> Option<Span> {
        let start = self.tokens.get(self.pos).copied().and_then(Token::span)?;
        let mut previous: Option<Token<'a>> = None;
        let mut end = start.end;
        while let Some(&token) = self.tokens.get(self.pos) {
            match token {
                Token::Word(..) => {}
                Token::Pipe(_) if kind == OperandKind::Regex => {}
                Token::Open(_) => {
                    let after_glob = matches!(
                        previous,
                        Some(Token::Word(word, _)) if word.ends_with(['?', '*', '+', '@', '!'])
                    );
                    if kind == OperandKind::Pattern && !after_glob {
                        return None;
                    }
                    let close = self.matched_close()?;
                    end = close.end;
                    previous = Some(Token::Close(close));
                    continue;
                }
                Token::Close(_) | Token::And(_) | Token::Or(_) | Token::Pipe(_) | Token::Compare(..) | Token::Blank => {
                    break;
                }
            }
            end = token.span().map_or(end, |span| span.end);
            previous = Some(token);
            self.pos += 1;
        }
        Some(Span::new(start.start, end))
    }

    /// From the `(` at `pos`, past its matching `)`: that `)`'s span.
    fn matched_close(&mut self) -> Option<Span> {
        let mut depth = 0_usize;
        while let Some(&token) = self.tokens.get(self.pos) {
            self.pos += 1;
            match token {
                Token::Open(_) => depth += 1,
                Token::Close(span) => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(span);
                    }
                }
                Token::Word(..) | Token::And(_) | Token::Or(_) | Token::Pipe(_) | Token::Compare(..) | Token::Blank => {
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Result<Expr, InterpError> {
        parse(text, Span::new(0, text.len())).map(|conditional| conditional.expr)
    }

    fn word<'a>(text: &'a str, operand: &Operand) -> &'a str {
        operand.span.text(text).unwrap()
    }

    // KNSH-102: bash's precedence: `!` binds tightest, then `&&`, then `||`; a word alone is `-n word`.
    #[test]
    fn reads_bash_grammar() {
        let text = "[[ ! -f x || a == b && ( c ) ]]";
        let Expr::Or(left, right) = read(text).unwrap() else {
            panic!()
        };
        assert!(matches!(*left, Expr::Not(ref inner) if matches!(**inner, Expr::Unary { ref op, .. } if op == "-f")));
        let Expr::And(compare, group) = *right else { panic!() };
        assert!(
            matches!(*compare, Expr::Binary { ref op, right, .. } if op == "==" && right.kind == OperandKind::Pattern)
        );
        assert!(matches!(*group, Expr::Unary { ref op, operand } if op == "-n" && word(text, &operand) == "c"));
    }

    // KNSH-102: the right side of `=~` keeps parentheses (with blanks inside) and `|`; quoted operators are words.
    #[test]
    fn regex_words_gather_like_bash() {
        let text = "[[ $x =~ ^(a b|c)+$ && \"-f\" ]]";
        let Expr::And(regex, quoted) = read(text).unwrap() else {
            panic!()
        };
        let Expr::Binary { right, .. } = *regex else { panic!() };
        assert_eq!(word(text, &right), "^(a b|c)+$");
        assert_eq!(right.kind, OperandKind::Regex);
        assert!(matches!(*quoted, Expr::Unary { ref op, .. } if op == "-n"));
        let text = "[[ ab == @(a|b)b ]]";
        let Expr::Binary { right, .. } = read(text).unwrap() else {
            panic!()
        };
        assert_eq!(word(text, &right), "@(a|b)b");
        let text = "[[ a < b ]] 2>/dev/null";
        let conditional = parse(text, Span::new(0, text.len())).unwrap();
        assert_eq!(conditional.close.text(text), Some("]]"));
    }

    // KNSH-102: what bash rejects when parsing is refused before anything runs.
    #[test]
    fn syntax_errors_are_refused() {
        for text in [
            "[[ ]]",
            "[[ -f ]]",
            "[[ a b ]]",
            "[[ a =~ ( ]]",
            "[[ ( a ]]",
            "[[ a == (b) ]]",
            "[[ a && ]]",
            "[[ a ; b ]]",
            "f() [[ a ]]",
        ] {
            assert!(
                matches!(
                    read(text),
                    Err(InterpError::Unsupported {
                        feature: Unsupported::Conditional,
                        ..
                    })
                ),
                "{text}"
            );
        }
    }
}
