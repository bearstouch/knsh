//! The properties of the `bash_lex` fuzz target (KNSH-028; `specs/07-testing/fuzzing.md`, NFR-SEC-05).
//!
//! Also compiled on stable by `crates/knsh-bash/tests/fuzz_regressions.rs`, which includes this file by path, so it
//! depends on nothing but `knsh-bash` and `std`. A failed property panics, which libFuzzer records as a crash.

use knsh_bash::{LexError, MAX_INPUT_LEN, Operator, RedirectionOperator, Segment, SegmentKind, Span, TokenKind, lex};

/// `bash_lex`: the lexer never panics and is deterministic. An accepted line is tiled exactly by its token spans
/// (FR-LC-02: nothing hides between tokens), each word by its segments and each double-quoted body by its inner
/// segments; every span lies on character boundaries; operators, blanks, newlines and comments cover exactly the
/// text they name. A rejection points inside the input (an unterminated construct runs to its end), and the size
/// rejection happens exactly when the input is over the limit.
pub fn bash_lex(data: &[u8]) {
    // Invalid UTF-8 is replaced rather than skipped, so every fuzzer input exercises the lexer.
    let input = String::from_utf8_lossy(data);
    let input = input.as_ref();
    let result = lex(input);
    assert_eq!(result, lex(input), "lexing is not deterministic");
    let tokens = match result {
        Ok(tokens) => tokens,
        Err(error) => return check_error(input, &error),
    };
    assert!(input.len() <= MAX_INPUT_LEN, "accepted input over the size limit");

    let mut end = 0;
    for token in &tokens {
        assert_eq!(token.span.start, end, "gap or overlap between tokens");
        assert!(token.span.end > token.span.start, "empty token");
        end = token.span.end;
        let text = span_text(input, token.span);
        let logical = text.replace("\\\n", "");
        match &token.kind {
            TokenKind::Word(word) => tiles(input, &word.segments, token.span),
            TokenKind::Operator(operator) => assert_eq!(logical, operator_text(*operator), "operator text"),
            TokenKind::Redirection(redirection) => {
                let operator_start = match redirection.fd {
                    Some(fd) => {
                        assert_eq!(
                            fd.span.start, token.span.start,
                            "descriptor number not at the token start"
                        );
                        let digits = span_text(input, fd.span).replace("\\\n", "");
                        assert!(!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()));
                        assert_eq!(fd.value.is_some(), digits.parse::<i32>().is_ok(), "descriptor value");
                        fd.span.end
                    }
                    None => token.span.start,
                };
                let operator = span_text(input, Span::new(operator_start, token.span.end)).replace("\\\n", "");
                assert_eq!(operator, redirection_text(redirection.operator), "redirection text");
            }
            TokenKind::Newline => assert_eq!(text, "\n"),
            TokenKind::Blank => assert!(logical.bytes().all(|byte| byte == b' ' || byte == b'\t')),
            TokenKind::Comment => assert!(text.starts_with('#') && !text.contains('\n')),
        }
    }
    assert_eq!(end, input.len(), "tokens do not reach the end of the input");
}

fn check_error(input: &str, error: &LexError) {
    match error {
        LexError::InputTooLarge { len, limit } => {
            assert!(
                *len == input.len() && *limit == MAX_INPUT_LEN && len > limit,
                "wrong size rejection"
            );
        }
        LexError::Unterminated { span, .. } => {
            span_text(input, *span);
            assert_eq!(
                span.end,
                input.len(),
                "an unterminated construct runs to the end of the input"
            );
        }
        LexError::NestingTooDeep { span, .. } => {
            assert!(!span_text(input, *span).is_empty(), "empty opener");
        }
        LexError::HereDocumentBody { span } => {
            let operator = span_text(input, *span).replace("\\\n", "");
            assert!(
                operator.ends_with("<<") || operator.ends_with("<<-"),
                "not a here-document operator"
            );
        }
        LexError::AmbiguousComment { span } => {
            assert_eq!(span_text(input, *span), "#", "not a comment start");
        }
    }
}

/// The text of `span`, which must lie inside `input` on character boundaries.
fn span_text(input: &str, span: Span) -> &str {
    assert!(span.start <= span.end, "inverted span {span:?}");
    span.text(input)
        .unwrap_or_else(|| panic!("span {span:?} outside the input or off a character boundary"))
}

/// `segments` tile `span` in order; bodies lie inside their segments; quoted bodies are tiled by their segments.
fn tiles(input: &str, segments: &[Segment], span: Span) {
    let mut end = span.start;
    for segment in segments {
        assert_eq!(segment.span.start, end, "gap or overlap between segments");
        span_text(input, segment.span);
        span_text(input, segment.body);
        assert!(segment.body.start >= segment.span.start && segment.body.end <= segment.span.end);
        end = segment.span.end;
        match &segment.kind {
            SegmentKind::DoubleQuoted(inner) | SegmentKind::Locale(inner) => tiles(input, inner, segment.body),
            SegmentKind::LineContinuation => assert_eq!(span_text(input, segment.span), "\\\n"),
            SegmentKind::Literal
            | SegmentKind::Escape
            | SegmentKind::SingleQuoted
            | SegmentKind::AnsiC
            | SegmentKind::Parameter
            | SegmentKind::ParameterExpansion
            | SegmentKind::CommandSubstitution
            | SegmentKind::Backtick
            | SegmentKind::Arithmetic
            | SegmentKind::InputProcessSubstitution
            | SegmentKind::OutputProcessSubstitution => assert!(!segment.span.is_empty(), "empty segment"),
        }
    }
    assert_eq!(end, span.end, "segments do not cover the word");
}

fn operator_text(operator: Operator) -> &'static str {
    match operator {
        Operator::Pipe => "|",
        Operator::PipeAmpersand => "|&",
        Operator::Or => "||",
        Operator::And => "&&",
        Operator::Background => "&",
        Operator::Semicolon => ";",
        Operator::DoubleSemicolon => ";;",
        Operator::SemicolonAmpersand => ";&",
        Operator::DoubleSemicolonAmpersand => ";;&",
        Operator::LeftParen => "(",
        Operator::RightParen => ")",
    }
}

fn redirection_text(operator: RedirectionOperator) -> &'static str {
    match operator {
        RedirectionOperator::Input => "<",
        RedirectionOperator::Output => ">",
        RedirectionOperator::Append => ">>",
        RedirectionOperator::Clobber => ">|",
        RedirectionOperator::ReadWrite => "<>",
        RedirectionOperator::HereDocument => "<<",
        RedirectionOperator::HereDocumentStripTabs => "<<-",
        RedirectionOperator::HereString => "<<<",
        RedirectionOperator::DuplicateInput => "<&",
        RedirectionOperator::DuplicateOutput => ">&",
        RedirectionOperator::OutputAll => "&>",
        RedirectionOperator::AppendAll => "&>>",
    }
}
