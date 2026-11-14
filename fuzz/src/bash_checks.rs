//! The properties of the `bash_lex` (KNSH-028) and `bash_parse` (KNSH-029) fuzz targets
//! (`specs/07-testing/fuzzing.md`, NFR-SEC-05).
//!
//! Also compiled on stable by `crates/knsh-bash/tests/fuzz_regressions.rs`, which includes this file by path, so it
//! depends on nothing but `knsh-bash` and `std`. A failed property panics, which libFuzzer records as a crash.

use knsh_bash::{
    LexError, MAX_INPUT_LEN, Operator, ParseError, RedirectionOperator, Segment, SegmentKind, SimpleCommand, Span,
    TokenKind, lex, parse,
};

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

/// `bash_parse`: the parser never panics and is deterministic, and it fails exactly when the lexer does with the same
/// error. A rejection points inside the input. An accepted line loses nothing (FR-LC-02, FR-LC-09): every word token
/// of the line is exactly one assignment, command word or redirection target of exactly one simple command, every
/// redirection token is one redirection, the simple commands come in source order without overlapping, and each one's
/// parts lie inside its span.
pub fn bash_parse(data: &[u8]) {
    let input = String::from_utf8_lossy(data);
    let input = input.as_ref();
    let result = parse(input);
    assert_eq!(result, parse(input), "parsing is not deterministic");
    match (result, lex(input)) {
        (Err(ParseError::Lex(error)), Err(lex_error)) => {
            assert_eq!(error, lex_error, "parser reports a different lexer error");
        }
        (Err(ParseError::Lex(_)), Ok(_)) => panic!("lexer error reported for a line that lexes"),
        (Ok(_) | Err(_), Err(_)) => panic!("line parsed past a lexer error"),
        (Err(error), Ok(_)) => {
            let span = error
                .span()
                .unwrap_or_else(|| panic!("parser error without a span: {error:?}"));
            span_text(input, span);
        }
        (Ok(script), Ok(tokens)) => {
            assert_eq!(script.span, Span::new(0, input.len()), "script span");
            let mut words = Vec::new();
            let mut redirections = Vec::new();
            for token in &tokens {
                match token.kind {
                    TokenKind::Word(_) => words.push(token.span),
                    TokenKind::Redirection(_) => redirections.push(token.span),
                    TokenKind::Operator(_) | TokenKind::Newline | TokenKind::Blank | TokenKind::Comment => {}
                }
            }
            // A `!` that negates a pipeline is a word token too; it belongs to the pipeline, not to a command.
            let negations: Vec<Span> = script
                .items
                .iter()
                .flat_map(|item| item.and_or.pipelines())
                .filter_map(|pipeline| pipeline.negation)
                .collect();
            for bang in &negations {
                assert_eq!(span_text(input, *bang).replace("\\\n", ""), "!", "negation is not `!`");
            }
            let commands: Vec<&SimpleCommand> = script.simple_commands().collect();
            check_commands(input, &commands, negations, &words, &redirections);
        }
    }
}

/// The `bash_parse` properties of an accepted line's simple commands. `negations` are the word tokens the pipelines
/// claimed for `!`; together with every command's words they must be exactly the line's word tokens, in order.
fn check_commands(
    input: &str,
    commands: &[&SimpleCommand],
    negations: Vec<Span>,
    words: &[Span],
    redirections: &[Span],
) {
    let mut seen_words = negations;
    let mut seen_redirections: Vec<Span> = Vec::new();
    let mut previous_end = 0;
    for command in commands {
        span_text(input, command.span);
        assert!(
            command.span.start >= previous_end,
            "simple commands overlap or are out of order"
        );
        assert!(!command.span.is_empty(), "empty simple command");
        previous_end = command.span.end;
        let inside = |span: Span| {
            assert!(
                span.start >= command.span.start && span.end <= command.span.end,
                "part outside its simple command"
            );
        };
        for assignment in &command.assignments {
            inside(assignment.span);
            assert!(assignment.value.start > assignment.span.start && assignment.value.end == assignment.span.end);
            let mut name = assignment.name.bytes();
            assert!(
                name.next()
                    .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic()),
                "assignment name"
            );
            assert!(
                name.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()),
                "assignment name"
            );
            seen_words.push(assignment.span);
        }
        for word in &command.words {
            inside(word.span);
            seen_words.push(word.span);
        }
        for redirect in &command.redirections {
            inside(redirect.span);
            assert_eq!(
                redirect.span.end, redirect.target.span.end,
                "redirection ends at its target"
            );
            seen_words.push(redirect.target.span);
            // The redirection token runs from the redirection's start to just before its target.
            seen_redirections.push(redirect.span);
        }
    }
    seen_words.sort_by_key(|span| span.start);
    assert_eq!(seen_words, words, "word tokens dropped, duplicated or invented");
    assert_eq!(
        seen_redirections.len(),
        redirections.len(),
        "redirection tokens dropped or invented"
    );
    for (redirect, token) in seen_redirections.iter().zip(redirections) {
        assert_eq!(redirect.start, token.start, "redirection out of place");
    }
}
