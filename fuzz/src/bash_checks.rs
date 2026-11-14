//! The properties of the `bash_lex` (KNSH-028) and `bash_parse` (KNSH-029, KNSH-030) fuzz targets
//! (`specs/07-testing/fuzzing.md`, NFR-SEC-05).
//!
//! Also compiled on stable by `crates/knsh-bash/tests/fuzz_regressions.rs`, which includes this file by path, so it
//! depends on nothing but `knsh-bash` and `std`. A failed property panics, which libFuzzer records as a crash.

use knsh_bash::{
    Command, CommandWord, CompoundCommand, CompoundKind, LexError, ListItem, LoopBody, LoopCommand, MAX_INPUT_LEN,
    Operator, ParseError, Redirect, RedirectionOperator, Script, Segment, SegmentKind, SimpleCommand, Span, Token,
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
/// of the line is claimed exactly once, by a part of a simple command, a reserved word, pattern or loop word of a
/// compound command, a function's `function` or name, or a `!`, unless it lies inside an unsupported construct, which
/// is kept whole; every redirection token is likewise one redirection or inside an unsupported construct. Each part
/// lies inside the command that claims it, simple commands come in source order without overlapping, and every
/// function call names definitions of the line.
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
            let mut claims = Claims::default();
            claims.list(input, &script.items, script.span);
            claims.check(input, &tokens);
            check_simple_commands(input, &script);
        }
    }
}

/// What the tree claims of the line's tokens.
#[derive(Default)]
struct Claims {
    /// Word tokens claimed, by span.
    words: Vec<Span>,
    /// Redirection tokens claimed, by where they start.
    redirections: Vec<usize>,
    /// Unsupported constructs, which claim every token inside them.
    opaque: Vec<Span>,
}

impl Claims {
    fn list(&mut self, input: &str, items: &[ListItem], parent: Span) {
        for item in items {
            inside(item.and_or.span, parent);
            for pipeline in item.and_or.pipelines() {
                inside(pipeline.span, item.and_or.span);
                if let Some(bang) = pipeline.negation {
                    assert_eq!(span_text(input, bang).replace("\\\n", ""), "!", "negation is not `!`");
                    self.words.push(bang);
                }
                for command in pipeline.commands() {
                    inside(command.span(), pipeline.span);
                    self.command(input, command);
                }
            }
        }
    }

    fn command(&mut self, input: &str, command: &Command) {
        let span = command.span();
        span_text(input, span);
        assert!(!span.is_empty(), "empty command");
        match command {
            Command::Simple(simple) => self.simple(simple),
            Command::Compound(compound) => self.compound(input, compound),
            Command::FunctionDefinition(definition) => {
                if let Some(keyword) = definition.keyword {
                    self.keyword(input, keyword, span, "function");
                }
                self.word(&definition.name, span);
                if let Some(parens) = definition.parens {
                    inside(parens, span);
                }
                inside(definition.body.span, span);
                assert_eq!(definition.body.span.end, span.end, "function ends with its body");
                self.compound(input, &definition.body);
            }
            Command::Unsupported(unsupported) => self.opaque.push(unsupported.span),
        }
    }

    fn simple(&mut self, command: &SimpleCommand) {
        for assignment in &command.assignments {
            inside(assignment.span, command.span);
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
            self.words.push(assignment.span);
        }
        for word in &command.words {
            self.word(word, command.span);
        }
        self.redirects(&command.redirections, command.span);
    }

    fn compound(&mut self, input: &str, compound: &CompoundCommand) {
        let span = compound.span;
        match &compound.kind {
            CompoundKind::Subshell(subshell) => {
                inside(subshell.open, span);
                inside(subshell.close, span);
                self.body(input, &subshell.body, span);
            }
            CompoundKind::Group(group) => {
                self.keyword(input, group.open, span, "{");
                self.body(input, &group.body, span);
                self.keyword(input, group.close, span, "}");
            }
            CompoundKind::If(command) => {
                assert!(!command.clauses.is_empty(), "if without a clause");
                for (index, clause) in command.clauses.iter().enumerate() {
                    self.keyword(input, clause.keyword, span, if index == 0 { "if" } else { "elif" });
                    self.body(input, &clause.condition, span);
                    self.keyword(input, clause.then, span, "then");
                    self.body(input, &clause.body, span);
                }
                if let Some(otherwise) = &command.else_clause {
                    self.keyword(input, otherwise.keyword, span, "else");
                    self.body(input, &otherwise.body, span);
                }
                self.keyword(input, command.fi, span, "fi");
            }
            CompoundKind::For(command) => {
                self.keyword(input, command.keyword, span, "for");
                self.word(&command.variable, span);
                if let Some(items) = &command.items {
                    self.keyword(input, items.keyword, span, "in");
                    for word in &items.words {
                        self.word(word, span);
                    }
                }
                self.loop_body(input, &command.body, span);
            }
            CompoundKind::While(command) => self.loop_command(input, command, span, "while"),
            CompoundKind::Until(command) => self.loop_command(input, command, span, "until"),
            CompoundKind::Case(command) => {
                self.keyword(input, command.keyword, span, "case");
                self.word(&command.subject, span);
                self.keyword(input, command.in_keyword, span, "in");
                for clause in &command.clauses {
                    assert!(!clause.patterns.is_empty(), "case arm without a pattern");
                    for pattern in &clause.patterns {
                        self.word(pattern, span);
                    }
                    inside(clause.close, span);
                    self.list(input, &clause.body, span);
                    if let Some(terminator) = clause.terminator {
                        inside(terminator.span, span);
                    }
                }
                self.keyword(input, command.esac, span, "esac");
            }
        }
        self.redirects(&compound.redirections, span);
    }

    fn loop_command(&mut self, input: &str, command: &LoopCommand, parent: Span, keyword: &str) {
        self.keyword(input, command.keyword, parent, keyword);
        self.body(input, &command.condition, parent);
        self.loop_body(input, &command.body, parent);
    }

    fn loop_body(&mut self, input: &str, body: &LoopBody, parent: Span) {
        let open = span_text(input, body.open).replace("\\\n", "");
        let close = if open == "do" { "done" } else { "}" };
        assert!(open == "do" || open == "{", "loop body opener");
        self.keyword(input, body.open, parent, &open);
        self.body(input, &body.body, parent);
        self.keyword(input, body.close, parent, close);
    }

    /// A list inside a compound command, which bash requires to be non-empty.
    fn body(&mut self, input: &str, items: &[ListItem], parent: Span) {
        assert!(!items.is_empty(), "empty compound list");
        self.list(input, items, parent);
    }

    fn keyword(&mut self, input: &str, span: Span, parent: Span, expected: &str) {
        inside(span, parent);
        assert_eq!(
            span_text(input, span).replace("\\\n", ""),
            expected,
            "reserved word text"
        );
        self.words.push(span);
    }

    fn word(&mut self, word: &CommandWord, parent: Span) {
        inside(word.span, parent);
        self.words.push(word.span);
    }

    fn redirects(&mut self, redirections: &[Redirect], parent: Span) {
        for redirect in redirections {
            inside(redirect.span, parent);
            assert_eq!(
                redirect.span.end, redirect.target.span.end,
                "redirection ends at its target"
            );
            self.words.push(redirect.target.span);
            // The redirection token runs from the redirection's start to just before its target.
            self.redirections.push(redirect.span.start);
        }
    }

    /// Every word and redirection token outside an unsupported construct is claimed exactly once, and nothing else is.
    fn check(mut self, input: &str, tokens: &[Token]) {
        for opaque in &self.opaque {
            assert!(!span_text(input, *opaque).is_empty(), "empty unsupported construct");
        }
        let covered = |span: Span| {
            self.opaque
                .iter()
                .any(|opaque| span.start >= opaque.start && span.end <= opaque.end)
        };
        let mut words = Vec::new();
        let mut redirections = Vec::new();
        for token in tokens {
            match token.kind {
                TokenKind::Word(_) if !covered(token.span) => words.push(token.span),
                TokenKind::Redirection(_) if !covered(token.span) => redirections.push(token.span.start),
                TokenKind::Word(_)
                | TokenKind::Redirection(_)
                | TokenKind::Operator(_)
                | TokenKind::Newline
                | TokenKind::Blank
                | TokenKind::Comment => {}
            }
        }
        self.words.sort_by_key(|span| span.start);
        assert_eq!(self.words, words, "word tokens dropped, duplicated or invented");
        self.redirections.sort_unstable();
        assert_eq!(
            self.redirections, redirections,
            "redirection tokens dropped, duplicated, invented or out of place"
        );
    }
}

/// `span` lies within `parent`.
fn inside(span: Span, parent: Span) {
    assert!(
        span.start >= parent.start && span.end <= parent.end,
        "part {span:?} outside its parent {parent:?}"
    );
}

/// Simple commands come in source order without overlapping, and each function call names definitions of the line.
fn check_simple_commands(input: &str, script: &Script) {
    let definitions: Vec<Span> = script
        .function_definitions()
        .map(|definition| definition.span)
        .collect();
    let mut previous_end = 0;
    for command in script.simple_commands() {
        span_text(input, command.span);
        assert!(!command.span.is_empty(), "empty simple command");
        assert!(
            command.span.start >= previous_end,
            "simple commands overlap or are out of order"
        );
        previous_end = command.span.end;
        if let Some(call) = &command.function_call {
            assert!(command.name().is_some(), "function call without a name");
            assert!(!call.definitions.is_empty(), "function call without a definition");
            for definition in &call.definitions {
                assert!(definitions.contains(definition), "function call names no definition");
                assert!(
                    definition.end <= command.span.start,
                    "function call before its definition"
                );
            }
        }
    }
}
