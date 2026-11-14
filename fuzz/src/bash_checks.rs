//! The properties of the `bash_lex` (KNSH-028, KNSH-031) and `bash_parse` (KNSH-029, KNSH-030, KNSH-031) fuzz targets
//! (`specs/07-testing/fuzzing.md`, NFR-SEC-05).
//!
//! Also compiled on stable by `crates/knsh-bash/tests/fuzz_regressions.rs`, which includes this file by path, so it
//! depends on nothing but `knsh-bash` and `std`. A failed property panics, which libFuzzer records as a crash.

use knsh_bash::{
    Command, CommandWord, CompoundCommand, CompoundKind, Construct, LexError, ListItem, LoopBody, LoopCommand,
    MAX_INPUT_LEN, MAX_TOKENS, Operator, ParseError, ParseOutcome, Redirect, RedirectionOperator, Script, Segment,
    SegmentKind, SimpleCommand, Span, Substitution, Token, TokenKind, lex, parse, parse_line,
};

/// `bash_lex`: the lexer never panics and is deterministic. An accepted line is tiled exactly by its token spans
/// (FR-LC-02: nothing hides between tokens), each word by its segments and each double-quoted body by its inner
/// segments; every span lies on character boundaries; operators, blanks, newlines and comments cover exactly the
/// text they name; a here-document body follows a newline, belongs to an earlier `<<` or `<<-`, and its segments
/// tile its body. A rejection points inside the input (an unterminated construct runs to the end of the input or of
/// the here-document body holding it), and the size rejection happens exactly when the input is over the limit.
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
    let mut previous: Option<&TokenKind> = None;
    for token in &tokens {
        assert_eq!(token.span.start, end, "gap or overlap between tokens");
        assert!(token.span.end > token.span.start, "empty token");
        end = token.span.end;
        let text = span_text(input, token.span);
        let logical = text.replace("\\\n", "");
        let after = previous.replace(&token.kind);
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
            TokenKind::HereDocumentBody(body) => {
                assert!(
                    matches!(after, Some(TokenKind::Newline | TokenKind::HereDocumentBody(_))),
                    "here-document body not after a newline"
                );
                assert_eq!(
                    token.span,
                    Span::new(body.body.start, body.delimiter.end),
                    "body token span"
                );
                assert_eq!(body.body.end, body.delimiter.start, "delimiter right after the body");
                assert!(body.operator.end <= token.span.start, "body before its operator");
                let operator = span_text(input, body.operator).replace("\\\n", "");
                assert!(
                    operator.ends_with(if body.strip_tabs { "<<-" } else { "<<" }),
                    "body of something other than a here-document operator"
                );
                assert!(
                    body.body.is_empty() || span_text(input, body.body).ends_with('\n'),
                    "partial body line"
                );
                tiles(input, &body.segments, body.body);
                if body.quoted {
                    assert!(
                        body.segments.iter().all(|segment| segment.kind == SegmentKind::Literal),
                        "quoted body not literal"
                    );
                }
            }
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
        LexError::Unterminated { span, construct } => {
            // To the end of the input, or of the here-document body (or backtick body, once parsed) holding it.
            assert!(!span_text(input, *span).is_empty(), "empty unterminated construct");
            if *construct == Construct::HereDocument {
                assert!(
                    span_text(input, *span).replace("\\\n", "").contains("<<"),
                    "unterminated here-document without an operator"
                );
            }
        }
        LexError::NestingTooDeep { span, .. } => {
            assert!(!span_text(input, *span).is_empty(), "empty opener");
        }
        LexError::TooManyTokens { span, limit } => {
            assert!(
                *limit == MAX_TOKENS && !span_text(input, *span).is_empty(),
                "wrong token-count rejection"
            );
        }
        LexError::AmbiguousHereDocument { span } => {
            let operator = span_text(input, *span).replace("\\\n", "");
            assert!(
                operator.ends_with("<<") || operator.ends_with("<<-"),
                "not a here-document operator"
            );
        }
        LexError::HereDocumentDelimiter { span } => {
            assert!(!span_text(input, *span).is_empty(), "empty delimiter word");
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

/// `bash_parse`: the parser never panics and is deterministic, and it fails whenever the lexer does, with the same
/// error (it may also fail on a lexer error inside a substitution body, which the line's lexer only delimits). A
/// rejection points inside the input. An accepted line loses nothing (FR-LC-02, FR-LC-09): every word token of the
/// line is claimed exactly once, by a part of a simple command, a reserved word, pattern or loop word of a compound
/// command, a function's `function` or name, or a `!`, unless it lies inside an unsupported construct, which is kept
/// whole; every redirection token is likewise one redirection, and every here-document body exactly one
/// here-document. Each part lies inside the command that claims it, simple commands of one script come in source
/// order without overlapping, and every function call names earlier definitions of the line. Every substitution's
/// script (KNSH-031) satisfies the same structure in the text it indexes, lies inside its substitution, and marks no
/// function call; every command the deep iterators yield has a span inside the text paired with it; only
/// here-documents and here-strings are ever marked as feeding an interpreter.
pub fn bash_parse(data: &[u8]) {
    let input = String::from_utf8_lossy(data);
    let input = input.as_ref();
    let result = parse(input);
    assert_eq!(result, parse(input), "parsing is not deterministic");
    check_outcome(input, &result);
    match (result, lex(input)) {
        (Err(ParseError::Lex(error)), Err(lex_error)) => {
            assert_eq!(error, lex_error, "parser reports a different lexer error");
        }
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
            claims.check_order();
            claims.check(input, &tokens);
            check_function_calls(&script);
            for (source, command) in script.commands_with_source(input) {
                assert!(!span_text(source, command.span()).is_empty(), "empty command");
            }
        }
    }
}

/// The fallback (KNSH-032): `parse_line` never panics, is deterministic and agrees with `parse`. A rejected line is
/// dynamic as a whole, never exact, with one part placed inside the line; a parsed line keeps its script, and every
/// dynamic part of it lies inside the line on character boundaries, in source order.
fn check_outcome(input: &str, result: &Result<Script, ParseError>) {
    let outcome = parse_line(input);
    assert_eq!(outcome, parse_line(input), "parse_line is not deterministic");
    match (result, &outcome) {
        (Err(_), ParseOutcome::Exact(_)) => panic!("parser error became exact"),
        (Err(_), ParseOutcome::Dynamic(dynamic)) => {
            assert!(dynamic.is_whole_line(), "rejected line kept a script");
            assert_eq!(dynamic.parts().len(), 1, "rejected line has one part");
        }
        (Ok(script), ParseOutcome::Exact(exact)) => assert_eq!(exact.script(), script, "exact script differs"),
        (Ok(script), ParseOutcome::Dynamic(dynamic)) => {
            assert_eq!(dynamic.script(), Some(script), "dynamic script differs");
            assert!(!dynamic.parts().is_empty(), "dynamic line without parts");
        }
    }
    let mut previous = 0;
    for part in outcome.dynamic_parts() {
        span_text(input, part.span);
        assert!(part.span.start >= previous, "dynamic parts out of order");
        previous = part.span.start;
    }
}

/// What the tree claims of the line's tokens.
#[derive(Default)]
struct Claims {
    /// Word tokens claimed, by span.
    words: Vec<Span>,
    /// Redirection tokens claimed, by where they start.
    redirections: Vec<usize>,
    /// Here-document body tokens claimed, by span.
    here_documents: Vec<Span>,
    /// Unsupported constructs, which claim every token inside them.
    opaque: Vec<Span>,
    /// The simple commands of this script (not of its substitutions), in tree order.
    simple_commands: Vec<Span>,
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
            Command::Simple(simple) => self.simple(input, simple),
            Command::Compound(compound) => self.compound(input, compound),
            Command::FunctionDefinition(definition) => {
                if let Some(keyword) = definition.keyword {
                    self.keyword(input, keyword, span, "function");
                }
                self.word(input, &definition.name, span);
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

    fn simple(&mut self, input: &str, command: &SimpleCommand) {
        self.simple_commands.push(command.span);
        assert!(
            command.function_call.is_none() || command.name().is_some(),
            "function call without a name"
        );
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
            substitutions(input, &assignment.substitutions, assignment.span);
        }
        for word in &command.words {
            self.word(input, word, command.span);
        }
        self.redirects(input, &command.redirections, command.span);
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
                self.word(input, &command.variable, span);
                if let Some(items) = &command.items {
                    self.keyword(input, items.keyword, span, "in");
                    for word in &items.words {
                        self.word(input, word, span);
                    }
                }
                self.loop_body(input, &command.body, span);
            }
            CompoundKind::While(command) => self.loop_command(input, command, span, "while"),
            CompoundKind::Until(command) => self.loop_command(input, command, span, "until"),
            CompoundKind::Case(command) => {
                self.keyword(input, command.keyword, span, "case");
                self.word(input, &command.subject, span);
                self.keyword(input, command.in_keyword, span, "in");
                for clause in &command.clauses {
                    assert!(!clause.patterns.is_empty(), "case arm without a pattern");
                    for pattern in &clause.patterns {
                        self.word(input, pattern, span);
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
        self.redirects(input, &compound.redirections, span);
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

    fn word(&mut self, input: &str, word: &CommandWord, parent: Span) {
        inside(word.span, parent);
        self.words.push(word.span);
        substitutions(input, &word.substitutions, word.span);
    }

    fn redirects(&mut self, input: &str, redirections: &[Redirect], parent: Span) {
        for redirect in redirections {
            inside(redirect.span, parent);
            assert_eq!(
                redirect.span.end, redirect.target.span.end,
                "redirection ends at its target"
            );
            self.words.push(redirect.target.span);
            substitutions(input, &redirect.target.substitutions, redirect.target.span);
            // The redirection token runs from the redirection's start to just before its target.
            self.redirections.push(redirect.span.start);
            let here_document = matches!(
                redirect.operator,
                RedirectionOperator::HereDocument | RedirectionOperator::HereDocumentStripTabs
            );
            assert_eq!(here_document, redirect.here_document.is_some(), "here-document body");
            if redirect.feeds_interpreter {
                assert!(
                    here_document || redirect.operator == RedirectionOperator::HereString,
                    "only a here-document or here-string feeds an interpreter"
                );
            }
            if let Some(document) = &redirect.here_document {
                assert!(redirect.target.substitutions.is_empty(), "delimiter expanded");
                let span = Span::new(document.body.start, document.delimiter.end);
                assert!(span.start >= redirect.span.end, "body before its operator");
                tiles(input, &document.segments, document.body);
                assert!(
                    !document.quoted || document.substitutions.is_empty(),
                    "quoted body runs commands"
                );
                substitutions(input, &document.substitutions, document.body);
                self.here_documents.push(span);
            }
        }
    }

    /// The simple commands of this script come in source order without overlapping.
    fn check_order(&self) {
        let mut previous_end = 0;
        for span in &self.simple_commands {
            assert!(!span.is_empty(), "empty simple command");
            assert!(
                span.start >= previous_end,
                "simple commands overlap or are out of order"
            );
            previous_end = span.end;
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
        let mut here_documents = Vec::new();
        for token in tokens {
            match token.kind {
                TokenKind::Word(_) if !covered(token.span) => words.push(token.span),
                TokenKind::Redirection(_) if !covered(token.span) => redirections.push(token.span.start),
                // Never covered: a body whose operator lies in an unsupported construct is refused.
                TokenKind::HereDocumentBody(_) => here_documents.push(token.span),
                TokenKind::Word(_)
                | TokenKind::Redirection(_)
                | TokenKind::Operator(_)
                | TokenKind::Newline
                | TokenKind::Blank
                | TokenKind::Comment => {}
            }
        }
        self.here_documents.sort_by_key(|span| span.start);
        assert_eq!(
            self.here_documents, here_documents,
            "here-document bodies dropped, duplicated or invented"
        );
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

/// Each function call names earlier definitions of the line.
fn check_function_calls(script: &Script) {
    let definitions: Vec<Span> = script
        .function_definitions()
        .map(|definition| definition.span)
        .collect();
    for command in script.simple_commands() {
        if let Some(call) = &command.function_call {
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

/// Each substitution's script, in the text it indexes (`input`, or the substitution's own text), has the structure
/// of a line, lies inside the substitution (which lies inside `parent`), and marks no function call.
fn substitutions(input: &str, substitutions: &[Substitution], parent: Span) {
    for substitution in substitutions {
        inside(substitution.span, parent);
        span_text(input, substitution.span);
        let source = substitution.source(input);
        match &substitution.text {
            Some(text) => assert_eq!(
                substitution.script.span,
                Span::new(0, text.len()),
                "un-escaped script span"
            ),
            None => inside(substitution.script.span, substitution.span),
        }
        span_text(source, substitution.script.span);
        let mut claims = Claims::default();
        claims.list(source, &substitution.script.items, substitution.script.span);
        claims.check_order();
        for command in substitution.script.simple_commands() {
            assert!(
                command.function_call.is_none(),
                "function call marked inside a substitution"
            );
        }
    }
}
