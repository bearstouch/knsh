//! In-house bash parser and classifier.
//!
//! Parses bash command lines and classifies wrappers, dynamic code and irreversible actions. Anything it cannot read
//! with confidence is classified as dynamic code, so parser gaps fail closed.
//!
//! The first stage is the lexer, [`lex`] (KNSH-028): it turns a whole agent command line into [`Token`]s with exact
//! byte spans, so the supervisor parses every part of the line (FR-LC-02). It reads words with their quoting
//! structure, control and redirection operators, comments, newlines and every quoting form decision 6 puts in scope
//! (single and double quotes, `$'…'`, `$"…"`, backslash escapes, line continuations), and finds the extent of each
//! substitution (`$( … )`, backticks, `${ … }`, `$(( … ))`, `<( … )`) without expanding anything. Reserved words
//! are only marked as candidates; whether they act as such depends on position, which the parser decides.
//!
//! The second stage is the parser, [`parse`] (KNSH-029): it builds a [`Script`] of lists (`;`, `&`, newlines),
//! and-or lists (`&&`, `||`), pipelines (`|`, `|&`, `!`) and simple commands, with the assignments before each
//! command separated from its words and redirections attached wherever they were written. Every node keeps its span,
//! and [`Script::simple_commands`] yields every simple command of the line in source order, so policy sees each part
//! of the line (FR-LC-09). It also reads the compound commands decision 6 makes exact (subshells, `{ }` groups, `if`,
//! `for`, `while`, `until`, `case`) and function definitions (KNSH-030). `simple_commands` descends into every
//! condition, body, case arm and function body, and a call that certainly reaches a function defined earlier in the
//! line is marked ([`SimpleCommand::function_call`]), so it is not resolved as a program. Constructs outside decision
//! 6 whose extent is certain (`select`, `[[ … ]]`, `(( … ))`) are kept whole as [`Command::Unsupported`] nodes; other
//! valid bash it does not read (`coproc`, `time` where bash versions read it differently, array assignments) is
//! refused with [`ParseError::Unsupported`] rather than read partly. The `time` keyword at the start of a pipeline
//! is read ([`TimeKeyword`], KNSH-036).
//!
//! Substitutions and here-documents (KNSH-031): every `$( … )`, backtick (un-escaped as bash does first), `<( … )`
//! and `>( … )` in a word, an assignment, a redirection target or an unquoted here-document body is parsed recursively
//! into a nested [`Script`] ([`Substitution`]), and [`Script::simple_commands`] yields its commands too. The lexer
//! reads here-document bodies ([`HereDocumentBody`]: `<<`, `<<-`, quoted and unquoted delimiters, several on one
//! line), the parser attaches each to its redirection ([`HereDocument`]), and a here-document or here-string read by a
//! shell or interpreter is marked for dynamic classification ([`Redirect::feeds_interpreter`]).
//!
//! The fail-closed fallback, [`parse_line`] (KNSH-032), is the entry point for the classifier: it never fails, and
//! turns every line into a [`ParseOutcome`], either [`Exact`] or [`Dynamic`] with a machine-readable
//! [`DynamicReason`] and span for each dynamic part. A line over a limit, with a syntax error or with a construct the
//! parser cannot delimit (`coproc` among them) is dynamic as a whole; a line that parses is dynamic in parts for an
//! unsupported construct, `eval`, `source` or `.`, a command name built from an expansion, or a here-document fed to
//! an interpreter. Only [`parse_line`] can build a `ParseOutcome`, so no parser error reaches [`Exact`].
//!
//! Builtins (KNSH-035): [`is_builtin`] names the commands bash 3.2 runs itself, so the supervisor does not resolve
//! them on `PATH` (FR-LC-03). Later bash builtins are left out, so a program of the same name is never hidden.
//!
//! The classifier, [`classify`] (KNSH-036), starts from a [`ParseOutcome`] and gives every simple command a
//! [`ClassifiedCommand`] with its record class ([`CommandClass`]): known wrappers (`env`, `command`, `exec`, `nice`,
//! `nohup`, `time`, `timeout`, `xargs`) are unwrapped with explicit option grammars, so `env FOO=1 nice -n 5 git
//! push` is decided as `git push` (FR-LC-04), and dynamic code is marked with a closed [`DynamicReason`]: `eval`,
//! `source` of agent-writable or unresolved files, interpreters given code with `-c` or `-e` or reading standard
//! input, names from expansions, and everything [`parse_line`] marks (FR-LC-05, FR-POL-20). Interpreters are data
//! ([`Interpreters`]), matched by the resolved binary's family ([`family_of`]) and extendable by a profile. Name
//! resolution and the trust of sourced files come from the caller through [`Resolver`].
//!
//! Subcommand normalisation, [`normalise`] (KNSH-037): for a trusted binary of a tool in [`SUBCOMMAND_TABLE`] (git,
//! npm, cargo, docker, kubectl and others; static data), global options before the subcommand are skipped and
//! recorded, so `git -c x=y push` is matched as `git push` (FR-POL-15), and the subcommand's network-intent classes
//! ([`NetworkClass`]: `network:none`, `network:fetch`, `network:publish`) are given for host rules (FR-LC-06,
//! FR-NET-03). An option the table does not know, an expansion or an unknown subcommand keeps the raw argv and gives
//! no classes: the subcommand is never guessed.
//!
//! Irreversible actions (KNSH-093): [`BUILTIN_IRREVERSIBLE`] is the list of commands flagged irreversible before
//! they run (FR-IRR-01, FR-IRR-02), matched by policy like `exec.ask` patterns over normalised arguments, and
//! [`curl_reason`] and [`rsync_reason`] read the arguments that decide whether a `curl` writes (`POST`, `PUT`,
//! `PATCH`, `DELETE`) or an `rsync` reaches a remote host. Unknown arguments are flagged (fail closed).
//!
//! Re-serialisation, [`reserialise`] (KNSH-038): the classified line is re-emitted with every command name that
//! resolved to a binary replaced by its absolute canonical path, quoted when needed, and nothing else changed, so the
//! binary that runs is the one that was classified (FR-LC-13). Builtins, function calls and dynamic parts are left
//! as written. The output is parsed again and must keep the line's shape; anything that cannot be replaced safely is a
//! [`ReserialiseError`], and the supervisor denies the line.
//!
//! # Boundaries
//!
//! No workspace or third-party dependencies, no I/O, no global state, no `unsafe`. Input is untrusted (NFR-SEC-05):
//! its size is checked before it is read ([`MAX_INPUT_LEN`]), the tokens of a line are capped ([`MAX_TOKENS`]),
//! recursion is bounded ([`MAX_NESTING_DEPTH`]), the first problem ends the lex or parse with a [`LexError`] or
//! [`ParseError`] (never a guess), and both stages and the fallback are fuzzed (`fuzz/`, targets `bash_lex` and
//! `bash_parse`). [`parse_line`] turns every error into dynamic code, never an allow (decision 6, KNSH-032). A parser
//! result is an intent filter, never a security boundary.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/command-lifecycle.md` (FR-LC-02: parse the whole line with a bash grammar;
//!   FR-LC-04: unwrap known wrappers; FR-LC-05: mark dynamic code; FR-LC-09: policy is evaluated for every part of
//!   the line)
//! - `specs/03-functional-requirements/policy.md` (FR-POL-20, FR-POL-21: dynamic code never inherits classes)
//! - `specs/05-models/execution-record.md` (`argv[].class`) and `specs/05-models/policy-profile.md`
//!   (`exec.interpreters`)
//! - `specs/03-functional-requirements/command-lifecycle.md` (FR-LC-13: run the line with resolved absolute paths;
//!   FR-LC-15: executable rules stop a binary swapped after classification)
//! - `specs/03-functional-requirements/policy.md` (FR-POL-15: subcommand normalisation) and
//!   `specs/03-functional-requirements/network-proxy.md` (FR-NET-03: classes reaching `approval_hosts`)
//! - `specs/03-functional-requirements/irreversible-actions.md` (FR-IRR-01, FR-IRR-02: the built-in list)
//! - `specs/09-reference/decisions.md` (decision 6: parser scope for phase 2)
//! - `specs/04-non-functional-requirements/security.md` (NFR-SEC-05: memory-safe, fuzzed parsers)
//! - `specs/09-reference/defaults-and-limits.md` (the parser limits and their rationale)
//! - `specs/02-architecture/implementation.md`
//! - `specs/07-testing/conformance.md`

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod ast;
mod builtins;
mod classify;
mod error;
mod functions;
mod interpreter_table;
mod interpreters;
mod irreversible;
mod lex;
mod limits;
mod outcome;
mod parse;
mod reserialise;
mod subcommand_table;
mod subcommands;
mod token;
mod wrappers;

pub use ast::{
    AndOr, AndOrOperator, AndOrPart, ArithmeticParts, Assignment, CaseClause, CaseCommand, CaseTerminator,
    CaseTerminatorKind, Command, CommandWord, CompoundCommand, CompoundKind, ElseClause, ForCommand, ForItems,
    FunctionCall, FunctionDefinition, Group, HereDocument, IfClause, IfCommand, ListItem, LoopBody, LoopCommand,
    PipeOperator, Pipeline, PipelinePart, Redirect, Script, Separator, SeparatorKind, SimpleCommand, Subshell,
    Substitution, SubstitutionKind, TimeKeyword, UnsupportedCommand,
};
pub use builtins::is_builtin;
pub use classify::{
    Argument, Classification, ClassifiedCommand, CommandClass, Lookup, Program, Resolver, SourceFile, classify,
};
pub use error::{
    CompoundStart, Construct, InterpreterTableError, LexError, ParseError, ReserialiseError, Unexpected,
    UnsupportedConstruct,
};
pub use interpreter_table::{Interpreter, Interpreters, family_of};
pub use irreversible::{BUILTIN_IRREVERSIBLE, curl_reason, rsync_reason};
pub use lex::lex;
pub use limits::{MAX_FUNCTION_DEFINITIONS, MAX_INPUT_LEN, MAX_NESTING_DEPTH, MAX_TOKENS};
pub use outcome::{Dynamic, DynamicPart, DynamicReason, Exact, ParseOutcome, parse_line};
pub use parse::{ParseOptions, parse, parse_with};
pub use reserialise::reserialise;
pub use subcommand_table::SUBCOMMAND_TABLE;
pub use subcommands::{
    NetworkClass, Normalisation, Normalised, RawReason, SkippedOption, Subcommand, SubcommandTool, normalise,
};
pub use token::{
    HereDocumentBody, IoNumber, Operator, Redirection, RedirectionOperator, ReservedWord, Segment, SegmentKind, Span,
    Token, TokenKind, Word,
};
