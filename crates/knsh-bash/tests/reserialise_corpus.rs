//! Round-trip property of line re-serialisation over the agent-command corpus (`tests/corpus/`; KNSH-038,
//! FR-LC-13).
//!
//! For every corpus line and several sessions (paths that need no quoting, paths with spaces, paths with quotes and
//! shell metacharacters), the re-serialised line must:
//!
//! - parse with the same outcome (exact or dynamic, with the same reasons);
//! - classify to the same entries: same classes, programs, wrapper links and arguments, with each replaced name now
//!   being its binary's path (the session resolves an absolute name to itself);
//! - differ from the input only at the replaced command names.
//!
//! The only error allowed is a name inside a backtick substitution bash un-escapes, which cannot be placed exactly
//! and fails closed. `knsh-bash` may depend on nothing, so the corpus file format (`specs/07-testing/
//! agent-command-corpus.md`) is read here directly rather than through `knsh-corpus`.

// The whole file is test code, so clippy's `allow-*-in-tests` settings cover the helpers too.
#![cfg(test)]

use std::fs;
use std::path::{Path, PathBuf};

use knsh_bash::{
    Classification, ClassifiedCommand, DynamicPart, Interpreters, Lookup, Program, ReserialiseError, Resolver, Script,
    SourceFile, Span, classify, parse_line, reserialise,
};

/// Every command line of the checked-in corpus, unescaped.
fn corpus_lines() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "txt"))
        .collect();
    files.sort();
    let mut lines = Vec::new();
    for file in files {
        for line in fs::read_to_string(&file).unwrap().lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let command = line
                .splitn(4, '\t')
                .nth(3)
                .unwrap_or_else(|| panic!("malformed entry: {line}"));
            lines.push(unescape(command));
        }
    }
    lines
}

/// Reverses the corpus escapes: `\\`, `\n`, `\t` and `\r`.
fn unescape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            other => panic!("bad escape {other:?} in {field}"),
        }
    }
    out
}

/// A session whose `PATH` binaries all sit in `folder`, with the project `/p` holding `./` scripts. An absolute name
/// resolves to itself, so a re-serialised line resolves exactly as the original did.
struct Session {
    folder: &'static str,
}

impl Resolver for Session {
    fn resolve(&self, name: &str, lookup: Lookup) -> Program {
        if name.starts_with('/') {
            return if name.starts_with("/p/") {
                Program::ProjectExecutable(PathBuf::from(name))
            } else {
                Program::Trusted(PathBuf::from(name))
            };
        }
        if let Some(relative) = name.strip_prefix("./") {
            return Program::ProjectExecutable(Path::new("/p").join(relative));
        }
        if name.contains('/') {
            return Program::ProjectExecutable(Path::new("/p").join(name));
        }
        if lookup == Lookup::Shell && knsh_bash::is_builtin(name) {
            return Program::Builtin;
        }
        Program::Trusted(Path::new(self.folder).join(name))
    }

    fn source_file(&self, _path: &str) -> SourceFile {
        SourceFile::Trusted
    }
}

const SESSIONS: [Session; 3] = [
    Session { folder: "/usr/bin" },
    Session {
        folder: "/Applications/My Tools/bin",
    },
    Session {
        folder: "/opt/it's [a] $b; c|d*",
    },
];

/// The name spans `classification` gives for its entries with a path outside every dynamic part: the names
/// re-serialisation replaces.
fn replaced_spans(classification: &Classification) -> Vec<Span> {
    let mut spans: Vec<Span> = classification
        .commands()
        .iter()
        .filter(|command| command.program.as_ref().is_some_and(|program| program.path().is_some()))
        .filter_map(|command| command.name_span)
        .filter(|span| {
            !classification
                .dynamic_parts()
                .iter()
                .any(|part| part.span.start < span.end && span.start < part.span.end)
        })
        .collect();
    spans.sort_by_key(|span| (span.start, span.end));
    spans.dedup();
    spans
}

/// `text` with every span cut out.
fn without(text: &str, spans: &[Span]) -> String {
    let mut out = String::new();
    let mut at = 0;
    for span in spans {
        out.push_str(&text[at..span.start]);
        at = span.end;
    }
    out.push_str(&text[at..]);
    out
}

// KNSH-038, FR-LC-13: re-serialising every corpus line keeps its AST shape and its simple commands, and changes only
// the replaced command names (property test over the corpus and several path shapes).
#[test]
fn round_trip_preserves_ast_over_corpus() {
    let lines = corpus_lines();
    assert!(lines.len() >= 200, "the corpus shrank: {} lines", lines.len());
    let interpreters = Interpreters::defaults();
    let mut rewritten = 0;
    let mut refused = 0;
    for session in &SESSIONS {
        for line in &lines {
            let outcome = parse_line(line);
            let classification = classify(&outcome, line, session, &interpreters);
            let output = match reserialise(line, &outcome, &classification) {
                Ok(output) => output,
                Err(ReserialiseError::NameNotOnLine { .. }) => {
                    refused += 1;
                    continue;
                }
                Err(error) => panic!("{line:?} in {}: {error}", session.folder),
            };
            let context = format!("{line:?} -> {output:?}");

            let reparsed = parse_line(&output);
            assert_eq!(reparsed.is_exact(), outcome.is_exact(), "{context}");
            let reasons = |parts: &[DynamicPart]| parts.iter().map(|part| part.reason).collect::<Vec<_>>();
            assert_eq!(
                reasons(reparsed.dynamic_parts()),
                reasons(outcome.dynamic_parts()),
                "{context}"
            );
            let simple = |script: Option<&Script>| script.map_or(0, |script| script.simple_commands().count());
            assert_eq!(simple(reparsed.script()), simple(outcome.script()), "{context}");

            let again = classify(&reparsed, &output, session, &interpreters);
            assert_eq!(again.commands().len(), classification.commands().len(), "{context}");
            for (old, new) in classification.commands().iter().zip(again.commands()) {
                assert_eq!(old.class, new.class, "{context}");
                assert_eq!(old.program, new.program, "{context}");
                assert_eq!(old.wrapper, new.wrapper, "{context}");
                assert_eq!(old.arguments_complete, new.arguments_complete, "{context}");
                let texts = |command: &ClassifiedCommand| {
                    command
                        .arguments
                        .iter()
                        .map(|argument| argument.text.clone())
                        .collect::<Vec<_>>()
                };
                assert_eq!(texts(old), texts(new), "{context}");
                let path = old.program.as_ref().and_then(Program::path).and_then(Path::to_str);
                assert!(
                    new.name == old.name || (new.name.as_deref() == path && path.is_some()),
                    "{context}: {:?} became {:?}",
                    old.name,
                    new.name
                );
            }

            // Nothing but the replaced names changed.
            let old_spans = replaced_spans(&classification);
            let new_spans = replaced_spans(&again);
            assert_eq!(old_spans.len(), new_spans.len(), "{context}");
            assert_eq!(without(line, &old_spans), without(&output, &new_spans), "{context}");
            if output != *line {
                rewritten += 1;
            }
        }
    }
    // Most corpus lines run a binary, so most are rewritten; refusals are rare (backticks with escapes).
    assert!(
        rewritten * 2 > lines.len() * SESSIONS.len(),
        "only {rewritten} lines rewritten"
    );
    assert!(refused * 50 < lines.len() * SESSIONS.len(), "{refused} lines refused");
}
