//! `knsh-corpus`: the dev-only command line for the agent-command corpus (KNSH-033). Never shipped.
//!
//! ```text
//! knsh-corpus check     [--corpus DIR]
//! knsh-corpus import    --source ID [--format lines|jsonl] [--field a.b.c] [--user NAME]... [--host NAME]...
//!                       [--tag TAG]... [--corpus DIR] FILE
//! knsh-corpus normalise [--user NAME]... [--host NAME]...      (stdin to stdout, one command per line)
//! ```
//!
//! `DIR` defaults to `tests/corpus`. Exit status: 0 on success, 1 when the check or import fails, 2 on a usage error.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use knsh_corpus::check::check_dir;
use knsh_corpus::entry::Tag;
use knsh_corpus::import::{ImportOptions, InputFormat, import};
use knsh_corpus::{CorpusError, Scrub, normalise};

/// The default corpus directory, relative to the workspace root.
const DEFAULT_CORPUS: &str = "tests/corpus";

const USAGE: &str = "\
knsh-corpus check     [--corpus DIR]
knsh-corpus import    --source ID [--format lines|jsonl] [--field a.b.c] [--user NAME]... [--host NAME]...
                      [--tag TAG]... [--corpus DIR] FILE
knsh-corpus normalise [--user NAME]... [--host NAME]...";

/// Parsed command-line options shared by the subcommands.
#[derive(Default)]
struct Args {
    corpus: Option<PathBuf>,
    source: Option<String>,
    format: Option<String>,
    field: Option<String>,
    scrub: Scrub,
    tags: Vec<Tag>,
    file: Option<PathBuf>,
}

fn parse_args(mut words: impl Iterator<Item = String>) -> Result<Args, CorpusError> {
    let mut args = Args::default();
    while let Some(arg) = words.next() {
        let mut value = |name: &str| {
            words
                .next()
                .ok_or_else(|| CorpusError::Usage(format!("{name} needs a value")))
        };
        match arg.as_str() {
            "--corpus" => args.corpus = Some(PathBuf::from(value("--corpus")?)),
            "--source" => args.source = Some(value("--source")?),
            "--format" => args.format = Some(value("--format")?),
            "--field" => args.field = Some(value("--field")?),
            "--user" => args.scrub.users.push(value("--user")?),
            "--host" => args.scrub.hosts.push(value("--host")?),
            "--tag" => args
                .tags
                .push(Tag::parse(&value("--tag")?).map_err(CorpusError::Entry)?),
            other if other.starts_with('-') => return Err(CorpusError::Usage(format!("unknown option {other}"))),
            other if args.file.is_none() => args.file = Some(PathBuf::from(other)),
            other => return Err(CorpusError::Usage(format!("unexpected argument {other}"))),
        }
    }
    Ok(args)
}

fn run_check(args: &Args) -> ExitCode {
    let dir = args.corpus.clone().unwrap_or_else(|| PathBuf::from(DEFAULT_CORPUS));
    match check_dir(&dir) {
        Ok(report) => {
            println!("{} entries in {} files: corpus is clean", report.entries, report.files);
            for (source, count) in &report.by_source {
                println!("  source {source}: {count}");
            }
            for (tag, count) in &report.by_tag {
                println!("  tag {tag}: {count}");
            }
            ExitCode::SUCCESS
        }
        Err(errors) => {
            for error in &errors {
                eprintln!("{error}");
            }
            eprintln!("{} problem(s) in {}", errors.len(), dir.display());
            ExitCode::FAILURE
        }
    }
}

fn run_import(args: Args) -> Result<ExitCode, CorpusError> {
    let source = args
        .source
        .ok_or_else(|| CorpusError::Usage("import needs --source".into()))?;
    let file = args
        .file
        .ok_or_else(|| CorpusError::Usage("import needs a trace FILE".into()))?;
    let format = match (args.format.as_deref().unwrap_or("lines"), args.field) {
        ("lines", None) => InputFormat::Lines,
        ("jsonl", Some(field)) => InputFormat::JsonLines {
            field: field.split('.').map(str::to_owned).collect(),
        },
        ("jsonl", None) => return Err(CorpusError::Usage("--format jsonl needs --field".into())),
        ("lines", Some(_)) => return Err(CorpusError::Usage("--field applies only to --format jsonl".into())),
        (other, _) => return Err(CorpusError::Usage(format!("unknown format {other}"))),
    };
    let options = ImportOptions {
        source,
        format,
        scrub: args.scrub,
        tags: args.tags,
    };
    let dir = args.corpus.unwrap_or_else(|| PathBuf::from(DEFAULT_CORPUS));
    let summary = import(&dir, &file, &options)?;
    println!(
        "read {}, added {}, duplicates {}, rejected {}",
        summary.read, summary.added, summary.duplicates, summary.rejected
    );
    Ok(ExitCode::SUCCESS)
}

fn run_normalise(args: &Args) -> Result<ExitCode, CorpusError> {
    let io = |source| CorpusError::Io {
        path: PathBuf::from("<stdio>"),
        source,
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        writeln!(out, "{}", normalise(&line.map_err(io)?, &args.scrub)).map_err(io)?;
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let mut argv = std::env::args().skip(1);
    let command = argv.next();
    let result = parse_args(argv).and_then(|args| match command.as_deref() {
        Some("check") => Ok(run_check(&args)),
        Some("import") => run_import(args),
        Some("normalise") => run_normalise(&args),
        _ => Err(CorpusError::Usage("expected check, import or normalise".into())),
    });
    match result {
        Ok(code) => code,
        Err(CorpusError::Usage(message)) => {
            eprintln!("knsh-corpus: {message}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("knsh-corpus: {error}");
            ExitCode::FAILURE
        }
    }
}
