//! The properties of the `word_expansion` fuzz target (KNSH-098, `specs/07-testing/fuzzing.md`, NFR-SEC-05).
//!
//! Also compiled on stable by `crates/knsh-interp/tests/fuzz_regressions.rs`, which includes this file by path, so it
//! depends on nothing but `knsh-bash`, `knsh-interp`, `knsh-platform` (its `testing` fakes) and `std`. A failed
//! property panics, which libFuzzer records as a crash.

use std::path::Path;
use std::sync::Arc;

use knsh_bash::{ParseOptions, parse_with};
use knsh_interp::{InterpError, Interpreter, ShellState};
use knsh_platform::testing::{FakeCollation, FakeDescriptors, FakeUserHomes, MemFs, ScriptedCommands};
use knsh_platform::{CommandOutcome, ExitStatus, Fs};

/// Longest word text tried: brace expansion and matching are polynomial, and a short input keeps each run fast.
const MAX_TEXT: usize = 2048;

/// What one run produced: its result and the arguments each command received.
type Outcome = (Result<u8, InterpError>, Vec<Vec<String>>);

/// A working directory `/w` with files, hidden entries, nested directories and a symlink, and `/bin/tool`.
fn files() -> MemFs {
    let fs = MemFs::new();
    for dir in ["/bin", "/w/d/e", "/w/.h", "/w/sp ace"] {
        fs.add_dir_all(Path::new(dir)).expect("directory");
    }
    for file in [
        "/bin/tool",
        "/w/a.rs",
        "/w/B.rs",
        "/w/.env",
        "/w/d/e/f.rs",
        "/w/d/g",
        "/w/sp ace/x",
    ] {
        fs.write(Path::new(file), b"", 0o755).expect("file");
    }
    fs.add_symlink(Path::new("/w/link"), Path::new("/w/d"))
        .expect("symlink");
    fs
}

/// Runs `tool <text>` with the glob options the bits of `flags` set.
fn run(line: &str, flags: u8) -> Option<Outcome> {
    let extglob = flags & 1 != 0;
    let script = parse_with(line, ParseOptions::default().with_extglob(extglob)).ok()?;
    let commands = Arc::new(ScriptedCommands::new());
    commands.on("/bin/tool", CommandOutcome::Finished(ExitStatus::Exited(0)));
    let mut state = ShellState::new("knsh", "/w")
        .expect("absolute directory")
        .with_environment([("PATH".into(), "/bin".into()), ("HOME".into(), "/home".into())])
        .with_positional(vec!["p q".into(), String::new(), "*".into()]);
    for (name, value) in [("x", "a b"), ("g", "*.rs"), ("e", ""), ("c", "a:b::c"), ("n", "3")] {
        state.set_variable(name, value);
    }
    let options = state.options_mut();
    options.extglob = extglob;
    options.globstar = flags & 2 != 0;
    options.dotglob = flags & 4 != 0;
    options.nocaseglob = flags & 8 != 0;
    options.nullglob = flags & 16 != 0;
    options.failglob = flags & 32 != 0;
    options.noglob = flags & 64 != 0;
    if flags & 128 != 0 {
        state.set_variable("IFS", ":");
    }
    let files = Arc::new(files());
    let fs: Arc<dyn Fs> = files.clone();
    let mut interpreter = Interpreter::new(
        state,
        fs,
        commands.clone(),
        Arc::new(FakeUserHomes::new().with_user("u", "/home/u")),
        Arc::new(FakeCollation::new().with_locale("en_US.UTF-8")),
        // Redirections in the text (KNSH-099) open files in the same memory filesystem.
        Arc::new(FakeDescriptors::new(files)),
        Box::new(std::io::sink()),
    );
    let result = interpreter.run(&script, line).map(knsh_interp::Status::code);
    let args = commands
        .runs()
        .into_iter()
        .map(|run| run.args.iter().map(|arg| arg.to_string_lossy().into_owned()).collect())
        .collect();
    Some((result, args))
}

/// `word_expansion`: brace expansion, splitting, pathname expansion and quote removal of any word never panic,
/// never overflow the stack and are deterministic; a run ends in a status or in a refusal, a nesting or expansion
/// limit, or a failed command start (never a source mismatch or a lost evaluation thread); and every argument
/// passed to a command is free of NUL, which no exec could carry.
pub fn word_expansion(data: &[u8]) {
    let Some((&flags, text)) = data.split_first() else {
        return;
    };
    if text.len() > MAX_TEXT {
        return;
    }
    let line = format!("tool {}", String::from_utf8_lossy(text));
    let Some(first) = run(&line, flags) else {
        return;
    };
    let second = run(&line, flags).expect("parsed once, parses again");
    assert_eq!(first, second, "expansion is not deterministic");
    match &first.0 {
        Ok(_)
        | Err(
            InterpError::Unsupported { .. }
            | InterpError::DepthExceeded { .. }
            | InterpError::ExpansionLimit { .. }
            | InterpError::Platform(_),
        ) => {}
        Err(other) => panic!("unexpected failure: {other:?}"),
    }
    for args in &first.1 {
        assert!(
            args.iter().all(|arg| !arg.contains('\0')),
            "NUL in an argument: {args:?}"
        );
    }
}
