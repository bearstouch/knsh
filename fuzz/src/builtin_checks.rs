//! The properties of the `builtin_conditional` fuzz target (KNSH-102, `specs/07-testing/fuzzing.md`, NFR-SEC-05):
//! the native interpreter's readers of `[[ … ]]`, `test` arguments, `printf` formats and `read` input.
//!
//! Also compiled on stable by `crates/knsh-interp/tests/fuzz_regressions.rs`, which includes this file by path, so it
//! depends on nothing but `knsh-bash`, `knsh-interp`, `knsh-platform` (its `testing` fakes) and `std`. A failed
//! property panics, which libFuzzer records as a crash.

use std::path::Path;
use std::sync::Arc;

use knsh_bash::parse;
use knsh_interp::{InterpError, Interpreter, ShellState};
use knsh_platform::Fs;
use knsh_platform::testing::{FakeCollation, FakeDescriptors, FakeLocalTime, FakeUserHomes, MemFs, ScriptedCommands};

/// Longest text tried: each run stays fast.
const MAX_TEXT: usize = 1024;

/// What one run produced: its result, what the shell wrote and the variables it set.
type Outcome = (Result<u8, InterpError>, Vec<u8>, Vec<Option<String>>);

/// A writer the test reads back.
#[derive(Clone, Default)]
struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `line` over a small filesystem, with `input` as standard input.
fn run(line: &str, input: &[u8]) -> Option<Outcome> {
    let script = parse(line).ok()?;
    let fs = Arc::new(MemFs::new());
    for dir in ["/bin", "/w/d"] {
        fs.add_dir_all(Path::new(dir)).expect("directory");
    }
    fs.write(Path::new("/w/f"), b"data\nmore\n", 0o644).expect("file");
    let files: Arc<dyn Fs> = fs.clone();
    let descriptors = Arc::new(FakeDescriptors::new(fs));
    let stdin = descriptors.input(input, false).expect("input");
    let stdout = descriptors.input(b"", false).expect("output");
    let stderr = descriptors.input(b"", false).expect("error");
    let mut state = ShellState::new("knsh", "/w")
        .expect("absolute directory")
        .with_environment([("PATH".into(), "/bin".into())]);
    for (name, value) in [("x", "a b"), ("e", ""), ("n", "3"), ("p", "^(a|b)+$")] {
        state.set_variable(name, value);
    }
    let output = Sink::default();
    let mut interpreter = Interpreter::new(
        state,
        files,
        Arc::new(ScriptedCommands::new()),
        Arc::new(FakeUserHomes::new()),
        Arc::new(FakeCollation::new().with_locale("en_US.UTF-8")),
        descriptors,
        Box::new(std::io::sink()),
    )
    .with_output(Box::new(output.clone()))
    .with_standard_descriptors([stdin, stdout, stderr])
    .with_local_time(Arc::new(FakeLocalTime::new(1_000_000_000)))
    .expect("clock");
    let result = interpreter.run(&script, line).map(knsh_interp::Status::code);
    let written = output
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let variables = ["a", "b", "out", "REPLY"]
        .iter()
        .map(|name| {
            interpreter
                .state()
                .variable(name)
                .map(|value| value.to_string_lossy().into_owned())
        })
        .collect();
    Some((result, written, variables))
}

/// `builtin_conditional`: for any text, `[[ text ]]`, `test text`, `printf -v out text a 1` and `read a b` of the
/// text never panic, never overflow the stack and are deterministic; a run ends in a status or in a refusal, a
/// nesting or expansion limit (never a source mismatch, a lost evaluation thread or a platform failure, which the
/// fakes never give).
pub fn builtin_conditional(data: &[u8]) {
    let Some((&form, text)) = data.split_first() else {
        return;
    };
    if text.len() > MAX_TEXT {
        return;
    }
    let text = String::from_utf8_lossy(text);
    let (line, input) = match form % 4 {
        0 => (format!("[[ {text} ]]"), Vec::new()),
        1 => (format!("test {text}"), Vec::new()),
        2 => (format!("printf -v out {text} a 1 '\"x' 2.5"), Vec::new()),
        _ => ("read a b; read -r -n 3 out; read".to_owned(), text.as_bytes().to_vec()),
    };
    let Some(first) = run(&line, &input) else {
        return;
    };
    let second = run(&line, &input).expect("parsed once, parses again");
    assert_eq!(first, second, "evaluation is not deterministic");
    match &first.0 {
        Ok(_)
        | Err(
            InterpError::Unsupported { .. } | InterpError::DepthExceeded { .. } | InterpError::ExpansionLimit { .. },
        ) => {}
        Err(other) => panic!("unexpected failure: {other:?}"),
    }
}
