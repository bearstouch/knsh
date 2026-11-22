//! Session tests over a scripted terminal and the fake filesystem (KNSH-107): what the user types, what the
//! terminal shows, what runs and what the history keeps.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use knsh_platform::testing::{FakeCollation, FakeDescriptors, FakeUserHomes, MemFs, ScriptedCommands};
use knsh_platform::{CommandOutcome, ExitStatus, Fs};

use super::*;
use crate::ShellState;

/// Bytes shared with the test.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buffer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// A terminal that delivers `input` one chunk per read, then end of input; what is drawn goes to `screen`.
struct Scripted {
    input: VecDeque<Vec<u8>>,
    screen: Buffer,
    columns: usize,
    editing: bool,
    started: Arc<Mutex<usize>>,
}

impl Terminal for Scripted {
    fn read(&mut self, buffer: &mut [u8], timeout: Option<Duration>) -> io::Result<Option<usize>> {
        let Some(mut chunk) = self.input.pop_front() else {
            return Ok(if timeout.is_some() { None } else { Some(0) });
        };
        let count = chunk.len().min(buffer.len());
        buffer[..count].copy_from_slice(&chunk[..count]);
        if count < chunk.len() {
            self.input.push_front(chunk.split_off(count));
        }
        Ok(Some(count))
    }

    fn write(&mut self, bytes: &[u8]) {
        let _ = std::io::Write::write(&mut self.screen, bytes);
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn start_editing(&mut self) -> bool {
        *self.started.lock().unwrap() += 1;
        self.editing
    }

    fn stop_editing(&mut self) {}
}

struct Harness {
    session: Session<Scripted>,
    screen: Buffer,
    output: Buffer,
    diagnostics: Buffer,
    fs: Arc<MemFs>,
    commands: Arc<ScriptedCommands>,
}

/// A session over the fake filesystem (`/bin/true`, `/bin/cat`, `HOME=/home/ana`) typing `keys`, each a chunk.
fn harness(keys: &[&[u8]], marks: bool, configure: impl FnOnce(&mut Interpreter)) -> Harness {
    let fs = Arc::new(MemFs::new());
    for dir in ["/bin", "/work", "/home/ana"] {
        fs.add_dir_all(Path::new(dir)).unwrap();
    }
    for program in ["true", "cat", "ls"] {
        fs.write(&Path::new("/bin").join(program), b"", 0o755).unwrap();
    }
    let commands = Arc::new(ScriptedCommands::new());
    for program in ["/bin/true", "/bin/cat", "/bin/ls"] {
        commands.on(program, CommandOutcome::Finished(ExitStatus::Exited(0)));
    }
    let (output, diagnostics, screen) = (Buffer::default(), Buffer::default(), Buffer::default());
    let state = ShellState::new("knsh", "/work").unwrap().with_environment([
        ("PATH".into(), "/bin".into()),
        ("HOME".into(), "/home/ana".into()),
        ("PS1".into(), "$ ".into()),
    ]);
    let mut shell = Interpreter::new(
        state,
        fs.clone(),
        commands.clone(),
        Arc::new(FakeUserHomes::new()),
        Arc::new(FakeCollation::new()),
        Arc::new(FakeDescriptors::new(fs.clone())),
        Box::new(diagnostics.clone()),
    )
    .with_output(Box::new(output.clone()))
    .with_job_control(None);
    configure(&mut shell);
    let terminal = Scripted {
        input: keys.iter().map(|chunk| chunk.to_vec()).collect(),
        screen: screen.clone(),
        columns: 80,
        editing: true,
        started: Arc::new(Mutex::new(0)),
    };
    let host = HostInfo {
        host: "mac.local".into(),
        user: "ana".into(),
        terminal: "ttys001".into(),
        superuser: false,
    };
    let options = SessionOptions {
        marks,
        logout_file: None,
    };
    let session = Session::new(shell, terminal, host, options);
    Harness {
        session,
        screen,
        output,
        diagnostics,
        fs,
        commands,
    }
}

impl Harness {
    fn run(&mut self) -> Status {
        self.session.load_history();
        self.session.run().unwrap()
    }

    fn history(&self) -> Vec<String> {
        self.session.shell().state().history().entries().to_vec()
    }
}

// KNSH-107, NFR-COMPAT-10: OSC 133 `A` before the prompt, `B` after it, `C` before the command runs and `D;status`
// before the next prompt; OSC 7 with the directory.
#[test]
fn osc_133_marks_around_command() {
    let mut h = harness(&[b"false\r", b"true\r"], true, |_| {});
    assert_eq!(h.run(), Status::SUCCESS);
    let screen = h.screen.text();
    let osc7 = "\x1b]7;file://mac.local/work\x07";
    let expected = [
        osc7,
        marks::PROMPT_START,
        "$ ",
        marks::COMMAND_START,
        "false",
        marks::OUTPUT_START,
        "\x1b]133;D;1\x07",
        osc7,
        marks::PROMPT_START,
        "$ ",
        marks::COMMAND_START,
        "true",
        marks::OUTPUT_START,
        "\x1b]133;D;0\x07",
        osc7,
        marks::PROMPT_START,
        "exit\n",
    ];
    let mut at = 0;
    for piece in expected {
        let found = screen[at..]
            .find(piece)
            .unwrap_or_else(|| panic!("{piece:?} after {at} in {screen:?}"));
        at += found + piece.len();
    }
    // `B` is written once per prompt, not with every redraw.
    assert_eq!(screen.matches(marks::COMMAND_START).count(), 3);
    // Without marks wanted, none.
    let mut plain = harness(&[b"true\r"], false, |_| {});
    plain.run();
    assert!(!plain.screen.text().contains("\x1b]133"));
    assert!(!plain.screen.text().contains("\x1b]7"));
}

// KNSH-107: `!!` runs the previous line again, shown first, and both go to the history.
#[test]
fn history_expansion_in_the_session() {
    let mut h = harness(&[b"echo a b\r", b"!!\r", b"echo !$\r", b"!nosuch\r"], false, |_| {});
    h.run();
    assert_eq!(h.output.text(), "a b\na b\nb\n");
    assert!(h.screen.text().contains("echo a b\n"));
    assert!(h.screen.text().contains("echo b\n"));
    assert!(h.screen.text().contains("knsh: !nosuch: event not found\n"));
    assert_eq!(h.history(), ["echo a b", "echo a b", "echo b"]);
}

#[test]
fn ignoredups_and_ignorespace_in_the_session() {
    let mut h = harness(
        &[b"HISTCONTROL=ignoreboth\r", b"true\r", b"true\r", b" true\r"],
        false,
        |_| {},
    );
    h.run();
    assert_eq!(h.history(), ["HISTCONTROL=ignoreboth", "true"]);
}

#[test]
fn continuation_lines_use_ps2_and_join_in_the_history() {
    let mut h = harness(
        &[b"if true\r", b"then echo x\r", b"fi\r", b"echo 'a\r", b"b'\r"],
        false,
        |_| {},
    );
    h.run();
    assert_eq!(h.output.text(), "x\na\nb\n");
    assert_eq!(
        h.screen.text().matches("\r\n> ").count(),
        3,
        "PS2 drawn on a row of its own, once per line"
    );
    assert_eq!(h.history(), ["if true; then echo x; fi", "echo 'a\nb'"]);
}

#[test]
fn interrupt_abandons_the_line() {
    let mut h = harness(&[b"echo abc\x03", b"echo $?\r"], false, |_| {});
    h.run();
    assert!(h.screen.text().contains("echo abc^C"));
    assert_eq!(h.output.text(), "130\n");
    assert_eq!(h.history(), ["echo $?"]);
}

#[test]
fn tab_completes_and_lists() {
    let mut h = harness(&[b"cat no\t\r", b"cat f\t\t\x15\r"], false, |shell| {
        let _ = shell;
    });
    h.fs.write(Path::new("/work/notes.txt"), b"", 0o644).unwrap();
    h.fs.write(Path::new("/work/foo1"), b"", 0o644).unwrap();
    h.fs.write(Path::new("/work/foo2"), b"", 0o644).unwrap();
    h.run();
    // A single match is inserted with a space after it; the common prefix of several is inserted, and a second
    // Tab lists them.
    assert_eq!(h.history(), ["cat notes.txt "]);
    let screen = h.screen.text();
    assert!(screen.contains("foo1  foo2\r\n"), "{screen:?}");
    assert_eq!(h.commands.names(), ["cat"]);
}

#[test]
fn prompt_escapes_reach_the_terminal() {
    let mut h = harness(&[b"cd /home/ana\r"], false, |shell| {
        shell.state_mut().set_variable("PS1", "\\u@\\h:\\w \\#\\$ ");
    });
    h.run();
    let screen = h.screen.text();
    assert!(screen.contains("ana@mac:/work 1$ "), "{screen:?}");
    assert!(screen.contains("ana@mac:~ 2$ "), "{screen:?}");
}

#[test]
fn history_file_is_loaded_and_saved() {
    let mut h = harness(&[b"\x1b[A\r", b"true\r"], false, |shell| {
        shell.state_mut().set_variable("HISTFILE", "/home/ana/.hist");
    });
    h.fs.write(Path::new("/home/ana/.hist"), b"echo old\n", 0o600).unwrap();
    h.run();
    // Up recalls the line from the file.
    assert_eq!(h.output.text(), "old\n");
    let saved = String::from_utf8(h.fs.contents(Path::new("/home/ana/.hist")).unwrap()).unwrap();
    assert_eq!(saved, "echo old\necho old\ntrue\n");
    assert!(h.diagnostics.text().is_empty(), "{}", h.diagnostics.text());
}

#[test]
fn defaults_follow_bash() {
    let mut h = harness(&[], false, |shell| {
        shell.state_mut().set_variable("PS1", "");
    });
    let state = h.session.shell().state();
    assert_eq!(state.variable("PS2").unwrap(), "> ");
    assert_eq!(state.variable("HISTFILE").unwrap(), "/home/ana/.bash_history");
    let options = state.options();
    assert!(options.emacs && options.history && options.histexpand && !options.vi);
    h.run();
    let state = h.session.shell().state();
    assert_eq!(state.variable("HISTSIZE").unwrap(), "500");
    assert_eq!(state.variable("HISTFILESIZE").unwrap(), "500");
    // End of input at the prompt says `exit`.
    assert!(h.screen.text().ends_with("exit\n"));
}

#[test]
fn without_a_terminal_lines_are_read_as_they_come() {
    let mut h = harness(&[b"echo one\n", b"echo two\n"], false, |_| {});
    h.session.terminal.editing = false;
    h.run();
    assert_eq!(h.output.text(), "one\ntwo\n");
    let mut vi = harness(&[b"set +o emacs\r", b"echo x\n"], false, |_| {});
    vi.run();
    assert_eq!(vi.output.text(), "x\n");
}

#[test]
fn exit_ends_the_session_and_refusals_do_not() {
    let mut h = harness(
        &[b"select x in a; do :; done\r", b"exit 4\r", b"echo never\r"],
        false,
        |_| {},
    );
    assert_eq!(h.run(), Status::new(4));
    assert!(h.screen.text().contains("knsh: "), "a refused construct is reported");
    assert!(!h.output.text().contains("never"));
}

#[test]
fn vi_mode_edits_lines() {
    let mut h = harness(&[b"set -o vi\r", b"echo hello\x1b", b"0wcwbye\r"], false, |_| {});
    h.run();
    assert_eq!(h.output.text(), "bye\n");
}

#[test]
fn reverse_search_runs_an_older_line() {
    let mut h = harness(&[b"echo first\r", b"echo second\r", b"\x12fir\r"], false, |_| {});
    h.run();
    assert_eq!(h.output.text(), "first\nsecond\nfirst\n");
    assert!(h.screen.text().contains("(reverse-i-search)`fir': echo first"));
}
