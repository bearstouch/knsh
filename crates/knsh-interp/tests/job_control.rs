//! KNSH-100 integration tests of job control with real processes (NFR-COMPAT-02, FR-SES-10).
//!
//! - `terminal_job_control_matches_bash`: an interactive shell on a real terminal (a pseudo-terminal from
//!   `/usr/bin/script`) starts `sleep 30`, gets Ctrl-Z, then `jobs`, `bg`, `jobs`, `fg` and Ctrl-C; the job lines it
//!   prints must be bash's. The shell is this test binary run again as a small read-and-run loop (no line editor
//!   yet: KNSH-107).
//! - `pause_and_resume_reach_every_job_group`: the supervisor's pause stops each job's process group and its resume
//!   continues them (job control on); without job control the jobs stay in the shell's own group, which the
//!   supervisor signals itself.
//!
//! The binary has its own `main` (`harness = false`) so it can be that shell.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::OsString;
    use std::io::{BufRead, Read, Write};
    use std::os::fd::AsFd;
    use std::process::{Command, Stdio as ProcessStdio};
    use std::sync::Arc;
    use std::time::Duration;

    use knsh_interp::{Interpreter, ShellState};
    use knsh_platform::macos::{
        RealFs, SystemCollation, SystemDescriptors, SystemProcesses, SystemShellTimes, SystemTerminal, SystemUserHomes,
    };
    use knsh_platform::{JobTerminal, ProcessCommandSpawner, Processes, SharedFd, Signal, Stdio};

    /// Set in the environment of this binary when it runs as the interactive shell.
    const SHELL_MODE: &str = "KNSH_JOB_CONTROL_SHELL";

    const PATH: &str = "/bin:/usr/bin";

    /// An interpreter over the real system with standard descriptors `stdio`, writing its own messages to standard
    /// error.
    fn interpreter(processes: Arc<SystemProcesses>, stdio: Stdio) -> Interpreter {
        let state = ShellState::new("knsh", std::env::temp_dir().canonicalize().unwrap())
            .unwrap()
            .with_environment([(OsString::from("PATH"), OsString::from(PATH))]);
        Interpreter::new(
            state,
            Arc::new(RealFs::new()),
            Arc::new(ProcessCommandSpawner::new(processes, stdio)),
            Arc::new(SystemUserHomes::new()),
            Arc::new(SystemCollation::new()),
            Arc::new(SystemDescriptors::new()),
            Box::new(std::io::stderr()),
        )
        .with_output(Box::new(std::io::stdout()))
        .with_times(Arc::new(SystemShellTimes::new()))
    }

    /// The interactive shell: takes the terminal on standard input, then reads and runs one line at a time,
    /// reporting jobs before each prompt (`$ ` on standard error, as bash prints it). `exit` or end of input ends
    /// it.
    pub fn shell() {
        let tty = SharedFd::new(std::io::stdin().as_fd().try_clone_to_owned().unwrap());
        let terminal: Arc<dyn JobTerminal> = Arc::new(SystemTerminal::take(tty).unwrap());
        let mut shell = interpreter(Arc::new(SystemProcesses::new()), Stdio::Inherit).with_job_control(Some(terminal));
        let stdin = std::io::stdin();
        loop {
            shell.notify_jobs().unwrap();
            eprint!("$ ");
            let mut line = String::new();
            if stdin.lock().read_line(&mut line).unwrap() == 0 || line.trim() == "exit" {
                break;
            }
            let script = knsh_bash::parse(&line).unwrap();
            shell.run(&script, &line).unwrap();
        }
    }

    /// What the test types, with the pause after each piece: a job, Ctrl-Z, `jobs`, `bg`, `jobs`, `fg`, Ctrl-C.
    const SESSION: &[(&str, u64)] = &[
        ("", 700),
        ("sleep 30\n", 1000),
        ("\u{1a}", 700),
        ("jobs\n", 400),
        ("bg\n", 400),
        ("jobs\n", 400),
        ("fg\n", 700),
        ("\u{3}", 500),
        ("exit\n", 500),
    ];

    /// Runs `program args` under a pseudo-terminal (`script -q /dev/null …`), typing [`SESSION`], and returns
    /// everything the terminal showed.
    fn under_terminal(program: &str, args: &[&str], env: &[(&str, &str)]) -> String {
        let mut child = Command::new("/usr/bin/script")
            .arg("-q")
            .arg("/dev/null")
            .arg(program)
            .args(args)
            .env_clear()
            .env("PATH", PATH)
            .env("TERM", "dumb")
            .envs(env.iter().copied())
            .stdin(ProcessStdio::piped())
            .stdout(ProcessStdio::piped())
            .stderr(ProcessStdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        for (text, pause) in SESSION {
            input.write_all(text.as_bytes()).unwrap();
            input.flush().unwrap();
            std::thread::sleep(Duration::from_millis(*pause));
        }
        drop(input);
        let mut output = String::new();
        child.stdout.take().unwrap().read_to_string(&mut output).unwrap();
        child.wait().unwrap();
        output
    }

    /// The job lines of a transcript (`[1]+  Stopped …`, `[1]+ sleep 30 &`) and the command `fg` echoes.
    fn job_lines(transcript: &str) -> Vec<String> {
        transcript
            .split(['\r', '\n'])
            .map(str::trim_end)
            .filter(|line| {
                let mut chars = line.chars();
                (chars.next() == Some('[') && chars.next().is_some_and(|ch| ch.is_ascii_digit())) || *line == "sleep 30"
            })
            .map(str::to_owned)
            .collect()
    }

    // AC: job control works in a real terminal; Ctrl-Z, `jobs`, `bg`, `fg` print what bash prints.
    pub fn terminal_job_control_matches_bash() {
        let bash = under_terminal(
            "/bin/bash",
            &["--norc", "--noprofile", "-i"],
            &[("PS1", "$ "), ("BASH_SILENCE_DEPRECATION_WARNING", "1")],
        );
        let exe = std::env::current_exe().unwrap();
        let knsh = under_terminal(exe.to_str().unwrap(), &[], &[(SHELL_MODE, "1")]);
        let expected = [
            "[1]+  Stopped                 sleep 30",
            "[1]+  Stopped                 sleep 30",
            "[1]+ sleep 30 &",
            "[1]+  Running                 sleep 30 &",
            "sleep 30",
        ];
        assert_eq!(job_lines(&bash), expected, "bash transcript: {bash:?}");
        assert_eq!(job_lines(&knsh), expected, "knsh transcript: {knsh:?}");
    }

    /// The `ps` state letters of process `pid` (`T` when stopped), or `None` once it is gone.
    fn state_of(pid: &str) -> Option<String> {
        let output = Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", pid])
            .output()
            .unwrap();
        let text = String::from_utf8(output.stdout).unwrap().trim().to_owned();
        (!text.is_empty()).then_some(text)
    }

    /// The process group of process `pid`, from `ps`.
    fn group_of(pid: &str) -> String {
        let output = Command::new("/bin/ps")
            .args(["-o", "pgid=", "-p", pid])
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    /// What `jobs options` prints, one line per job (through a file, the shell's standard output being this
    /// test's).
    fn jobs_output(shell: &mut Interpreter, options: &str) -> Vec<String> {
        let dir = std::env::temp_dir().canonicalize().unwrap();
        let file = dir.join(format!("knsh-jobs-{}", std::process::id()));
        let line = format!("jobs {options} >{}\n", file.display());
        shell.run(&knsh_bash::parse(&line).unwrap(), &line).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        std::fs::remove_file(&file).unwrap();
        text.lines().map(str::to_owned).collect()
    }

    // FR-SES-10: the supervisor's pause stops every job's group and its resume continues them; without job control
    // the jobs are in the shell's own group.
    pub fn pause_and_resume_reach_every_job_group() {
        let processes = Arc::new(SystemProcesses::new());
        let mut shell = interpreter(processes.clone(), Stdio::Null).with_job_control(None);
        let line = "sleep 30 & sleep 30 | sleep 30 &\n";
        shell.run(&knsh_bash::parse(line).unwrap(), line).unwrap();
        let pids = jobs_output(&mut shell, "-p");
        assert_eq!(pids.len(), 2);
        for pid in &pids {
            assert_eq!(group_of(pid), *pid, "each job leads a group of its own");
        }
        let signals = shell.job_signals();
        assert_eq!(signals.groups().len(), 2);
        signals.pause().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        for pid in &pids {
            assert!(state_of(pid).unwrap().starts_with('T'), "{pid} stopped");
        }
        signals.resume().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        for pid in &pids {
            assert!(!state_of(pid).unwrap().starts_with('T'), "{pid} running again");
        }
        // The pause's stops were not taken for the user's: no job is stopped for `jobs`.
        assert_eq!(jobs_output(&mut shell, "-s"), Vec::<String>::new());
        assert_eq!(jobs_output(&mut shell, "-r").len(), 2);
        for group in signals.groups() {
            processes.signal_job(group, Signal::Kill).unwrap();
        }
        let wait = "wait\n";
        shell.run(&knsh_bash::parse(wait).unwrap(), wait).unwrap();
        assert_eq!(signals.groups(), Vec::new());

        // Without job control: the shell's own group, which the supervisor's signal to it reaches.
        let mut script = interpreter(Arc::new(SystemProcesses::new()), Stdio::Null);
        let line = "sleep 30 &\n";
        script.run(&knsh_bash::parse(line).unwrap(), line).unwrap();
        let pids = jobs_output(&mut script, "-p");
        assert_eq!(group_of(&pids[0]), group_of(&std::process::id().to_string()));
        assert_eq!(script.job_signals().groups(), Vec::new());
        Command::new("/bin/kill").args(["-9", &pids[0]]).status().unwrap();
        script.run(&knsh_bash::parse(wait).unwrap(), wait).unwrap();
    }

    /// Whether this run is the interactive shell.
    pub fn is_shell() -> bool {
        std::env::var_os(SHELL_MODE).is_some()
    }
}

#[cfg(target_os = "macos")]
fn main() {
    if macos::is_shell() {
        macos::shell();
        return;
    }
    let tests: [(&str, fn()); 2] = [
        (
            "pause_and_resume_reach_every_job_group",
            macos::pause_and_resume_reach_every_job_group,
        ),
        (
            "terminal_job_control_matches_bash",
            macos::terminal_job_control_matches_bash,
        ),
    ];
    let filter: Vec<String> = std::env::args().skip(1).filter(|arg| !arg.starts_with('-')).collect();
    let mut failed = 0;
    for (name, test) in tests {
        if !filter.is_empty() && !filter.iter().any(|wanted| name.contains(wanted.as_str())) {
            continue;
        }
        if std::panic::catch_unwind(test).is_ok() {
            println!("test {name} ... ok");
        } else {
            println!("test {name} ... FAILED");
            failed += 1;
        }
    }
    if failed > 0 {
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {}
