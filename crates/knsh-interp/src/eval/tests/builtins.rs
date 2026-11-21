//! The core builtins over the fake filesystem and scripted commands (KNSH-101; NFR-COMPAT-02). Messages and
//! statuses were checked against bash (3.2 here; where bash 5.2 differs, its source is followed and the case is
//! marked).

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::PathBuf;

use super::*;

/// The environment entry `name` of the `index`th command run.
fn env_of(h: &Harness, index: usize, name: &str) -> Option<String> {
    h.commands.runs()[index]
        .env
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.to_string_lossy().into_owned())
}

/// The arguments of the `index`th command run.
fn args_of(h: &Harness, index: usize) -> Vec<String> {
    h.commands.runs()[index]
        .args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

fn var(h: &Harness, name: &str) -> Option<String> {
    h.interpreter
        .state()
        .variable(name)
        .map(|value| value.to_string_lossy().into_owned())
}

/// Records each directory `cd` reports.
#[derive(Default)]
struct Directories(Mutex<Vec<PathBuf>>);

impl DirectoryObserver for Directories {
    fn changed(&self, cwd: &Path) {
        self.0.lock().unwrap().push(cwd.to_path_buf());
    }
}

// ---- cd and pwd ----

// KNSH-101 unit test: `CDPATH` is searched for a relative name (and the directory printed), `OLDPWD` gets the old
// `PWD`, and `cd -` goes back and prints where.
#[test]
fn cd_uses_cdpath_and_sets_oldpwd() {
    let mut h = Harness::new();
    h.fs.add_dir_all(Path::new("/projects/app/src")).unwrap();
    h.fs.add_dir_all(Path::new("/work/local")).unwrap();
    assert_eq!(h.status("CDPATH=/nowhere:/projects; cd app"), 0);
    assert_eq!(h.interpreter.state().cwd(), Path::new("/projects/app"));
    assert_eq!(var(&h, "PWD").as_deref(), Some("/projects/app"));
    assert_eq!(var(&h, "OLDPWD").as_deref(), Some("/work"));
    assert_eq!(h.output.text(), "/projects/app\n");
    // An empty entry is the working directory, and prints nothing; `./name` never searches `CDPATH`.
    assert_eq!(h.status("cd /work; CDPATH=:/projects; cd local"), 0);
    assert_eq!(h.interpreter.state().cwd(), Path::new("/work/local"));
    assert_eq!(h.status("cd ./src"), 1);
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: cd: ./src: No such file or directory\n"
    );
    assert_eq!(h.status("cd -"), 0);
    assert_eq!(h.interpreter.state().cwd(), Path::new("/work"));
    assert_eq!(var(&h, "OLDPWD").as_deref(), Some("/work/local"));
    assert!(h.output.text().ends_with("/work\n"));
    // Commands run in the new directory.
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("cd /projects; x"), 0);
    assert_eq!(h.commands.runs()[0].cwd, Path::new("/projects"));
}

// KNSH-101 unit test: `-P` resolves symbolic links; `-L` (the default) keeps them and treats `..` as text, and
// `pwd -P` shows the physical directory.
#[test]
fn cd_physical_resolves_symlinks() {
    let mut h = Harness::new();
    h.fs.add_dir_all(Path::new("/data/real/sub")).unwrap();
    h.fs.add_symlink(Path::new("/work/link"), Path::new("/data/real"))
        .unwrap();
    assert_eq!(h.status("cd link; pwd; pwd -P"), 0);
    assert_eq!(h.output.text(), "/work/link\n/data/real\n");
    assert_eq!(h.status("cd ..; pwd"), 0);
    assert!(h.output.text().ends_with("/work\n"));
    assert_eq!(h.status("cd -P link/sub"), 0);
    assert_eq!(var(&h, "PWD").as_deref(), Some("/data/real/sub"));
    // Physically, `..` of the link's target is its parent.
    assert_eq!(h.status("cd /work; cd -P link/.."), 0);
    assert_eq!(h.interpreter.state().cwd(), Path::new("/data"));
    h.interpreter.state_mut().options_mut().physical = true;
    assert_eq!(h.status("cd /work/link"), 0);
    assert_eq!(h.interpreter.state().cwd(), Path::new("/data/real"));
}

// NFR-COMPAT-02: `cd`'s errors and statuses, as bash's.
#[test]
fn cd_errors_match_bash() {
    let mut h = Harness::new();
    h.fs.write(Path::new("/work/file"), b"", 0o644).unwrap();
    let cases: &[(&str, u8, &str)] = &[
        ("cd /missing", 1, "cd: /missing: No such file or directory"),
        ("cd file", 1, "cd: file: Not a directory"),
        ("cd a b", 1, "cd: too many arguments"),
        ("cd -", 1, "cd: OLDPWD not set"),
        ("unset HOME; cd", 1, "cd: HOME not set"),
    ];
    for (line, status, message) in cases {
        let before = h.diagnostics.text().len();
        assert_eq!(h.status(line), *status, "{line}");
        assert_eq!(
            &h.diagnostics.text()[before..],
            format!("knsh: line 1: {message}\n"),
            "{line}"
        );
    }
    // bash 5.2: an invalid option is a usage error (2), with the usage line unprefixed.
    assert_eq!(h.status("cd -x"), 2);
    assert!(
        h.diagnostics
            .text()
            .ends_with("knsh: line 1: cd: -x: invalid option\ncd: usage: cd [-L|[-P [-e]] [-@]] [dir]\n")
    );
    assert_eq!(h.interpreter.state().cwd(), Path::new("/work"));
    // `cd ''` stays where it is, as bash does.
    assert_eq!(h.status("cd ''"), 0);
    assert_eq!(h.interpreter.state().cwd(), Path::new("/work"));
}

// KNSH-101 acceptance (NFR-COMPAT-10): each directory change is reported to the host, which writes OSC 7 and
// publishes `cwd.changed`; a failed `cd` and a subshell's `cd` are not.
#[test]
fn cd_reports_each_change_to_the_directory_observer() {
    let directories = Arc::new(Directories::default());
    let observer: Arc<dyn DirectoryObserver> = directories.clone();
    let mut h = Harness::with(|interpreter| interpreter.with_directory_observer(observer));
    h.fs.add_dir_all(Path::new("/work/a")).unwrap();
    assert_eq!(h.status("cd a; cd /missing; (cd /); cd .."), 0);
    assert_eq!(
        *directories.0.lock().unwrap(),
        [PathBuf::from("/work/a"), PathBuf::from("/work")]
    );
    // The OSC 7 observer writes the sequence for the new directory.
    assert_eq!(crate::osc7(b"mac", b"/work/a b"), "\x1b]7;file://mac/work/a%20b\x07");
}

// A read-only `PWD`: bash still changes directory, reports, and returns 1.
#[test]
fn cd_with_a_readonly_pwd_changes_directory_and_fails() {
    let mut h = Harness::new();
    h.fs.add_dir_all(Path::new("/work/a")).unwrap();
    assert_eq!(h.status("readonly PWD; cd a"), 1);
    assert_eq!(h.interpreter.state().cwd(), Path::new("/work/a"));
    assert_eq!(h.diagnostics.text(), "knsh: line 1: PWD: readonly variable\n");
}

// Bash drops an inherited `OLDPWD` that is not a directory, and `export -p` shows it without a value.
#[test]
fn oldpwd_starts_exported_without_a_value() {
    let mut h = Harness::new();
    assert_eq!(h.status("echo \"${OLDPWD-unset}\"; export -p"), 0);
    assert_eq!(
        h.output.text(),
        "unset\ndeclare -x OLDPWD\ndeclare -x PATH=\"/bin\"\ndeclare -x PWD=\"/work\"\ndeclare -x SHLVL=\"1\"\n"
    );
}

// ---- export, readonly, declare, unset ----

// KNSH-101 unit test: an exported variable reaches every command started after, `export -n` takes it back, and a
// variable exported without a value is not passed until it has one.
#[test]
fn export_marks_variable_for_children() {
    let mut h = Harness::new();
    h.on("env", &[exited(0)]);
    assert_eq!(h.status("A=1; export A B; env; B=2 C=3; env; export -n A; env"), 0);
    assert_eq!(env_of(&h, 0, "A").as_deref(), Some("1"));
    assert_eq!(env_of(&h, 0, "B"), None);
    assert_eq!(env_of(&h, 1, "B").as_deref(), Some("2"));
    assert_eq!(env_of(&h, 1, "C"), None);
    assert_eq!(env_of(&h, 2, "A"), None);
    assert!(h.interpreter.state().is_exported("B"));
    // `export x=$y` is an assignment: the value is not split or matched against file names.
    h.interpreter.state_mut().set_variable("y", "a  b *");
    assert_eq!(h.status("export x=$y; env"), 0);
    assert_eq!(env_of(&h, 3, "x").as_deref(), Some("a  b *"));
    assert_eq!(h.status("export 1x=2"), 1);
    assert!(
        h.diagnostics
            .text()
            .ends_with("export: `1x=2': not a valid identifier\n")
    );
}

// KNSH-101 unit test: a read-only variable cannot be assigned (the line is abandoned, as bash 5.2 does outside
// POSIX mode), unset, or given another value by `declare`; its command still runs without the assignment.
#[test]
fn readonly_blocks_assignment() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("readonly r=1; r=2; x same-line\nx next"), 0);
    assert_eq!(var(&h, "r").as_deref(), Some("1"));
    assert_eq!(args_of(&h, 0), ["next"]);
    assert_eq!(h.status("r=3 x temp"), 0);
    assert_eq!(env_of(&h, 1, "r"), None);
    assert_eq!(h.status("unset r"), 1);
    assert_eq!(h.status("declare r=4"), 1);
    assert_eq!(h.status("export r=5"), 1);
    assert_eq!(h.status("for r in a; do x; done"), 1);
    assert_eq!(h.status("(( r = 6 ))"), 1);
    assert_eq!(var(&h, "r").as_deref(), Some("1"));
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: r: readonly variable\n\
         knsh: line 1: r: readonly variable\n\
         knsh: line 1: unset: r: cannot unset: readonly variable\n\
         knsh: line 1: declare: r: readonly variable\n\
         knsh: line 1: r: readonly variable\n\
         knsh: line 1: r: readonly variable\n\
         knsh: line 1: r: readonly variable\n"
    );
    assert_eq!(h.commands.runs().len(), 2);
}

// NFR-COMPAT-02: `declare -i`, `-l` and `-u` change what is assigned; `declare -p` prints as bash does.
#[test]
fn declare_attributes_and_printing() {
    let mut h = Harness::new();
    assert_eq!(
        h.status("declare -i n=3+4; n+=2; declare -l lo=ABC; lo+=Dé; declare -u up=abc; declare w; declare -rx z=2"),
        0
    );
    assert_eq!(var(&h, "n").as_deref(), Some("9"));
    assert_eq!(var(&h, "lo").as_deref(), Some("abcdé"));
    assert_eq!(var(&h, "up").as_deref(), Some("ABC"));
    assert_eq!(h.status("q='a\"b$c'; declare -p n lo w z q"), 0);
    assert_eq!(
        h.output.text(),
        "declare -i n=\"9\"\ndeclare -l lo=\"abcdé\"\ndeclare -- w\ndeclare -rx z=\"2\"\ndeclare -- q=\"a\\\"b\\$c\"\n"
    );
    assert_eq!(h.status("echo \"${w-unset}\" \"${z@a}\""), 0);
    assert!(h.output.text().ends_with("unset rx\n"));
    assert_eq!(h.status("declare -p nosuch"), 1);
    assert!(
        h.diagnostics
            .text()
            .ends_with("knsh: line 1: declare: nosuch: not found\n")
    );
    // An arithmetic error in an integer assignment abandons the line.
    assert_eq!(h.status("n='1+'; echo same\necho next"), 0);
    assert!(h.output.text().ends_with("next\n"));
    // Functions cannot be defined yet: `declare -f` lists none and finds none.
    assert_eq!(h.status("declare -f"), 0);
    assert_eq!(h.status("declare -F nosuch"), 1);
    // Listing everything would show variables bash keeps itself: refused.
    assert_eq!(refused(h.run("declare -p")), Unsupported::ShellVariable);
    assert_eq!(refused(h.run("readonly -p")), Unsupported::ShellVariable);
    assert_eq!(refused(h.run("export RANDOM")), Unsupported::ShellVariable);
}

#[test]
fn unset_removes_variables_and_reports_bad_names() {
    let mut h = Harness::new();
    assert_eq!(h.status("a=1 b=2; unset a b c"), 0);
    assert_eq!(var(&h, "a"), None);
    assert_eq!(h.status("unset 1a"), 1);
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: unset: `1a': not a valid identifier\n"
    );
    assert_eq!(h.status("unset -f nosuch"), 0);
    // Unsetting PATH empties the hash table, as any change of PATH does.
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("x; unset PATH; hash"), 0);
    assert!(h.output.text().ends_with("hash: hash table empty\n"));
}

// Assignments before a builtin are seen by it and what it runs, then undone (bash's temporary environment).
#[test]
fn assignments_before_builtins_are_temporary() {
    let mut h = Harness::new();
    h.on("env", &[exited(0)]);
    h.fs.add_dir_all(Path::new("/home/x")).unwrap();
    assert_eq!(
        h.status("HOME=/home/x cd; v=1 eval 'env; echo $v'; echo \"[${v-unset}]\""),
        0
    );
    assert_eq!(h.interpreter.state().cwd(), Path::new("/home/x"));
    assert_eq!(var(&h, "HOME"), None);
    assert_eq!(env_of(&h, 0, "v").as_deref(), Some("1"));
    assert_eq!(h.output.text(), "1\n[unset]\n");
    // `export` keeps a variable it names from the temporary environment.
    assert_eq!(h.status("w=5 export w; echo $w"), 0);
    assert!(h.output.text().ends_with("5\n"));
    assert!(h.interpreter.state().is_exported("w"));
}

// NFR-COMPAT-02: `declare -r` and `declare -x` keep the temporary assignment they name, as `readonly` and `export`
// do (bash's `att_propagate`), so `x=1 declare -r x` leaves `x` read-only; `export -n` and `declare -i` do not keep it.
#[test]
fn declaration_builtins_keep_the_temporary_assignments_they_mark() {
    let mut h = Harness::new();
    assert_eq!(h.status("x=1 declare -r x; declare -p x"), 0);
    assert_eq!(h.output.text(), "declare -rx x=\"1\"\n");
    assert_eq!(h.status("x=2; echo $x"), 1);
    assert!(h.diagnostics.text().ends_with("x: readonly variable\n"));
    assert_eq!(h.status("y=1 typeset -x y; declare -p y"), 0);
    assert!(h.output.text().ends_with("declare -x y=\"1\"\n"));
    assert_eq!(
        h.status("w=1 declare -i w; z=1 export -n z; echo \"[${w-unset}${z-unset}]\""),
        0
    );
    assert!(h.output.text().ends_with("[unsetunset]\n"));
}

// ---- control flow ----

// KNSH-101 unit test: `return` outside a function or sourced file is an error (bash 5.2: status 2); inside a
// sourced file it leaves the file.
#[test]
fn return_outside_function_is_error() {
    let mut h = Harness::new();
    assert_eq!(h.status("return; echo $?"), 0);
    assert_eq!(h.output.text(), "2\n");
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: return: can only `return' from a function or sourced script\n"
    );
    h.fs.write(Path::new("/work/lib.sh"), b"echo in\nreturn 3\necho never\n", 0o644)
        .unwrap();
    assert_eq!(h.status(". ./lib.sh; echo $?"), 0);
    assert_eq!(h.output.text(), "2\nin\n3\n");
}

#[test]
fn break_and_continue_leave_and_resume_loops() {
    let mut h = Harness::new();
    assert_eq!(
        h.status("for i in 1 2 3; do for j in a b; do if true; then continue 2; fi; done; echo no; done; echo $i"),
        0
    );
    assert_eq!(h.output.text(), "3\n");
    assert_eq!(
        h.status("while :; do while :; do break 2; done; echo no; done; echo out"),
        0
    );
    assert!(h.output.text().ends_with("out\n"));
    // `continue` in an arithmetic `for` still runs the update.
    assert_eq!(h.status("for ((k = 0; k < 3; k++)); do continue; done; echo $k"), 0);
    assert!(h.output.text().ends_with("3\n"));
    // A subshell's `break` ends only the subshell.
    assert_eq!(h.status("for i in 1 2; do (break); echo $i; done"), 0);
    assert!(h.output.text().ends_with("1\n2\n"));
    // Outside a loop: bash's message, status 0. `break 0` leaves every loop with 1.
    assert_eq!(h.status("break"), 0);
    assert!(
        h.diagnostics
            .text()
            .ends_with("break: only meaningful in a `for', `while', or `until' loop\n")
    );
    assert_eq!(h.status("for i in 1; do break 0; echo no; done"), 1);
    // A word that is not a number ends the script with `$?` plus 128, as bash's `throw_to_top_level`.
    assert_eq!(h.status("true; for i in 1; do break x; done; echo no"), 128);
}

#[test]
fn exit_shift_and_set_follow_bash() {
    let mut h = Harness::new();
    assert_eq!(h.status("exit 300; echo no"), 44);
    assert_eq!(h.status("false; exit"), 1);
    // bash 5.2: a word that is not a number exits with 2.
    assert_eq!(h.status("exit abc"), 2);
    // A second argument is an error that abandons the line; the next line runs.
    assert_eq!(h.status("exit 1 2; echo same\necho next"), 0);
    assert_eq!(h.output.text(), "next\n");
    assert_eq!(
        h.status("set -- a 'b c' d; shift; echo $# \"$1\"; shift 5; echo $?; set x; echo $*"),
        0
    );
    assert!(h.output.text().ends_with("2 b c\n1\nx\n"));
    assert_eq!(h.status("shift abc"), 1);
    assert_eq!(h.status("shift -1"), 1);
    assert!(
        h.diagnostics
            .text()
            .ends_with("shift: abc: numeric argument required\nknsh: line 1: shift: -1: shift count out of range\n")
    );
    assert_eq!(h.status("local x=1"), 1);
    assert!(
        h.diagnostics
            .text()
            .ends_with("local: can only be used in a function\n")
    );
}

// ---- echo ----

// KNSH-101 unit test: `echo`'s options and escapes, with and without `xpg_echo`, as bash's.
#[test]
fn echo_escape_handling_matches_bash_and_xpg_echo() {
    let mut h = Harness::new();
    assert_eq!(
        h.status(r"echo -e 'a\tb\x41\0101' -E; echo -n x; echo -ne 'y\cz' more; echo; echo 'a\nb' -n"),
        0
    );
    assert_eq!(h.output.text(), "a\tbAA -E\nxy\na\\nb -n\n");
    h.interpreter.state_mut().options_mut().xpg_echo = true;
    assert_eq!(h.status(r"echo 'c\nd'; echo -E 'e\nf'"), 0);
    assert!(h.output.text().ends_with("c\nd\ne\\nf\n"));
    // A closed standard output is bash's write error.
    assert_eq!(h.status("echo x >&-"), 1);
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: echo: write error: Bad file descriptor\n"
    );
}

// ---- eval and source ----

// KNSH-101 acceptance: the commands `eval` and `source` run start through the spawner like any other, the seam
// KNSH-108 decides at, with the shell's state.
#[test]
fn eval_and_source_run_commands_through_the_spawner() {
    let mut h = Harness::new();
    h.on("tool", &[exited(4)]);
    h.fs.write(Path::new("/work/inc.sh"), b"v=from-file\ntool \"$1\" \"$#\"\n", 0o644)
        .unwrap();
    assert_eq!(
        h.status("set -- a b; eval 'w=$2; tool $1'; echo $? $w; source inc.sh x; echo $? $v $#"),
        0
    );
    assert_eq!(h.ran(), ["tool", "tool"]);
    assert_eq!(args_of(&h, 0), ["a"]);
    assert_eq!(args_of(&h, 1), ["x", "1"]);
    // The positional parameters are put back after `source` with arguments.
    assert_eq!(h.output.text(), "4 b\n4 from-file 2\n");
    // What the check refuses is refused when `eval` runs it.
    assert_eq!(refused(h.run("eval 'echo $(ls)'")), Unsupported::CommandSubstitution);
}

// Untrusted input: text that runs itself again holds its text and tree per level, so the bytes of `eval`, `source`
// and alias text running at once are bounded; a small file that sources itself still ends at the nesting limit.
#[test]
fn nested_text_running_at_once_is_bounded() {
    let mut h = Harness::new();
    // 400 KiB in two lines: the third level would hold more than 1 MiB.
    let mut big = format!("#{}\n", "x".repeat(400 * 1024));
    big.push_str(". ./big.sh\n");
    h.fs.write(Path::new("/work/big.sh"), big.as_bytes(), 0o644).unwrap();
    assert!(matches!(
        h.run(". ./big.sh"),
        Err(InterpError::ExpansionLimit { limit, .. }) if limit == knsh_bash::MAX_INPUT_LEN
    ));
    h.fs.write(Path::new("/work/self.sh"), b". ./self.sh\n", 0o644).unwrap();
    assert!(matches!(h.run(". ./self.sh"), Err(InterpError::DepthExceeded { .. })));
    // The count is released as each level ends: the same file runs again afterwards.
    h.fs.write(
        Path::new("/work/once.sh"),
        big.replace(". ./big.sh\n", "").as_bytes(),
        0o644,
    )
    .unwrap();
    assert_eq!(
        h.status(". ./once.sh; . ./once.sh; . ./once.sh; . ./once.sh; . ./once.sh"),
        0
    );
}

// NFR-COMPAT-02: messages inside a sourced file are named after it; `eval` lines count from its line; an
// expansion error abandons only the `eval`'s own line.
#[test]
fn nested_messages_follow_bash() {
    let mut h = Harness::new();
    h.fs.write(Path::new("/work/inc.sh"), b"\nnosuch1\n", 0o644).unwrap();
    assert_eq!(
        h.status("true\neval 'true\nnosuch2'\n. ./inc.sh\neval 'echo $((1/0)); echo in'; echo out"),
        0
    );
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 3: nosuch2: command not found\n\
         ./inc.sh: line 2: nosuch1: command not found\n\
         knsh: line 5: 1/0: division by 0 (error token is \"0\")\n"
    );
    assert_eq!(h.output.text(), "out\n");
    assert_eq!(h.status("source nosuch"), 1);
    assert!(
        h.diagnostics
            .text()
            .ends_with("knsh: line 1: nosuch: No such file or directory\n")
    );
    assert_eq!(h.status("source"), 2);
    assert!(
        h.diagnostics.text().ends_with(
            "knsh: line 1: source: filename argument required\nsource: usage: source filename [arguments]\n"
        )
    );
    assert_eq!(h.status(". /work"), 1);
    assert!(
        h.diagnostics
            .text()
            .ends_with("knsh: line 1: .: /work: is a directory\n")
    );
}

// NFR-COMPAT-02: a syntax error in `eval` or `source` text: what comes before its line runs, then bash's report
// and status 2 (bash 5.2's `EX_BADUSAGE`).
#[test]
fn syntax_errors_in_eval_and_source_are_reported_like_bash() {
    let mut h = Harness::new();
    assert_eq!(h.status("eval 'a )'; echo $?"), 0);
    assert_eq!(
        h.diagnostics.text(),
        "knsh: eval: line 1: syntax error near unexpected token `)'\nknsh: eval: line 1: `a )'\n"
    );
    assert_eq!(h.output.text(), "2\n");
    h.fs.write(Path::new("/work/bad.sh"), b"echo one\nif true\n", 0o644)
        .unwrap();
    assert_eq!(h.status(". ./bad.sh"), 2);
    assert!(h.output.text().ends_with("one\n"));
    assert!(
        h.diagnostics
            .text()
            .ends_with("./bad.sh: line 3: syntax error: unexpected end of file\n")
    );
    assert_eq!(refused(h.run("eval \"echo 'a\"")), Unsupported::Unparsed);
}

// ---- command lookup: hash, type, command, builtin, exec ----

// KNSH-101 unit test: `type` names aliases (while they are expanded), keywords, builtins and files, hashed ones
// as hashed. Functions cannot be defined until KNSH-103, so none is ever reported.
#[test]
fn type_reports_builtin_function_alias_file() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    h.interpreter.state_mut().options_mut().expand_aliases = true;
    assert_eq!(
        h.status("alias ll='ls -l'\ntype ll if cd x; x; type x; type -t ll if cd x nosuch"),
        1
    );
    assert_eq!(
        h.output.text(),
        "ll is aliased to `ls -l'\nif is a shell keyword\ncd is a shell builtin\nx is /bin/x\n\
         x is hashed (/bin/x)\nalias\nkeyword\nbuiltin\nfile\n"
    );
    assert_eq!(h.diagnostics.text(), "");
    assert_eq!(h.status("type nosuch"), 1);
    assert_eq!(h.diagnostics.text(), "knsh: line 1: type: nosuch: not found\n");
    assert_eq!(h.status("type -p cd x; type -P cd; type -a echo"), 0);
    assert!(
        h.output
            .text()
            .ends_with("/bin/x\necho is a shell builtin\necho is /bin/echo\n")
    );
    // Without `expand_aliases` (a script) an alias is not reported, as bash does.
    h.interpreter.state_mut().options_mut().expand_aliases = false;
    assert_eq!(h.status("type -t ll"), 1);
}

#[test]
fn command_finds_and_describes_without_functions() {
    let mut h = Harness::new();
    h.on("x", &[exited(3)]);
    assert_eq!(h.status("command -v cd x if nosuch; echo $?"), 0);
    assert_eq!(h.output.text(), "cd\n/bin/x\nif\n0\n");
    assert_eq!(h.status("command -V nosuch"), 1);
    assert_eq!(h.diagnostics.text(), "knsh: line 1: command: nosuch: not found\n");
    assert_eq!(h.status("command x a"), 3);
    assert_eq!(args_of(&h, 0), ["a"]);
    assert_eq!(h.status("command echo hi; builtin echo there; builtin x"), 1);
    assert!(h.output.text().ends_with("hi\nthere\n"));
    assert!(h.diagnostics.text().ends_with("builtin: x: not a shell builtin\n"));
    // `command -p` searches the standard path, not `PATH`.
    h.fs.add_dir_all(Path::new("/usr/bin")).unwrap();
    h.fs.write(Path::new("/usr/bin/std"), b"", 0o755).unwrap();
    h.commands.on("/usr/bin/std", exited(0));
    assert_eq!(h.status("command -p std; std"), 127);
    assert_eq!(h.commands.runs()[1].program, Path::new("/usr/bin/std"));
}

// NFR-COMPAT-02: the hash table remembers what `PATH` found, counts uses, and empties when `PATH` changes.
#[test]
fn hash_remembers_commands_like_bash() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("hash; x; x; hash; hash -t x; hash -l"), 0);
    assert_eq!(
        h.output.text(),
        "hash: hash table empty\nhits\tcommand\n   2\t/bin/x\n/bin/x\nbuiltin hash -p /bin/x x\n"
    );
    // A hashed command is run from the table, even after it moved, until `hash -r` or a change of `PATH`.
    h.fs.add_dir_all(Path::new("/opt")).unwrap();
    h.fs.write(Path::new("/opt/x"), b"", 0o755).unwrap();
    h.commands.on("/opt/x", exited(0));
    assert_eq!(h.status("PATH=/opt:/bin; x; PATH=/opt:/bin; hash -r; x"), 0);
    let programs: Vec<PathBuf> = h.commands.runs().into_iter().map(|run| run.program).collect();
    assert_eq!(programs[2..], [PathBuf::from("/opt/x"), PathBuf::from("/opt/x")]);
    assert_eq!(h.status("hash nosuch cd; hash -d nosuch"), 1);
    assert!(
        h.diagnostics
            .text()
            .ends_with("knsh: line 1: hash: nosuch: not found\nknsh: line 1: hash: nosuch: not found\n")
    );
}

// `exec cmd` runs the program and the shell ends with its status; `-a` and `-l` set its `argv[0]`, `-c` empties
// its environment; a program that cannot run ends a script with 127 or 126.
#[test]
fn exec_runs_the_program_and_ends_the_shell() {
    let mut h = Harness::new();
    h.on("x", &[exited(5)]);
    assert_eq!(h.status("exec x a; echo no"), 5);
    assert_eq!(h.output.text(), "");
    assert_eq!(h.status("exec -a name x"), 5);
    assert_eq!(h.commands.runs()[1].argv0, OsStr::new("name"));
    assert_eq!(h.status("exec -l x"), 5);
    assert_eq!(h.commands.runs()[2].argv0, OsStr::new("-x"));
    assert_eq!(h.status("A=1 exec -c x"), 5);
    assert_eq!(
        h.commands.runs()[3].env,
        [] as [(std::ffi::OsString, std::ffi::OsString); 0]
    );
    // Bash lowers SHLVL for the program that replaces it.
    assert_eq!(h.status("exec x"), 5);
    assert_eq!(env_of(&h, 4, "SHLVL").as_deref(), Some("0"));
    assert_eq!(h.status("exec nosuch; echo no"), 127);
    assert_eq!(h.diagnostics.text(), "knsh: line 1: exec: nosuch: not found\n");
}

// NFR-COMPAT-02 (fail open for humans): a program `exec` found but could not start ends a script, as bash's failed
// `exec` does, but not an interactive shell, which goes on with the status.
#[test]
fn exec_of_a_program_that_cannot_start_keeps_an_interactive_shell() {
    let mut h = Harness::new();
    h.on("x", &[CommandOutcome::NotExecutable]);
    assert_eq!(h.status("exec x; echo no"), 126);
    assert_eq!(h.output.text(), "");
    let mut h = Harness::with(|interpreter| interpreter.with_job_control(None));
    h.on("x", &[CommandOutcome::NotExecutable]);
    assert_eq!(h.status("exec x; echo $?"), 0);
    assert_eq!(h.output.text(), "126\n");
}

// ---- aliases ----

// KNSH-101 unit test: aliases expand only with `expand_aliases` on (an interactive shell), and only in lines read
// after they were defined; an alias is not expanded again inside itself.
#[test]
fn alias_expansion_requires_expand_aliases() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    // A script: defined, listed, never expanded.
    assert_eq!(h.status("alias say='echo said'\nsay hi"), 127);
    assert!(h.diagnostics.text().ends_with("say: command not found\n"));
    assert_eq!(h.status("alias"), 0);
    assert_eq!(h.output.text(), "alias say='echo said'\n");
    // Interactive: expanded in later lines, not on the line that defines it.
    let mut h = Harness::with(|interpreter| interpreter.with_job_control(None));
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("alias say='echo said' x='x -v '; say same-line"), 127);
    assert_eq!(h.status("say it; x x"), 0);
    assert_eq!(h.output.text(), "said it\n");
    // The text ends with a blank, so the next word is expanded too, as bash does (`x -v x -v`).
    assert_eq!(args_of(&h, 0), ["-v", "x", "-v"]);
    assert_eq!(h.status("alias ls='ls -G'; alias l=ls"), 0);
    h.fs.write(Path::new("/bin/ls"), b"", 0o755).unwrap();
    h.on("ls", &[exited(0)]);
    assert_eq!(h.status("l /tmp"), 0);
    assert_eq!(args_of(&h, 1), ["-G", "/tmp"]);
    // A quoted name is not an alias.
    assert_eq!(h.status("'say' quoted"), 127);
    assert_eq!(h.status("unalias say; unalias say"), 1);
    assert!(h.diagnostics.text().ends_with("unalias: say: not found\n"));
}

#[test]
fn alias_builtin_errors_match_bash() {
    let mut h = Harness::new();
    // The status is the last command's, as always.
    assert_eq!(h.status("alias q; alias a/b=1; alias it=\"it's\"; alias it"), 0);
    assert_eq!(h.output.text(), "alias it='it'\\''s'\n");
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: alias: q: not found\nknsh: line 1: alias: `a/b': invalid alias name\n"
    );
    assert_eq!(h.status("unalias"), 2);
    assert!(
        h.diagnostics
            .text()
            .ends_with("unalias: usage: unalias [-a] name [name ...]\n")
    );
}

// ---- umask ----

// The shell's umask reaches the commands it starts and the files its redirections create.
#[test]
fn umask_is_printed_set_and_passed_on() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    // Until the host gives the process's umask, commands keep it and printing it is refused.
    assert_eq!(h.status("x"), 0);
    assert_eq!(h.commands.runs()[0].umask, None);
    assert_eq!(refused(h.run("umask")), Unsupported::UnknownUmask);
    assert_eq!(refused(h.run("umask g-w")), Unsupported::UnknownUmask);
    h.interpreter.state_mut().set_umask(0o022);
    assert_eq!(h.status("umask; umask -S; umask 077; umask; umask -p; x >secret"), 0);
    assert_eq!(h.output.text(), "0022\nu=rwx,g=rx,o=rx\n0077\numask 0077\n");
    assert_eq!(h.commands.runs()[1].umask, Some(0o077));
    let mode = h.fs.metadata(Path::new("/work/secret")).unwrap().mode;
    assert_eq!(mode, 0o600);
    assert_eq!(h.status("umask u=rwx,g=rx,o=; umask; umask 999"), 1);
    assert!(h.output.text().ends_with("0027\n"));
    assert_eq!(
        h.diagnostics.text(),
        "knsh: line 1: umask: 999: octal number out of range\n"
    );
}

// Untrusted input: a chain of aliases each starting with the next is bounded, in a pipeline too, rather than
// recursing until the stack runs out.
#[test]
fn alias_chains_are_bounded() {
    let mut h = Harness::with(|interpreter| interpreter.with_job_control(None));
    let mut defs = String::new();
    for index in 0..200 {
        let _ = writeln!(defs, "alias a{index}=a{}", index + 1);
    }
    assert_eq!(h.status(&defs), 0);
    assert_eq!(refused(h.run("a0")), Unsupported::Alias);
    assert_eq!(refused(h.run("a0 | a0")), Unsupported::Alias);
}

// Untrusted input: `eval` and `source` that run themselves end at the nesting limit with an error, never a stack
// overflow.
#[test]
fn recursive_eval_and_source_end_at_the_depth_limit() {
    let mut h = Harness::new();
    assert_eq!(
        h.run(r#"x='eval "$x"'; eval "$x""#),
        Err(InterpError::DepthExceeded { limit: MAX_EVAL_DEPTH })
    );
    h.fs.write(Path::new("/work/self.sh"), b". ./self.sh\n", 0o644).unwrap();
    assert_eq!(
        h.run(". ./self.sh"),
        Err(InterpError::DepthExceeded { limit: MAX_EVAL_DEPTH })
    );
    // An alias inside `eval` inside a pipeline, nested again and again.
    let mut h = Harness::with(|interpreter| interpreter.with_job_control(None));
    assert_eq!(h.status("alias e='eval \"$x\" | :'"), 0);
    assert!(matches!(
        h.run("x='e'; e"),
        Err(InterpError::DepthExceeded { .. } | InterpError::Unsupported { .. })
    ));
}
