//! The interpreters whose command lines can carry code, as data (KNSH-036; FR-LC-05, FR-POL-20).
//!
//! `sh -c 'rm -rf x'`, `python3 -c '…'` and `node -e '…'` run a program written on the command line, which the parser
//! cannot decide: they are dynamic code. `python3 script.py` runs a file, which is not dynamic by the spec's list: it is
//! decided by the interpreter's own resolution (`static` or `project_executable`). An interpreter given no script reads
//! its program from standard input (`curl … | bash`), which is dynamic too.
//!
//! Each [`Interpreter`] entry describes one family's option grammar just far enough to tell those cases apart; the
//! [defaults](Interpreters::defaults) cover the shells, python, node, ruby, perl, php, deno, bun and osascript, and a
//! profile can add families or options ([`Interpreters::extend`]). A family is matched by the base name of the
//! *resolved* binary with any version suffix removed, so `/opt/homebrew/…/python3.12` is `python`
//! ([`family_of`]).
//!
//! # How a command line is read
//!
//! The arguments are scanned from the left, as the interpreter's own option parser would, until the first operand:
//!
//! - an option in [`code_options`](Interpreter::code_options) (`-c`, `-e`, `--eval`) makes the command
//!   [`InterpreterCode`](crate::DynamicReason::InterpreterCode), and one in
//!   [`stdin_options`](Interpreter::stdin_options) (`bash -s`, `python3 -i`), or the operand `-`, makes it
//!   [`InterpreterStdin`](crate::DynamicReason::InterpreterStdin);
//! - an option in [`value_options`](Interpreter::value_options) takes the next argument as its value unless one is
//!   attached (`-W error`, `-Werror`, `--require=x`); one in [`script_options`](Interpreter::script_options) names the
//!   program to run, like a script operand (`python3 -m pip`);
//! - short options cluster (`bash -ec`, `perl -lane`), each letter read in turn until one takes a value; `+` starts
//!   a cluster like `-` (`bash +o posix`). Any other letter is read as a flag, so an option's optional attached value
//!   (`perl -i.bak`, `perl -l`) is scanned as more letters: that can only find a code option that is not there
//!   (`perl -i.e`), never miss one (`perl -lane`). The POSIX shells read a value option inside a cluster differently
//!   ([`cluster_values_from_next`](Interpreter::cluster_values_from_next)): it takes the *next* argument and the cluster
//!   goes on, so `bash -oc errexit 'code'` is code;
//! - a long option the table does not know may take the next argument as its value (`zsh --emulate sh -c code`,
//!   `ruby --disable gems -e code`), so an operand right after one is only a possible script: reading goes on as if
//!   it were that value, and a code option found later still makes the line code;
//! - the first operand is the script, unless it is one of [`code_subcommands`](Interpreter::code_subcommands)
//!   (`deno eval`), which is code, or names standard input (`bash /dev/stdin`, `/dev/fd/0`), which reads it.
//!
//! With no operand, the interpreter reads standard input when
//! [`reads_stdin_without_script`](Interpreter::reads_stdin_without_script) is set, unless an
//! [`info_options`](Interpreter::info_options) entry (`--version`) means it runs nothing.
//!
//! Errors lean towards dynamic: a long option the table does not know is read both with and without a value, and an
//! argument built from an expansion before the script (`bash $FLAGS x`, `python3 "$f"`) is
//! [`ExpandedArgument`](crate::DynamicReason::ExpandedArgument), since it could be `-c`. A wrong table can still read
//! code as a script when an unlisted option's value is itself a listed value option (`node --unlisted -r -e code`),
//! or for an unlisted *short* option that takes a separate value; the defaults list the value options of each family
//! for that reason. A script that is a symbolic link to standard input is not seen either. A parser result is an
//! intent filter, never a security boundary: dynamic code's limits come from the sandbox and the proxy (FR-POL-21).

use crate::error::InterpreterTableError;

/// One interpreter family and the parts of its option grammar that matter for dynamic code. See the module
/// documentation for how a command line is read with it.
///
/// Options are written as on the command line: a short option is `-` and one character (`-c`), and clusters with
/// other short options; a long option is `--` and a name (`--eval`), and also matches `--eval=value`. Single-dash
/// long options (`-Command`) are not read as such: they are read as clusters, which can only add dynamic marks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interpreter {
    /// The family name: a resolved binary's base name with any version suffix removed (`python` for `python3.12`).
    pub family: String,
    /// Options whose value, or whose presence, makes the command line a program (`-c`, `-e`, `--eval`).
    pub code_options: Vec<String>,
    /// Options that make the interpreter read its program from standard input (`bash -s`, `python3 -i`).
    pub stdin_options: Vec<String>,
    /// Options that take the next argument as their value when none is attached (`python3 -W error`).
    pub value_options: Vec<String>,
    /// Options whose value names the program to run, which then counts as the script (`python3 -m pip`).
    pub script_options: Vec<String>,
    /// Options that make the interpreter run nothing when no script is given (`--version`, `--help`).
    pub info_options: Vec<String>,
    /// First operands that are not a script but run code (`deno eval`, `deno repl`).
    pub code_subcommands: Vec<String>,
    /// Whether the interpreter reads its program from standard input when given no script (`bash`, `python3`), as
    /// opposed to printing help (`bun`).
    pub reads_stdin_without_script: bool,
    /// Whether a value option inside a cluster takes the next argument as its value and the rest of the cluster is
    /// read as more options, as the POSIX shells do (`bash -oc errexit 'code'` runs `code`), rather than taking the
    /// rest of the cluster as its value (`python3 -Werror`).
    pub cluster_values_from_next: bool,
}

/// The built-in description of one family, as static data.
struct Defaults {
    families: &'static [&'static str],
    code: &'static [&'static str],
    stdin: &'static [&'static str],
    value: &'static [&'static str],
    script: &'static [&'static str],
    info: &'static [&'static str],
    subcommands: &'static [&'static str],
    reads_stdin: bool,
    cluster_values_from_next: bool,
}

/// The default table. The shells share one grammar; `fish` adds its init command. Every entry was written from the
/// interpreter's manual page (`bash(1)`, `python3(1)`, `node --help`, `ruby(1)`, `perlrun(1)`, `php(1)`,
/// `deno --help`, `bun --help`, `osascript(1)`).
const DEFAULTS: &[Defaults] = &[
    Defaults {
        families: &[
            "sh", "bash", "rbash", "zsh", "dash", "ash", "ksh", "mksh", "oksh", "pdksh", "yash", "csh", "tcsh",
        ],
        code: &["-c"],
        stdin: &["-s"],
        value: &["-o", "-O", "--rcfile", "--init-file"],
        script: &[],
        info: &["--version", "--help"],
        subcommands: &[],
        reads_stdin: true,
        cluster_values_from_next: true,
    },
    Defaults {
        families: &["fish"],
        code: &["-c", "-C", "--command", "--init-command"],
        stdin: &[],
        value: &[
            "-d",
            "--debug",
            "-o",
            "--debug-output",
            "--features",
            "--profile",
            "--profile-startup",
        ],
        script: &[],
        info: &["-v", "--version", "-h", "--help"],
        subcommands: &[],
        reads_stdin: true,
        cluster_values_from_next: false,
    },
    Defaults {
        families: &["python", "pypy"],
        code: &["-c"],
        stdin: &["-i"],
        value: &["-W", "-X", "-Q", "--check-hash-based-pycs"],
        script: &["-m"],
        info: &[
            "-V",
            "--version",
            "-h",
            "-?",
            "--help",
            "--help-env",
            "--help-xoptions",
            "--help-all",
        ],
        subcommands: &[],
        reads_stdin: true,
        cluster_values_from_next: false,
    },
    Defaults {
        families: &["node", "nodejs"],
        code: &["-e", "-p", "--eval", "--print"],
        stdin: &["-i", "--interactive"],
        value: &[
            "-r",
            "-C",
            "--require",
            "--import",
            "--loader",
            "--experimental-loader",
            "--conditions",
            "--input-type",
            "--title",
            "--env-file",
            "--env-file-if-exists",
            "--inspect-port",
            "--debug-port",
            "--redirect-warnings",
            "--diagnostic-dir",
            "--report-dir",
            "--report-directory",
            "--report-filename",
            "--report-signal",
            "--secure-heap",
            "--secure-heap-min",
            "--stack-trace-limit",
            "--trace-event-categories",
            "--trace-event-file-pattern",
            "--unhandled-rejections",
            "--watch-path",
            "--disable-warning",
            "--icu-data-dir",
            "--openssl-config",
            "--tls-cipher-list",
            "--use-largepages",
            "--run",
        ],
        script: &[],
        info: &["-v", "--version", "-h", "--help", "--v8-options"],
        subcommands: &[],
        reads_stdin: true,
        cluster_values_from_next: false,
    },
    Defaults {
        families: &["ruby"],
        code: &["-e"],
        stdin: &[],
        value: &[
            "-I",
            "-r",
            "-C",
            "-E",
            "--encoding",
            "--external-encoding",
            "--internal-encoding",
        ],
        script: &[],
        info: &["--version", "-h", "--help"],
        subcommands: &[],
        reads_stdin: true,
        cluster_values_from_next: false,
    },
    Defaults {
        families: &["perl"],
        code: &["-e", "-E"],
        stdin: &[],
        value: &["-I", "-M", "-m"],
        script: &[],
        info: &["-v", "-V", "-h", "--version", "--help"],
        subcommands: &[],
        reads_stdin: true,
        cluster_values_from_next: false,
    },
    Defaults {
        families: &["php"],
        code: &["-r", "-B", "-R", "-E"],
        stdin: &["-a"],
        value: &["-c", "-d", "-z", "-t"],
        script: &["-f", "-F", "-S"],
        info: &[
            "-v",
            "-h",
            "-i",
            "-m",
            "--version",
            "--help",
            "--info",
            "--modules",
            "--ini",
        ],
        subcommands: &[],
        reads_stdin: true,
        cluster_values_from_next: false,
    },
    Defaults {
        families: &["deno"],
        code: &[],
        stdin: &[],
        value: &[],
        script: &[],
        info: &["-V", "--version", "-h", "--help"],
        subcommands: &["eval", "repl"],
        reads_stdin: true,
        cluster_values_from_next: false,
    },
    Defaults {
        families: &["bun"],
        code: &["-e", "-p", "--eval", "--print"],
        stdin: &[],
        value: &["-r", "--preload", "--cwd", "--env-file", "--config", "-c"],
        script: &[],
        info: &["-v", "--version", "-h", "--help"],
        subcommands: &["repl"],
        reads_stdin: false,
        cluster_values_from_next: false,
    },
    Defaults {
        families: &["osascript"],
        code: &["-e"],
        stdin: &["-i"],
        value: &["-l", "-s"],
        script: &[],
        info: &[],
        subcommands: &[],
        reads_stdin: true,
        cluster_values_from_next: false,
    },
];

/// What an interpreter's command line runs, as far as dynamic code is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InterpreterRun {
    /// Code written on the command line (`-c`, `-e`, `deno eval`).
    Code,
    /// A program read from standard input or from arguments supplied at run time.
    Stdin,
    /// An argument before the script is built from an expansion, so it could be a code option.
    Expanded,
    /// A script file or module, or nothing at all (`--version`): not dynamic by itself.
    Script,
}

/// An argument as the classifier sees it: its text after quote removal, or `None` when it is built from an expansion
/// (or from text a wrapper supplies at run time), so its value is not known from the line.
pub(crate) type ArgumentText<'a> = Option<&'a str>;

impl Interpreter {
    /// An entry for `family` with no options, which reads standard input when given no script. Add options by setting
    /// the public fields.
    #[must_use]
    pub fn new(family: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            code_options: Vec::new(),
            stdin_options: Vec::new(),
            value_options: Vec::new(),
            script_options: Vec::new(),
            info_options: Vec::new(),
            code_subcommands: Vec::new(),
            reads_stdin_without_script: true,
            cluster_values_from_next: false,
        }
    }

    /// The entry for one family of the defaults.
    fn from_defaults(family: &str, defaults: &Defaults) -> Self {
        let owned = |options: &[&str]| options.iter().map(|option| (*option).to_owned()).collect();
        Self {
            family: family.to_owned(),
            code_options: owned(defaults.code),
            stdin_options: owned(defaults.stdin),
            value_options: owned(defaults.value),
            script_options: owned(defaults.script),
            info_options: owned(defaults.info),
            code_subcommands: owned(defaults.subcommands),
            reads_stdin_without_script: defaults.reads_stdin,
            cluster_values_from_next: defaults.cluster_values_from_next,
        }
    }

    /// Checks the entry's shape: a family name that could be a base name, and options spelled `-x` or `--name`.
    fn validate(&self) -> Result<(), InterpreterTableError> {
        if self.family.is_empty() || self.family.contains(['/', '\0']) || family_of(&self.family) != self.family {
            return Err(InterpreterTableError::InvalidFamily {
                family: self.family.clone(),
            });
        }
        let options = [
            &self.code_options,
            &self.stdin_options,
            &self.value_options,
            &self.script_options,
            &self.info_options,
        ];
        for option in options.into_iter().flatten() {
            if !is_option_spelling(option) {
                return Err(InterpreterTableError::InvalidOption {
                    family: self.family.clone(),
                    option: option.clone(),
                });
            }
        }
        Ok(())
    }

    /// Adds `other`'s options to this entry, keeping its own. Extending never removes an option or turns off
    /// reading standard input or reading clusters the shells' way, so a profile can only make detection stricter.
    fn merge(&mut self, other: Self) {
        let lists = [
            (&mut self.code_options, other.code_options),
            (&mut self.stdin_options, other.stdin_options),
            (&mut self.value_options, other.value_options),
            (&mut self.script_options, other.script_options),
            (&mut self.info_options, other.info_options),
            (&mut self.code_subcommands, other.code_subcommands),
        ];
        for (mine, theirs) in lists {
            for item in theirs {
                if !mine.contains(&item) {
                    mine.push(item);
                }
            }
        }
        self.reads_stdin_without_script |= other.reads_stdin_without_script;
        self.cluster_values_from_next |= other.cluster_values_from_next;
    }

    /// What the command line `arguments` (after the interpreter's name) runs. `complete` is `false` when more
    /// arguments are supplied at run time (`xargs python3`), which then may hold the script or a code option.
    pub(crate) fn run(&self, arguments: &[ArgumentText<'_>], complete: bool) -> InterpreterRun {
        let mut info = false;
        let mut index = 0;
        // Set while the previous argument was a long option the table does not know: it may take this argument as
        // its value.
        let mut after_unknown = false;
        // Set once an operand was read that may instead have been an unknown option's value: it is the script in
        // one reading, and the scan goes on in the other, where only a dynamic answer can change the result.
        let mut tentative_script = false;
        while let Some(argument) = arguments.get(index) {
            let Some(argument) = *argument else {
                return InterpreterRun::Expanded;
            };
            index += 1;
            let maybe_value = std::mem::take(&mut after_unknown);
            if argument == "--" {
                let after = match arguments.get(index) {
                    Some(Some(operand)) => self.operand(operand),
                    Some(None) => InterpreterRun::Expanded,
                    None if tentative_script => InterpreterRun::Script,
                    None => self.without_script(info, complete),
                };
                if after != InterpreterRun::Script || !maybe_value {
                    return after;
                }
                // `--` may be the unknown option's value: read on as options.
                tentative_script = true;
                continue;
            }
            if argument == "-" {
                return InterpreterRun::Stdin;
            }
            let step = if let Some(long) = argument.strip_prefix("--") {
                self.long_option(long)
            } else if let Some(cluster) = argument.strip_prefix(['-', '+']).filter(|cluster| !cluster.is_empty()) {
                self.cluster(cluster)
            } else {
                let run = self.operand(argument);
                if run == InterpreterRun::Script && maybe_value {
                    tentative_script = true;
                    continue;
                }
                return run;
            };
            match step {
                Step::Run(run) => return run,
                Step::Info => info = true,
                Step::Flag => {}
                Step::Unknown => after_unknown = true,
                Step::TakesNext(count) => {
                    for _ in 0..count {
                        match arguments.get(index) {
                            Some(Some(_)) => index += 1,
                            // An unquoted expansion as a value may split into several words, one of them a code
                            // option.
                            Some(None) => return InterpreterRun::Expanded,
                            None => break,
                        }
                    }
                }
            }
        }
        if tentative_script {
            InterpreterRun::Script
        } else {
            self.without_script(info, complete)
        }
    }

    /// What `--name` or `--name=value` does.
    fn long_option(&self, long: &str) -> Step {
        let (name, attached) = match long.split_once('=') {
            Some((name, _)) => (name, true),
            None => (long, false),
        };
        let listed = |options: &[String]| options.iter().any(|option| option.strip_prefix("--") == Some(name));
        if listed(&self.code_options) {
            Step::Run(InterpreterRun::Code)
        } else if listed(&self.stdin_options) {
            Step::Run(InterpreterRun::Stdin)
        } else if listed(&self.script_options) {
            Step::Run(InterpreterRun::Script)
        } else if listed(&self.value_options) && !attached {
            Step::TakesNext(1)
        } else if listed(&self.info_options) {
            Step::Info
        } else if attached {
            Step::Flag
        } else {
            Step::Unknown
        }
    }

    /// What a cluster of short options (`ec` in `-ec`) does, read letter by letter as `getopt` would.
    fn cluster(&self, cluster: &str) -> Step {
        let mut info = false;
        let mut values = 0;
        for (offset, letter) in cluster.char_indices() {
            let listed = |options: &[String]| options.iter().any(|option| short_letter(option) == Some(letter));
            let rest_empty = cluster.len() == offset + letter.len_utf8();
            if listed(&self.code_options) {
                return Step::Run(InterpreterRun::Code);
            }
            if listed(&self.stdin_options) {
                return Step::Run(InterpreterRun::Stdin);
            }
            if listed(&self.script_options) {
                return Step::Run(InterpreterRun::Script);
            }
            if listed(&self.value_options) {
                if self.cluster_values_from_next {
                    // The shells: the value is the next argument (one per value option), and the cluster goes on.
                    values += 1;
                    continue;
                }
                // The rest of the cluster is the value, or the next argument when nothing is attached.
                return if rest_empty { Step::TakesNext(1) } else { Step::Flag };
            }
            info |= listed(&self.info_options);
        }
        if values > 0 {
            Step::TakesNext(values)
        } else if info {
            Step::Info
        } else {
            Step::Flag
        }
    }

    /// What the first operand runs: a script, code for a code subcommand, or standard input for a path naming it.
    fn operand(&self, operand: &str) -> InterpreterRun {
        if self.code_subcommands.iter().any(|subcommand| subcommand == operand) {
            InterpreterRun::Code
        } else if names_standard_input(operand) {
            InterpreterRun::Stdin
        } else {
            InterpreterRun::Script
        }
    }

    /// What a command line with no script runs.
    fn without_script(&self, info: bool, complete: bool) -> InterpreterRun {
        if !complete {
            // The arguments supplied at run time may be the script, `-c` or `-`: unknown.
            InterpreterRun::Stdin
        } else if info || !self.reads_stdin_without_script {
            InterpreterRun::Script
        } else {
            InterpreterRun::Stdin
        }
    }
}

/// What one option does to the scan.
enum Step {
    /// It decides the command line.
    Run(InterpreterRun),
    /// It means the interpreter runs nothing without a script.
    Info,
    /// A flag, or an option whose value is attached: go on.
    Flag,
    /// A long option the table does not know, with no attached value: it may take the next argument.
    Unknown,
    /// Options whose values are the next arguments, this many.
    TakesNext(usize),
}

/// The interpreter families the classifier knows: the [defaults](Self::defaults), plus what a profile adds.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interpreters {
    /// One entry per family, defaults first.
    entries: Vec<Interpreter>,
}

impl Interpreters {
    /// The built-in table: `sh`, `bash`, `zsh` and the other shells, `python` (and `pypy`), `node`, `ruby`, `perl`,
    /// `php`, `deno`, `bun` and `osascript`.
    #[must_use]
    pub fn defaults() -> Self {
        let entries = DEFAULTS
            .iter()
            .flat_map(|defaults| {
                defaults
                    .families
                    .iter()
                    .map(move |family| Interpreter::from_defaults(family, defaults))
            })
            .collect();
        Self { entries }
    }

    /// Adds a family, or adds options to one already known (a profile's `exec.interpreters` entries). Extending
    /// never removes anything, so a profile can only make detection stricter.
    ///
    /// # Errors
    ///
    /// [`InterpreterTableError`] when the family name is empty, holds `/`, or ends in a version suffix (`python3`; the
    /// family is `python`), or an option is not spelled `-x` or `--name`. The
    /// table is left unchanged.
    pub fn extend(&mut self, interpreter: Interpreter) -> Result<(), InterpreterTableError> {
        interpreter.validate()?;
        match self.entries.iter_mut().find(|entry| entry.family == interpreter.family) {
            Some(entry) => entry.merge(interpreter),
            None => self.entries.push(interpreter),
        }
        Ok(())
    }

    /// The entries, defaults first, then families added in order.
    #[must_use]
    pub fn entries(&self) -> &[Interpreter] {
        &self.entries
    }

    /// The entry for the program named `program` (a path or a base name), by its [family](family_of).
    #[must_use]
    pub fn find(&self, program: &str) -> Option<&Interpreter> {
        let family = family_of(program);
        self.entries.iter().find(|entry| entry.family == family)
    }
}

impl Default for Interpreters {
    fn default() -> Self {
        Self::defaults()
    }
}

/// The family of a program: the last part of its path without a version suffix (trailing digits and dots, then a
/// trailing `-`), so `/opt/homebrew/bin/python3.12` and `python3` are `python`, and `perl5.34` is `perl`.
///
/// # Examples
///
/// ```
/// assert_eq!(knsh_bash::family_of("/usr/local/bin/python3.12"), "python");
/// assert_eq!(knsh_bash::family_of("node"), "node");
/// ```
#[must_use]
pub fn family_of(program: &str) -> &str {
    let base = program.rsplit('/').next().unwrap_or(program);
    base.trim_end_matches(|character: char| character.is_ascii_digit() || character == '.')
        .trim_end_matches('-')
}

/// Whether a script path names the interpreter's standard input (`/dev/stdin`, `/dev/fd/0`, `/proc/self/fd/0`),
/// after removing empty, `.` and `..` components, as the kernel would for these directories.
fn names_standard_input(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component),
        }
    }
    matches!(
        components.as_slice(),
        ["dev", "stdin"] | ["dev", "fd", ..] | ["proc", _, "fd", ..]
    )
}

/// The letter of a short option spelled `-x`.
fn short_letter(option: &str) -> Option<char> {
    let mut characters = option.strip_prefix('-')?.chars();
    let letter = characters.next().filter(|letter| *letter != '-')?;
    characters.next().is_none().then_some(letter)
}

/// Whether `option` is spelled `-x` or `--name`, with no `=` and no blank.
fn is_option_spelling(option: &str) -> bool {
    let long = option
        .strip_prefix("--")
        .is_some_and(|name| !name.is_empty() && !name.contains(['=', ' ', '\t', '\n']));
    long || short_letter(option).is_some_and(|letter| !letter.is_whitespace() && letter != '=')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `program` with `line` (split on blanks; a word holding `$` is an expansion) runs.
    fn run(program: &str, line: &str) -> InterpreterRun {
        let table = Interpreters::defaults();
        let words: Vec<ArgumentText<'_>> = line
            .split_whitespace()
            .map(|word| (!word.contains('$')).then_some(word))
            .collect();
        table.find(program).expect(program).run(&words, true)
    }

    // FR-LC-05: `sh -c`, `bash -c`, `zsh -c` and their clusters are code.
    #[test]
    fn shell_dash_c_is_code_even_in_a_cluster() {
        for (program, line) in [
            ("sh", "-c x"),
            ("bash", "-c x"),
            ("zsh", "-c x"),
            ("bash", "-ec x"),
            ("bash", "-xc x"),
            ("bash", "+x -c x"),
            ("bash", "-o errexit -c x"),
            ("bash", "--norc -c x"),
            ("dash", "-c x"),
        ] {
            assert_eq!(run(program, line), InterpreterRun::Code, "{program} {line}");
        }
    }

    // FR-LC-05: interpreters with `-c` or `-e`.
    #[test]
    fn interpreter_code_options_are_code() {
        for (program, line) in [
            ("python3", "-c x"),
            ("python3", "-Bc x"),
            ("python3", "-W error -c x"),
            ("node", "-e x"),
            ("node", "--eval=x"),
            ("node", "-pe x"),
            ("node", "--require ./r.js -e x"),
            ("ruby", "-e x"),
            ("perl", "-lane x"),
            ("perl", "-I lib -e x"),
            ("php", "-r x"),
            ("deno", "eval x"),
            ("deno", "repl"),
            ("bun", "-e x"),
            ("osascript", "-e x"),
        ] {
            assert_eq!(run(program, line), InterpreterRun::Code, "{program} {line}");
        }
    }

    // A value glued to its option is not read as further options: `-Wignore::DeprecationWarning` holds a `c`.
    #[test]
    fn attached_values_are_not_read_as_options() {
        assert_eq!(
            run("python3", "-Wignore::DeprecationWarning x.py"),
            InterpreterRun::Script
        );
        assert_eq!(run("perl", "-i.orig x.pl"), InterpreterRun::Script);
        // An optional attached value is scanned as letters: `-lane` is `-l -a -n -e`.
        assert_eq!(run("perl", "-lane x"), InterpreterRun::Code);
        assert_eq!(run("ruby", "-Ilib x.rb"), InterpreterRun::Script);
    }

    #[test]
    fn script_files_and_modules_are_not_code() {
        for (program, line) in [
            ("python3", "script.py -c x"),
            ("python3", "-u script.py"),
            ("python3", "-m pip install -e ."),
            ("bash", "./build.sh -c"),
            ("bash", "-- -c"),
            ("node", "server.js"),
            ("deno", "run main.ts"),
            ("php", "-S localhost:8000"),
            ("python3", "--version"),
            ("bash", "--version"),
            ("bun", ""),
            ("bun", "run dev"),
        ] {
            assert_eq!(run(program, line), InterpreterRun::Script, "{program} {line}");
        }
    }

    // An interpreter with no script reads code from its standard input (`curl … | bash`).
    #[test]
    fn interpreter_without_script_reads_stdin() {
        for (program, line) in [
            ("bash", ""),
            ("bash", "-s arg"),
            ("bash", "-x"),
            ("python3", "-"),
            ("python3", "-i x.py"),
            ("node", ""),
            ("perl", "-w"),
            ("php", "-a"),
            ("osascript", ""),
        ] {
            assert_eq!(run(program, line), InterpreterRun::Stdin, "{program} {line}");
        }
        // Arguments supplied at run time (`xargs bash`) may be the script or `-c`.
        let table = Interpreters::defaults();
        assert_eq!(table.find("bash").unwrap().run(&[], false), InterpreterRun::Stdin);
        assert_eq!(
            table.find("bash").unwrap().run(&[Some("x.sh")], false),
            InterpreterRun::Script
        );
    }

    // An expansion before the script could be `-c`.
    #[test]
    fn expansion_before_the_script_is_expanded() {
        assert_eq!(run("bash", "$FLAGS x.sh"), InterpreterRun::Expanded);
        assert_eq!(run("python3", "$SCRIPT"), InterpreterRun::Expanded);
        assert_eq!(run("python3", "-W $W x.py"), InterpreterRun::Expanded);
        assert_eq!(run("bash", "-- $X"), InterpreterRun::Expanded);
        // After the script, arguments are the script's.
        assert_eq!(run("python3", "x.py $ARGS"), InterpreterRun::Script);
    }

    // Review fix (FR-LC-05): bash and dash take `-o`/`-O`'s value from the next argument and read on in the cluster,
    // so `bash -oc errexit 'code'` runs `code`.
    #[test]
    fn shell_value_option_in_a_cluster_does_not_hide_dash_c() {
        for line in ["-oc errexit x", "-Oc extglob x", "+oc posix x", "-eoc pipefail x"] {
            assert_eq!(run("bash", line), InterpreterRun::Code, "{line}");
        }
        assert_eq!(run("sh", "-oc errexit x"), InterpreterRun::Code);
        // Each value option in the cluster takes one argument.
        assert_eq!(run("bash", "-oO errexit extglob x.sh"), InterpreterRun::Script);
        assert_eq!(run("bash", "-eo pipefail x.sh"), InterpreterRun::Script);
        assert_eq!(run("bash", "-o $O x.sh"), InterpreterRun::Expanded);
        // Elsewhere the rest of the cluster is still the value.
        assert_eq!(run("python3", "-Wc x.py"), InterpreterRun::Script);
    }

    // Review fix (FR-LC-05): a long option the table does not know may take the next argument as its value, so the
    // word after it is not taken for the script when a code option follows.
    #[test]
    fn unknown_long_option_may_take_a_value() {
        for (program, line) in [
            ("zsh", "--emulate sh -c x"),
            ("ruby", "--disable gems -e x"),
            ("node", "--allow-fs-read /tmp -e x"),
            ("node", "--unlisted -- -e x"),
            ("node", "--a v --b w -p x"),
            ("deno", "--unlisted v eval x"),
        ] {
            assert_eq!(run(program, line), InterpreterRun::Code, "{program} {line}");
        }
        assert_eq!(run("node", "--unlisted v -"), InterpreterRun::Stdin);
        // Without a code option, the possible script is the script: no false alarm for flags.
        for (program, line) in [
            ("node", "--no-warnings server.js"),
            ("node", "--enable-source-maps dist/index.js --port 3"),
            ("node", "--unlisted -- x.js"),
            ("ruby", "--disable-gems x.rb"),
            ("node", "--max-old-space-size=4096 x.js -e"),
        ] {
            assert_eq!(run(program, line), InterpreterRun::Script, "{program} {line}");
        }
    }

    // Review fix (FR-LC-05): a script path that names standard input reads the program from the pipe.
    #[test]
    fn script_naming_standard_input_reads_stdin() {
        for (program, line) in [
            ("bash", "/dev/stdin"),
            ("bash", "/dev/../dev/stdin"),
            ("python3", "//dev/./fd/0"),
            ("node", "/proc/self/fd/0"),
            ("ruby", "-- /dev/fd/3"),
        ] {
            assert_eq!(run(program, line), InterpreterRun::Stdin, "{program} {line}");
        }
        assert_eq!(run("bash", "dev/stdin"), InterpreterRun::Script);
        assert_eq!(run("bash", "/dev/stdin.sh"), InterpreterRun::Script);
    }

    #[test]
    fn family_strips_path_and_version_suffix() {
        assert_eq!(family_of("/opt/homebrew/bin/python3.12"), "python");
        assert_eq!(family_of("python3"), "python");
        assert_eq!(family_of("perl5.34"), "perl");
        assert_eq!(family_of("ruby-3.2"), "ruby");
        assert_eq!(family_of("node"), "node");
        assert_eq!(family_of("/bin/sh"), "sh");
        assert!(Interpreters::defaults().find("/usr/bin/python3.12").is_some());
        assert!(Interpreters::defaults().find("/usr/bin/git").is_none());
    }

    #[test]
    fn every_default_entry_is_valid_and_unique() {
        let table = Interpreters::defaults();
        let mut families: Vec<&str> = table.entries().iter().map(|entry| entry.family.as_str()).collect();
        for entry in table.entries() {
            assert_eq!(entry.validate(), Ok(()), "{}", entry.family);
        }
        let count = families.len();
        families.sort_unstable();
        families.dedup();
        assert_eq!(families.len(), count);
        for family in [
            "sh",
            "bash",
            "zsh",
            "python",
            "node",
            "ruby",
            "perl",
            "php",
            "deno",
            "bun",
            "osascript",
        ] {
            assert!(table.find(family).is_some(), "{family}");
        }
    }

    // The list is extendable by profile; extending only adds.
    #[test]
    fn profile_can_add_families_and_options_but_not_remove() {
        let mut table = Interpreters::defaults();
        let mut lua = Interpreter::new("lua");
        lua.code_options.push("-e".to_owned());
        lua.value_options.push("-l".to_owned());
        table.extend(lua).unwrap();
        let words = [Some("-l"), Some("socket"), Some("-e"), Some("x")];
        assert_eq!(table.find("lua5.4").unwrap().run(&words, true), InterpreterRun::Code);

        // Re-declaring python with nothing keeps its options and its reading of standard input.
        let mut python = Interpreter::new("python");
        python.reads_stdin_without_script = false;
        python.code_options.push("--exec".to_owned());
        table.extend(python).unwrap();
        let python = table.find("python3").unwrap();
        assert!(!python.cluster_values_from_next);
        assert!(python.code_options.contains(&"-c".to_owned()));
        assert!(python.code_options.contains(&"--exec".to_owned()));
        assert!(python.reads_stdin_without_script);
        // Re-declaring a shell without the shells' cluster reading keeps it.
        let mut bash = Interpreter::new("bash");
        bash.cluster_values_from_next = false;
        table.extend(bash).unwrap();
        assert!(table.find("bash").unwrap().cluster_values_from_next);
    }

    #[test]
    fn invalid_entries_are_refused_and_leave_the_table_unchanged() {
        let mut table = Interpreters::defaults();
        let before = table.clone();
        for family in ["", "/usr/bin/lua", "lua5"] {
            assert!(matches!(
                table.extend(Interpreter::new(family)),
                Err(InterpreterTableError::InvalidFamily { .. })
            ));
        }
        for option in ["e", "-", "--", "-ab", "--x=y", "--a b"] {
            let mut entry = Interpreter::new("lua");
            entry.code_options.push(option.to_owned());
            assert!(
                matches!(table.extend(entry), Err(InterpreterTableError::InvalidOption { .. })),
                "{option}"
            );
        }
        assert_eq!(table, before);
    }
}
