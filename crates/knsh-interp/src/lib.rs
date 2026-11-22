//! Native bash interpreter: evaluates the syntax tree [`knsh_bash::parse`] builds (phase 4, KNSH-096).
//!
//! Phase 4 replaces "one stock interpreter per line" with `knsh`'s own bash-compatible interpreter, so the supervisor
//! can decide on every simple command, including inside scripts (`specs/00-stories/README.md`, phase 4). This crate
//! is its execution engine. KNSH-096 is the core: shell state ([`ShellState`]: variables, positional parameters,
//! `$?`, an options placeholder, the working directory) and an evaluator ([`Interpreter`]) for simple commands that
//! run external programs, `;` and newline lists, `&&`, `||`, `!`, `if`, `for`, `while`, `until`, `case` and `{ }`
//! groups, with bash's exit statuses ([`Status`]). KNSH-097 adds tilde, parameter and arithmetic expansion (every
//! `${…}` operator of bash 5.2 but arrays and `@P`), `(( ))`, arithmetic `for` and `let`, and `set -u`
//! ([`ShellOptions::nounset`]); [`evaluate_arithmetic`] evaluates one arithmetic expression on its own. KNSH-098
//! adds brace expansion, `IFS` word splitting, pathname expansion (with `set -f` and the `dotglob`, `nullglob`,
//! `failglob`, `nocaseglob`, `globstar` and `extglob` options of [`ShellOptions`]), `$'…'` and quote removal, in
//! bash's order. KNSH-099 adds every redirection but here-documents (`< > >> >| <> <& >& &> &>> <<<`, numbered and
//! `{name}` descriptors, closing with `-`, moving with `n-`, `set -C` as [`ShellOptions::noclobber`]), applied left to
//! right on the shell's own descriptor table and undone after each command, `exec` with redirections only (kept for
//! the shell's life) and `:`; `/dev/stdin`, `/dev/stdout`, `/dev/stderr` and `/dev/fd/N` name the shell's
//! descriptors, and `/dev/tcp` and `/dev/udp` are refused (FR-NET-08). KNSH-100 adds pipelines (`|`, `|&`,
//! `PIPESTATUS`, `pipefail` and `lastpipe` as [`ShellOptions`]), `( … )` subshells, background jobs (`&`, `$!`), the
//! job builtins `wait` (with `-n`), `jobs`, `fg`, `bg` and `disown`, the `time` keyword, and job control (`set -m`
//! as [`ShellOptions::monitor`]; an interactive shell with its terminal through [`Interpreter::with_job_control`],
//! and [`JobSignals`] for the supervisor's pause, FR-SES-10). KNSH-101 adds the core builtins: `cd` (with `CDPATH`,
//! `-L`, `-P` and `OLDPWD`; the host is told of each change through a [`DirectoryObserver`], [`Osc7`] writing
//! OSC 7), `pwd`, `export`, `unset`, `readonly`, `declare` and `typeset` (variable attributes), `local`, `shift`, `set` for the positional parameters, `exit`, `return`,
//! `break`, `continue`, `true`, `false`, `:`, `echo` (with [`ShellOptions::xpg_echo`]), `eval`, `source` and `.`,
//! `command`, `builtin`, `type`, `hash` (bash's command hash table), `alias` and `unalias` (expanded with
//! [`ShellOptions::expand_aliases`]), `umask` (passed to every command and redirection) and `exec` with a command.
//! KNSH-102 adds `test` and `[` (bash's argument-count rules, file tests through [`knsh_platform::Fs::status`]),
//! `[[ … ]]` (no splitting or pathname expansion, `==` patterns with extended-glob groups, `=~` through the system's
//! POSIX regular expressions with `BASH_REMATCH`), `printf` (every bash conversion, `%q`, `%(…)T` through the host's
//! [`knsh_platform::LocalTime`] given with [`Interpreter::with_local_time`], `-v`) and `read` (`-r -d -n -N -p -s
//! -t -u`, `IFS` splitting, timeouts at status 142), reading the spawner's standard input given with
//! [`Interpreter::with_standard_descriptors`]. KNSH-103 adds functions (both syntaxes, `return`, `FUNCNEST`, the
//! call stack in `FUNCNAME`, `BASH_SOURCE` and `BASH_LINENO`), bash's dynamic scopes (`local`, `declare` in a
//! function, `declare -g`), sparse indexed and associative arrays (in bash 5.2's hash order) with every array
//! expansion, subscript and slice, arrays in arithmetic, name references (`declare -n`), `read -a` and
//! `mapfile`/`readarray`. Scripts must be parsed with [`knsh_bash::ParseOptions::arrays`] for array assignments.
//! KNSH-104 adds `trap` (`EXIT`, `ERR`, `DEBUG`, `RETURN` and signals, with bash's inheritance by functions and
//! subshells), `set` with every option letter and `-o` name of bash 5.2 and `shopt` (each option either implemented
//! in [`ShellOptions`] or held at bash's default, changing it refused): `set -e` with bash's exemptions, `-x` with
//! `PS4`, `-v`, `-n`, `-E` and `-T`. The host hands the shell the signals sent to it through [`ShellSignals`]
//! ([`Interpreter::shell_signals`]) and the signals it was started ignoring through
//! [`ShellState::with_ignored_signals`]; [`Interpreter::terminating_signal`] and [`Interpreter::finish`] end it as
//! bash ends. KNSH-105 adds command substitution (`$(…)` and backquotes: the output without its trailing newlines,
//! split and matched against file names unless quoted, `$?` its status, `$(< file)`), process substitution (`<(…)`
//! and `>(…)` as `/dev/fd/N`, closed after their command), here-documents (`<<`, `<<-`, quoted delimiters) and
//! `coproc` (named and `COPROC` arrays, `NAME_PID`); each substitution and coprocess runs in a copy of the shell on a
//! thread of its own, so its commands start through the same spawner. Scripts using `coproc` must be parsed with
//! [`knsh_bash::ParseOptions::coproc`]. KNSH-106 adds bash's POSIX mode, not as a dialect but as the flag
//! [`ShellOptions::posix`] read where bash 5.2 reads `posixly_correct`: a host starting a shell as `sh` or with
//! `--posix` ([`posix_mode_requested`]) uses [`ShellState::with_posix_mode`]; `set -o posix` and `POSIXLY_CORRECT`
//! turn it on from the script or the environment. Special builtins are found before functions, assignments before
//! them persist, and their usage errors, redirection and assignment errors end a non-interactive shell (unless
//! `command` runs them), as do the expansion, `.`, `eval`, `for` and function-name errors bash makes fatal there;
//! tilde, redirection-word, `echo` (macOS `/bin/sh`'s), `trap`, `alias`, `export -p`, `shift`, `break`, `type`,
//! `cd`, hash and job-status differences follow bash's list.
//!
//! # Boundaries
//!
//! - The tree is consumed unchanged: there is no second parser of commands. Words are expanded from the parser's
//!   segments; only the bodies the parser keeps whole (`${…}`, `$((…))`, `(( … ))`) are read again, as bash reads
//!   them when it expands them. `case` patterns, the pattern operators and pathname expansion match with bash's
//!   `*`, `?`, bracket and (with `extglob`) group rules. A script using `extglob` groups in its own text is parsed
//!   with [`knsh_bash::parse_with`]; so is a script using `{name}>file` (with
//!   [`knsh_bash::ParseOptions::redirection_variables`], as bash 4.1 and later read it).
//! - Every effect goes through an injected trait from `knsh-platform`: commands are looked up and directories read
//!   for pathname expansion through [`knsh_platform::Fs`], file names sorted through [`knsh_platform::Collation`]
//!   (bash's `strcoll` order), redirection files opened through [`knsh_platform::Descriptors`], and commands run
//!   through [`knsh_platform::CommandSpawner`] with exactly the shell's descriptor table, so tests run without
//!   processes or a real filesystem and no descriptor of the interpreter's own process reaches a command. That spawner is where KNSH-108 decides each command: a native-mode agent line's interpreter runs with
//!   `knsh_platform::supervision::SupervisedSpawner`, which asks the supervisor to decide and start every command
//!   (with its real argv, after expansion) and fails closed.
//! - A subshell is a copy of the interpreter, never a forked process (the process is multithreaded, and every program
//!   must start through the spawner): pipeline stages and background lists that the shell runs itself run on threads
//!   of their own (decision 19). Children are known by handle, waited for by one thread each, and a job's process
//!   group is signalled only while one of its members is held unreaped.
//! - What later stories implement (a substitution inside the text the interpreter reads again
//!   itself: `[[ … ]]`, `(( … ))`, `$(( … ))`) is refused with [`InterpError::Unsupported`] by a check of the whole
//!   script before anything runs (substitution bodies included), or, when only an expansion's value reveals it (or
//!   `eval` and `source` text), when it is reached. `[[ … ]]`, which
//!   the parser keeps whole, is read again from its text with the same lexer, as `(( … ))` bodies are; one bash's
//!   parser would reject is refused by that check.
//! - Regular expressions are the system's `regcomp` and `regexec` ([`knsh_platform::regex_match`], decision 21):
//!   the engine bash itself calls, so `=~` matches exactly as bash's; no new crate.
//! - `eval`, `source` and alias text are parsed, checked and evaluated by the same parser and evaluator as the
//!   script, so every program in them starts through the same spawner (KNSH-108). `cd` changes the interpreter's
//!   working directory, never the process's, and `exec cmd` runs the program and then ends the shell (decision 20).
//! - Nesting is bounded by an explicit, documented limit ([`MAX_EVAL_DEPTH`]) that fails with
//!   [`InterpError::DepthExceeded`], on an evaluation thread whose stack ([`EVAL_STACK_SIZE`]) holds that many
//!   levels. Loops have no iteration limit, as in bash. Brace and pathname expansion are bounded in words, size and
//!   directory entries read, failing with [`InterpError::ExpansionLimit`].
//! - No `unsafe`, no I/O of its own beyond the injected traits and the diagnostics and output writers, no
//!   third-party crates.
//!
//! # Specification
//!
//! - `specs/00-stories/KNSH-096-interpreter-core-and-ast-evaluator.md`
//! - `specs/00-stories/KNSH-099-redirections-and-descriptor-management.md`, `specs/09-reference/decisions.md`
//!   (decision 18: network redirections refused)
//! - `specs/04-non-functional-requirements/compatibility.md` (NFR-COMPAT-01: bash semantics; NFR-COMPAT-02: corpus
//!   behaviour; NFR-COMPAT-09: 126 and 127)
//! - `specs/00-stories/KNSH-097-parameter-variable-and-arithmetic-expansion.md`
//! - `specs/04-non-functional-requirements/compatibility.md` (NFR-COMPAT-05: the bash 3.2 and 5.2 differences)
//! - `specs/00-stories/KNSH-098-word-splitting-quote-removal-and-pathname-expansion.md`
//! - `specs/00-stories/KNSH-100-pipelines-subshells-and-job-control.md`, FR-SES-10 (pause of every job's group),
//!   `specs/09-reference/decisions.md` (decision 19: subshells are copies)
//! - `specs/00-stories/KNSH-101-core-builtins.md`, NFR-COMPAT-10 (OSC 7), `specs/09-reference/decisions.md`
//!   (decision 20: `exec` runs, then ends the shell)
//! - `specs/00-stories/KNSH-102-builtins-test-printf-read.md`, `specs/09-reference/decisions.md` (decision 21: system
//!   regular expressions)
//! - `specs/00-stories/KNSH-104-traps-signals-set-and-shopt-options.md`
//! - `specs/00-stories/KNSH-105-process-substitution-coproc-and-here-documents.md`, `specs/09-reference/decisions.md`
//!   (decision 6: `coproc` stays dynamic for the classifier)
//! - `specs/00-stories/KNSH-106-posix-mode.md`, `specs/09-reference/decisions.md` (decision 22: `echo` in POSIX mode
//!   as macOS's `/bin/sh`)
//! - `specs/09-reference/defaults-and-limits.md` (the evaluation, arithmetic and expansion depth limits, the brace
//!   and pathname expansion bounds, the `printf` and `read` bounds, and the command substitution output bound)

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod arith;
mod brace;
mod check;
mod cond;
mod error;
mod eval;
mod expand;
mod glob;
pub mod interactive;
mod jobs;
mod lookup;
mod observer;
mod options;
mod param;
mod pattern;
mod printf;
mod quote;
mod scan;
mod state;
mod status;
mod trap;
mod vars;
mod word;

pub use arith::{Failure as ArithmeticError, MAX_ARITH_DEPTH, evaluate_arithmetic};
pub use error::{InterpError, Unsupported};
pub use eval::interactive::{Completion, LineStatus, continues_line, is_incomplete};
pub use eval::{EVAL_STACK_SIZE, Interpreter, MAX_EVAL_DEPTH};
pub use jobs::{JobSignals, MAX_REMEMBERED_JOBS};
pub use observer::{DirectoryObserver, Osc7, osc7};
pub use options::posix_mode_requested;
pub use state::{ShellOptions, ShellState};
pub use status::Status;
pub use trap::ShellSignals;
