# Compatibility

Humans keep their own zsh or bash; agent lines run in stock bash under the supervisor. A feature that breaks bash compatibility is not shipped as a default.

## Modes

| | Human sessions | Agent lines (phase 2) | Native mode (phase 4) |
| --- | --- | --- | --- |
| Interpreter | Stock zsh or bash, hosted by `knsh` (integration mode) | The stock interpreter the caller asked for (`sh`, `bash` or `zsh`), one per line, spawned by the supervisor | `knsh`'s own interpreter |
| What is observed | Each command line, through `preexec` and `precmd`, as telemetry | The whole line, parsed before it runs | Every simple command, including inside scripts and functions |
| Decisions and sandbox | None | Per line, enforced by the sandbox | Per simple command |
| Script compatibility | Exactly the host shell's | Exactly the interpreter used | Target: bash 5.2, including bash's POSIX mode when started as `sh` or with `--posix`; at least 99% of a corpus of agent-generated commands behaving as in bash |

## Requirements

| ID | Requirement |
| --- | --- |
| NFR-COMPAT-01 | Existing bash and zsh scripts, rc files and agent-generated commands must run unchanged. |
| NFR-COMPAT-02 | **Bash compatibility is the target.** The native interpreter must aim to run bash scripts and interactive bash usage unchanged. POSIX behaviour comes through bash's own POSIX mode, not as a separate dialect, and bash extensions (arrays, `[[ ]]`, process substitution, `shopt` options) are in scope. |
| NFR-COMPAT-03 | **zsh is supported by running real zsh**, in integration mode for humans and for agent lines that ask for it. The native interpreter does not emulate zsh. |
| NFR-COMPAT-04 | Agent lines must use `/bin/bash` (bash 3.2 on macOS) unless the profile names another (for example Homebrew bash 5), so agents see the same bash a plain `bash -c` would give them. |
| NFR-COMPAT-05 | Differences between bash 3.2 and 5.2 that agents rely on must be covered by the corpus tests. |
| NFR-COMPAT-06 | Interactive zsh users must be able to stay in integration mode permanently. |
| NFR-COMPAT-07 | Conformance must be measured in CI on every release ([conformance](../07-testing/conformance.md)). |
| NFR-COMPAT-08 | `knsh` must be addable to `/etc/shells`, with the user's permission, so it works as a login shell with `chsh`. Login and startup-file behaviour follow the hosted shell. |
| NFR-COMPAT-09 | Exit status must follow bash: 127 for command not found, 128 plus the signal number for signals. A policy denial uses 126, with the reason always printed on stderr and kept in the record ([exit codes](../09-reference/exit-codes.md)). |
| NFR-COMPAT-10 | In every mode the engine must emit OSC 7 (working directory) and OSC 133 (prompt, command, output and exit code). |
| NFR-COMPAT-11 | Native mode must reach at least 99% of the agent-command corpus behaving as in bash 5.2. |

## Bash 3.2 and 5.2: expansion differences

The native interpreter follows bash 5.2. Where `/bin/bash` (3.2) used by agent lines (NFR-COMPAT-04) behaves
differently for parameter and arithmetic expansion, the difference is listed here and covered by the KNSH-097 unit
tests (`crates/knsh-interp/src/expand/tests.rs`, `src/arith/tests.rs`); forms both agree on are checked against
`/bin/bash` itself (`crates/knsh-interp/tests/bash_differential.rs`) (NFR-COMPAT-05).

| Form | Bash 3.2 | Bash 5.2 (native) |
| --- | --- | --- |
| `${x^}`, `${x^^}`, `${x,}`, `${x,,}`, `${x~}`, `${x~~}` | Bad substitution | Case modification |
| `${x@Q}`, `@E`, `@A`, `@a`, `@U`, `@u`, `@L`, `@K`, `@k` | Bad substitution | Transformations (`@P` refused until KNSH-107) |
| `${x:1:-1}` (negative length) | Error: `substring expression < 0` | Counts from the end |
| `${x/p/&}` | `&` is literal | `patsub_replacement` on by default: an unquoted `&` is the match |
| `set -u` with an unset parameter, `${x?}` | Shell exits with status 127 | Shell exits with status 1 |
| `${x?}` with `x` unset | `x: parameter null or not set` | `x: parameter not set` (`${x:?}` keeps the longer message) |
| `cmd <<<$x` (unquoted expansion in a here-string, KNSH-099) | Split on `IFS` and joined with spaces | Not split |
| `{name}>file` (KNSH-099) | `{name}` is an ordinary word | Opens a descriptor from 10 up and stores its number in `name` |
| `&>>file` (KNSH-099) | Syntax error | Appends standard output and error |
| `a \|& b` (KNSH-100) | Syntax error | Standard error joins the pipe, after `a`'s own redirections |
| `wait -n`, `shopt -s lastpipe` (KNSH-100) | No such option | First job to end; the last command of a pipeline runs in the shell without job control |
| `${!x}` with `x` unset or empty | Expands to nothing | Error `x: invalid indirect expansion` or `: invalid variable name`, line abandoned |
| `{01..03}`, `{1..9..2}`, `{a..e..2}` (KNSH-098) | No padding (`1 2 3`); a step leaves the word as written | Zero padding to the widest end; steps |
| `**` with `globstar` (KNSH-098) | No such option: `**` is `*` | Any depth of directories |
| `.*` (KNSH-098) | Also matches `.` and `..` | Never matches `.` and `..` (`globskipdots`, on by default) |

Known differences of the native interpreter from bash 5.2 (KNSH-098): in the C locale bash matches `?` and bracket
expressions against bytes and the interpreter against characters, so they differ for non-ASCII text only (`?`
matches `é` here, `??` does in bash); the `failglob` error names the word after quote removal; a pattern starting
with an `extglob` group matches a hidden name when one of the group's alternatives starts with `.` (bash 5.2 looks
deeper); `GLOBIGNORE` implies `dotglob` only while it is set and not empty. Glob results are sorted with the system's
`strcoll` (macOS); glibc's collation is checked with the Linux port (KNSH-110).

Known differences of the native interpreter from bash 5.2 in redirections (KNSH-099): descriptor numbers above 255
are `Bad file descriptor` (bash allows up to its open-file limit); `/dev/stdin`, `/dev/stdout`, `/dev/stderr` and
`/dev/fd/N` are the shell's own descriptors, duplicated without truncation, as opening `/dev/fd` does on macOS, while
any other path that leads into `/dev/fd` (a symlink to it) is refused with `Operation not permitted`, because in the
interpreter's process it would reach the engine's own descriptors; `/dev/tcp` and `/dev/udp` are refused
([decision 18](../09-reference/decisions.md)); here-documents are refused until KNSH-105, and a redirection after
`(( … ))` or `for (( … ))` is refused; what the shell would write to its standard input (its messages after `2>&0`)
is dropped; a program that vanishes between lookup and `exec` while descriptors above 2 are redirected ends with
127 (126 if it cannot be executed) without bash's message. `{name}>file` is read only when the line is parsed with
`knsh_bash::ParseOptions::redirection_variables`, which the native interpreter's caller sets (bash 3.2 reads
`{name}` as a word, so without the option the line is refused).

Known differences of the native interpreter from bash 5.2 in pipelines, subshells and job control (KNSH-100): a
subshell is a copy of the interpreter, not a forked process ([decision 19](../09-reference/decisions.md)), so a
background job whose last command the shell runs itself (`{ …; } &`, `a && b &`, `x=1 &`) has no process id and
reading `$!` after it is refused rather than given a number that may belong to another process; under job control
such a command (a compound pipeline stage, a subshell) cannot be stopped as a whole: its programs stop, and Ctrl-Z
reports the job stopped once none of its programs runs; `jobs` and `fg` show the command's source text with blanks
collapsed, where bash reprints it from its own parse; `jobs` in a pipeline stage lists the subshell's jobs (none), not
the shell's; the state of a job a signal ended is macOS's `strsignal` text (`Terminated: 15`); `disown` forgets a
job, so a later `wait` for its process id is `not a child of this shell` (127); `$-` has no `H` (history arrives
with KNSH-107); `time` adds the shell's own CPU time and that of every child its process reaped meanwhile, which in
a process running several shells includes the others'. The terminal modes a stopped job had are not saved for its
`fg` (the shell restores its own).
| Messages under `bash -c` | `bash: message` (no line number on one-line scripts) | `bash: line n: message` |
| Arithmetic error token after trailing blanks (`$(( 1 + ))`) | `error token is " "` | The last token read: `error token is "+ "` |
| `base#` with no digits (`$((2#))`) | 0 | Error `invalid integer constant` |
| Division by zero inside a longer expression (`$((4/0+1))`) | `error token is "+1"` (the token after the divisor) | `error token is "0+1"` (from the divisor on) |
