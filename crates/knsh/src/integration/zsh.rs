//! Hosting stock zsh: the startup wrapper and the launch plan (KNSH-019, FR-SES-20, FR-SES-22, NFR-COMPAT-01,
//! NFR-COMPAT-03, NFR-COMPAT-06).
//!
//! # Startup files
//!
//! `knsh` points `ZDOTDIR` at an engine-owned directory holding one file, [`ZSHENV`], and passes the user's own
//! `ZDOTDIR` (if any) in [`ORIGINAL_ZDOTDIR_VAR`]. zsh reads `/etc/zshenv`, then the wrapper instead of the user's
//! `.zshenv`. The wrapper's first act is to restore the user's `ZDOTDIR` exactly (set, set to empty, or unset);
//! then it sources the user's `.zshenv` from `${ZDOTDIR-$HOME}`, as zsh would (with `FUNCTION_ARGZERO` off meanwhile,
//! so that `$0` there is the shell's name, not the file's path).
//!
//! zsh looks `ZDOTDIR` up again for every later startup file, so from then on zsh itself reads `/etc/zprofile`,
//! `.zprofile`, `/etc/zshrc`, `.zshrc`, `/etc/zlogin`, `.zlogin` and, at exit, `.zlogout`, in its own order and from
//! wherever the user's files left `ZDOTDIR`. Nothing else is wrapped, so the order, the `ZDOTDIR` every file sees, and
//! the `ZDOTDIR` every child process inherits are those of plain zsh. This mechanism is an implementation choice,
//! recorded in `specs/08-integrations/terminals-and-shells.md`.
//!
//! # Hooks
//!
//! Only when recording is on (the telemetry descriptor number is passed in [`TELEMETRY_FD_VAR`]) the wrapper adds
//! `preexec` and `precmd` functions with `add-zsh-hook`, which appends to `preexec_functions` / `precmd_functions`
//! and never replaces a user's or framework's hooks. They are installed right after the user's `.zshenv`; a later
//! rc file that *assigns* those arrays without keeping their entries drops them, which only loses telemetry.
//!
//! The hooks must never print, fail, block or change the user's shell:
//!
//! - The inherited descriptor is reopened close-on-exec (`sysopen -o cloexec` from the stock `zsh/system` module) and
//!   the original closed, so no command the user runs inherits it. The variable is removed from the environment.
//! - Each hook runs under `emulate -L zsh` (the user's options, traps and patterns are restored on return) and
//!   ignores `SIGPIPE` for its own duration only: interactive zsh is killed by `SIGPIPE`, which a write to a pipe
//!   whose reader has gone would raise.
//! - The descriptor is non-blocking ([`TelemetryPipe`](knsh_platform::macos::TelemetryPipe)) and errors go to
//!   `/dev/null`, so a full, closed or vanished pipe drops the line without delay or output.
//! - `$?` is captured as the first statement of `precmd`; zsh restores it for the next hook function anyway.
//! - The hook functions are parsed before the user's `.zshenv` runs, so its aliases cannot change them.
//!
//! The line format is in [`telemetry`](super::telemetry).
//!
//! # Terminal marks
//!
//! When `knsh` asks for them ([`MARKS_VAR`], KNSH-022), whether or not recording is on, the
//! wrapper adds a second pair of hooks, `_knsh_mark_preexec` and `_knsh_mark_precmd`, that write OSC 7 and OSC 133
//! ([`marks`](super::marks)) to standard output while it is a terminal. `A` is written by `precmd`, `B` is appended to
//! `PS1` inside `%{ %}` (and taken off again by the next hook, unless something has set `PS1` since), `C` by
//! `preexec`, and `D;<status>` by the next `precmd`. The marks' `precmd` moves both hooks to the end of their arrays
//! whenever something was added after them, so `PS1` is final when it is marked.

use std::ffi::{OsStr, OsString};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use super::marks::MARKS_VAR;

/// The stock zsh that integration mode hosts (NFR-COMPAT-03: zsh is supported by running real zsh).
pub const SYSTEM_ZSH: &str = "/bin/zsh";

/// The variable zsh reads its startup files from.
pub const ZDOTDIR_VAR: &str = "ZDOTDIR";

/// Carries the user's own `ZDOTDIR` to the wrapper. Absent means `ZDOTDIR` was unset. The wrapper removes it.
pub const ORIGINAL_ZDOTDIR_VAR: &str = "KNSH_ZSH_ZDOTDIR";

/// Carries the telemetry descriptor number to the wrapper when recording is on. The wrapper removes it.
pub const TELEMETRY_FD_VAR: &str = "KNSH_TELEMETRY_FD";

/// The name of the wrapper file inside the startup directory.
pub const STARTUP_FILE: &str = ".zshenv";

/// The wrapper `.zshenv` that `knsh` installs in its zsh startup directory. Static: everything that varies per
/// session arrives in the environment, so one copy serves every session and `knsh` never needs to clean up after
/// a session, including one replaced by `exec`.
pub const ZSHENV: &str = r#"# Kinetic Shell integration mode for zsh (KNSH-019). Written by knsh, which overwrites any change.
#
# knsh pointed ZDOTDIR here, so zsh reads this file instead of the user's .zshenv. It restores the user's ZDOTDIR,
# then sources the user's .zshenv. zsh itself then reads every later startup file from the user's ZDOTDIR, in its
# normal order, exactly as plain zsh would.

# The user's ZDOTDIR, restored exactly: unset, empty or set (an empty ZDOTDIR is not the same as an unset one).
if (( ${+KNSH_ZSH_ZDOTDIR} )); then
  export ZDOTDIR="$KNSH_ZSH_ZDOTDIR"
  unset KNSH_ZSH_ZDOTDIR
else
  unset ZDOTDIR
fi

# Telemetry (recording on only). Taken over before any user file runs, so neither those files nor any command sees
# the variable or the inherited descriptor.
if (( ${+KNSH_TELEMETRY_FD} )); then
  () {
    emulate -L zsh
    local fd="$KNSH_TELEMETRY_FD"
    unset KNSH_TELEMETRY_FD
    [[ "$fd" == <3-> ]] || return 0
    # A close-on-exec copy that commands do not inherit; without zsh/system there is no telemetry.
    if [[ -o interactive ]] && zmodload zsh/system 2>/dev/null; then
      typeset -g _knsh_telemetry_fd
      sysopen -w -o cloexec -u _knsh_telemetry_fd "/dev/fd/$fd" 2>/dev/null || unset _knsh_telemetry_fd
    fi
    # Braces: a redirection on `exec` itself would apply to the whole shell from then on.
    { exec {fd}>&- } 2>/dev/null
    return 0
  }
fi

# Terminal marks (KNSH-022): OSC 7 and OSC 133, whether or not recording is on. knsh asks for them only when its
# standard output is a terminal, and the hooks write nothing while it is not one.
if (( ${+KNSH_TERMINAL_MARKS} )); then
  [[ "$KNSH_TERMINAL_MARKS" == 1 && -o interactive ]] && typeset -gi _knsh_marks=1
  unset KNSH_TERMINAL_MARKS
fi

# Escapes $1 for a telemetry field into the caller's $_knsh_out: \\ \n \t \r \0.
_knsh_escape() {
  _knsh_out=${1//\\/\\\\}
  _knsh_out=${_knsh_out//$'\n'/\\n}
  _knsh_out=${_knsh_out//$'\t'/\\t}
  _knsh_out=${_knsh_out//$'\r'/\\r}
  _knsh_out=${_knsh_out//$'\0'/\\0}
}

# preexec: a command line is about to run. $1 is the line as typed (empty when history is off; then $3).
_knsh_preexec() {
  emulate -L zsh
  trap '' PIPE
  (( ${+_knsh_telemetry_fd} )) || return 0
  # Still our pipe: after the user closes the descriptor, a file they open may reuse its number.
  [[ -p /dev/fd/$_knsh_telemetry_fd ]] || return 0
  local _knsh_out _knsh_cwd
  _knsh_escape "$PWD"
  _knsh_cwd=$_knsh_out
  _knsh_escape "${1:-$3}"
  print -rnu "$_knsh_telemetry_fd" -- "knsh1"$'\t'"preexec"$'\t'"$_knsh_cwd"$'\t'"$_knsh_out"$'\n' 2>/dev/null
  _knsh_pending=1
  return 0
}

# precmd: the prompt is back. Reports $? only after a preexec (not for an empty line or the first prompt).
_knsh_precmd() {
  local -i _knsh_status=$?
  emulate -L zsh
  trap '' PIPE
  (( ${+_knsh_telemetry_fd} && _knsh_pending )) || return 0
  _knsh_pending=0
  [[ -p /dev/fd/$_knsh_telemetry_fd ]] || return 0
  local _knsh_out
  _knsh_escape "$PWD"
  print -rnu "$_knsh_telemetry_fd" -- "knsh1"$'\t'"precmd"$'\t'"$_knsh_status"$'\t'"$_knsh_out"$'\n' 2>/dev/null
  return 0
}

# Percent-encodes $1 for a file:// URL into the caller's $_knsh_out: every byte but A-Z a-z 0-9 / . _ ~ - becomes
# %XX. Byte by byte (no_multibyte), so a non-ASCII name is encoded as its UTF-8 bytes.
_knsh_urlenc() {
  emulate -L zsh
  setopt no_multibyte
  _knsh_out=$1
  [[ $1 == *[^A-Za-z0-9/._~-]* ]] || return 0
  local _knsh_c _knsh_x
  local -i _knsh_i
  _knsh_out=
  for (( _knsh_i = 1; _knsh_i <= ${#1}; _knsh_i++ )); do
    _knsh_c=${1[_knsh_i]}
    if [[ $_knsh_c == [A-Za-z0-9/._~-] ]]; then
      _knsh_out+=$_knsh_c
    else
      printf -v _knsh_x '%%%02X' "'$_knsh_c"
      _knsh_out+=$_knsh_x
    fi
  done
  return 0
}

# Takes the command start mark off PS1 again, unless something has set PS1 since.
_knsh_unmark() {
  [[ -n $_knsh_ps1_marked && $PS1 == "$_knsh_ps1_marked" ]] && PS1=$_knsh_ps1
  _knsh_ps1_marked=
  return 0
}

# precmd for the marks: OSC 133 D with the status of the line that ran (only after its C), OSC 7, OSC 133 A, then
# OSC 133 B at the end of PS1. Moves the marks' hooks after any added since (later startup files add theirs after the
# wrapper's), so that PS1 is final when it is marked and C is the last thing before the line's output.
_knsh_mark_precmd() {
  local -i _knsh_status=$? _knsh_pct=0
  [[ -o prompt_percent ]] && _knsh_pct=1
  emulate -L zsh
  _knsh_unmark
  if [[ ${precmd_functions[-1]-} != _knsh_mark_precmd || ${preexec_functions[-1]-} != _knsh_mark_preexec ]]; then
    { add-zsh-hook -d precmd _knsh_mark_precmd && add-zsh-hook precmd _knsh_mark_precmd &&
      add-zsh-hook -d preexec _knsh_mark_preexec && add-zsh-hook preexec _knsh_mark_preexec } 2>/dev/null
  fi
  if [[ -t 1 ]]; then
    local _knsh_out _knsh_d= _knsh_h
    (( _knsh_mark_ran )) && _knsh_d=$'\e]133;D;'$_knsh_status$'\a'
    _knsh_urlenc "$HOST"
    _knsh_h=$_knsh_out
    _knsh_urlenc "$PWD"
    print -rn -- "$_knsh_d"$'\e]7;file://'"$_knsh_h$_knsh_out"$'\a\e]133;A\a' 2>/dev/null
    # %{ %} tells zsh the mark takes no room; without prompt_percent it would be printed as text.
    if (( _knsh_pct )); then
      _knsh_ps1=$PS1
      PS1+=$'%{\e]133;B\a%}'
      _knsh_ps1_marked=$PS1
    fi
  fi
  _knsh_mark_ran=0
  return 0
}

# preexec for the marks: PS1 as the user set it, then OSC 133 C.
_knsh_mark_preexec() {
  emulate -L zsh
  _knsh_unmark
  [[ -t 1 ]] || return 0
  print -rn -- $'\e]133;C\a' 2>/dev/null
  _knsh_mark_ran=1
  return 0
}

# Appends the preexec $1 and the precmd $2 after any hooks the user has, with add-zsh-hook; the arrays directly only
# if it is unavailable.
_knsh_add_hooks() {
  emulate -L zsh
  if ! { autoload -Uz add-zsh-hook && add-zsh-hook preexec $1 && add-zsh-hook precmd $2 } 2>/dev/null; then
    typeset -ga preexec_functions precmd_functions
    (( ${preexec_functions[(Ie)$1]} )) || preexec_functions+=($1)
    (( ${precmd_functions[(Ie)$2]} )) || precmd_functions+=($2)
  fi
}

# zsh reads its own startup files with $0 left as the shell's name, but `source` sets $0 to the file's path while
# FUNCTION_ARGZERO is on (the zsh default). The option is off while the user's file runs, and back on afterwards.
if [[ -r "${ZDOTDIR-$HOME}/.zshenv" ]]; then
  if [[ -o function_argzero ]]; then
    \builtin unsetopt function_argzero
    source "${ZDOTDIR-$HOME}/.zshenv"
    \builtin setopt function_argzero
  else
    source "${ZDOTDIR-$HOME}/.zshenv"
  fi
fi

if (( ${+_knsh_telemetry_fd} )); then
  typeset -gi _knsh_pending=0
  \_knsh_add_hooks _knsh_preexec _knsh_precmd
else
  \builtin unfunction _knsh_escape _knsh_preexec _knsh_precmd
fi
if (( ${_knsh_marks-0} )); then
  typeset -gi _knsh_mark_ran=0
  typeset -g _knsh_ps1= _knsh_ps1_marked=
  \_knsh_add_hooks _knsh_mark_preexec _knsh_mark_precmd
else
  \builtin unfunction _knsh_urlenc _knsh_unmark _knsh_mark_precmd _knsh_mark_preexec
fi
\builtin unset _knsh_marks
\builtin unfunction _knsh_add_hooks
"#;

/// Whether a shell-mode invocation is a human interactive shell that integration mode hosts.
///
/// `knsh` with no command line and no script operand, interactive because `-i` was given or because standard
/// input and standard error are terminals (the rule zsh and bash apply). Everything else (`knsh -c`, scripts, piped
/// input) belongs to the agent and unattended paths of later stories (`specs/06-api/cli.md` "Shell invocation").
#[must_use]
pub fn is_human_interactive(
    command: Option<&OsStr>,
    operands: &[OsString],
    force_interactive: bool,
    on_terminal: bool,
) -> bool {
    command.is_none() && operands.is_empty() && (force_interactive || on_terminal)
}

/// Everything that varies when starting zsh.
#[derive(Debug, Clone, Copy)]
pub struct ZshLaunch<'a> {
    /// The zsh binary.
    pub zsh: &'a Path,
    /// The installed startup directory, or `None` to start plain zsh with no wrapper (and so no hooks) when it
    /// could not be installed: a human shell is never refused (FR-SES-22).
    pub startup_dir: Option<&'a Path>,
    /// The user's `ZDOTDIR` as `knsh` received it; `None` when unset.
    pub user_zdotdir: Option<&'a OsStr>,
    /// A login shell (`-l`, `--login`, or `argv[0]` starting with `-`).
    pub login: bool,
    /// `-i` was given.
    pub force_interactive: bool,
    /// The inherited telemetry descriptor when recording is on; `None` when off.
    pub telemetry_fd: Option<RawFd>,
    /// Whether the wrapper adds the terminal marks hooks (KNSH-022): `knsh`'s standard output is a terminal.
    pub marks: bool,
}

/// How to start zsh: a pure function of [`ZshLaunch`], applied to a process by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    /// The executable.
    pub program: PathBuf,
    /// `argv[0]`: `-zsh` for a login shell, which is how `login(1)` starts one, so `$0` matches plain zsh.
    pub arg0: OsString,
    /// Arguments after `argv[0]`.
    pub args: Vec<OsString>,
    /// Variables removed from the inherited environment, before [`LaunchPlan::set_env`] is applied.
    pub remove_env: Vec<OsString>,
    /// Variables set in the inherited environment.
    pub set_env: Vec<(OsString, OsString)>,
}

impl ZshLaunch<'_> {
    /// The plan for this launch. The rest of the environment is inherited unchanged.
    #[must_use]
    pub fn plan(&self) -> LaunchPlan {
        let argv0 = if self.login { "-zsh" } else { "zsh" };
        let args = if self.force_interactive {
            vec![OsString::from("-i")]
        } else {
            Vec::new()
        };
        // Our own variables never pass through from knsh's environment: a stale value would mislead the wrapper.
        // `KNSH_RECORDING` too: only a shell that is recorded right now may claim it (FR-SES-25).
        let mut remove_env = vec![
            OsString::from(ORIGINAL_ZDOTDIR_VAR),
            OsString::from(TELEMETRY_FD_VAR),
            OsString::from(super::RECORDING_VAR),
            OsString::from(MARKS_VAR),
        ];
        let mut set_env = Vec::new();
        if let Some(startup_dir) = self.startup_dir {
            if self.marks {
                set_env.push((OsString::from(MARKS_VAR), OsString::from("1")));
            }
            remove_env.push(OsString::from(ZDOTDIR_VAR));
            set_env.push((OsString::from(ZDOTDIR_VAR), startup_dir.as_os_str().to_owned()));
            if let Some(user_zdotdir) = self.user_zdotdir {
                set_env.push((OsString::from(ORIGINAL_ZDOTDIR_VAR), user_zdotdir.to_owned()));
            }
            if let Some(fd) = self.telemetry_fd {
                set_env.push((OsString::from(TELEMETRY_FD_VAR), OsString::from(fd.to_string())));
                // Hooks installed and telemetry flowing: the shell is recorded (KNSH-021).
                set_env.push((OsString::from(super::RECORDING_VAR), OsString::from("1")));
            }
        }
        LaunchPlan {
            program: self.zsh.to_path_buf(),
            arg0: OsString::from(argv0),
            args,
            remove_env,
            set_env,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch() -> ZshLaunch<'static> {
        ZshLaunch {
            zsh: Path::new(SYSTEM_ZSH),
            startup_dir: Some(Path::new("/h/engine/shell/zsh")),
            user_zdotdir: None,
            login: false,
            force_interactive: false,
            telemetry_fd: None,
            marks: false,
        }
    }

    fn position(needle: &str) -> usize {
        ZSHENV
            .find(needle)
            .unwrap_or_else(|| panic!("wrapper lacks {needle:?}"))
    }

    fn env_value<'a>(plan: &'a LaunchPlan, key: &str) -> Option<&'a OsStr> {
        plan.set_env
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_os_str())
    }

    // KNSH-019 unit test (NFR-COMPAT-01): the wrapper restores the user's ZDOTDIR before anything else and then
    // sources only the user's .zshenv, from `${ZDOTDIR-$HOME}` as zsh does. It never sources .zprofile, .zshrc or
    // .zlogin itself: zsh reads those in its own order, from the restored ZDOTDIR.
    #[test]
    fn startup_wrapper_sources_user_files_in_zsh_order() {
        let restore = position("export ZDOTDIR=\"$KNSH_ZSH_ZDOTDIR\"");
        let unset = position("unset ZDOTDIR");
        let takeover = position("unset KNSH_TELEMETRY_FD");
        let source = position("source \"${ZDOTDIR-$HOME}/.zshenv\"");
        let install = position("\\_knsh_add_hooks _knsh_preexec _knsh_precmd\n");
        assert!(
            restore < source && unset < source,
            "ZDOTDIR is restored before the user's .zshenv runs"
        );
        assert!(
            takeover < source,
            "the descriptor is taken over before any user file runs"
        );
        assert!(source < install, "hooks are added after the user's .zshenv");
        for later in [".zprofile", ".zshrc", ".zlogin", ".zlogout"] {
            assert!(!ZSHENV.contains(later), "{later} is left to zsh");
        }
        // One `source` per FUNCTION_ARGZERO branch, both of the user's .zshenv.
        assert_eq!(ZSHENV.matches("source ").count(), 2);
        assert_eq!(ZSHENV.matches("source \"${ZDOTDIR-$HOME}/.zshenv\"").count(), 2);
        // `$0` in the user's .zshenv is the shell's name, as in plain zsh, not the file's path.
        assert!(position("unsetopt function_argzero") < source);
        // `${ZDOTDIR-$HOME}`, not `${ZDOTDIR:-$HOME}`: zsh uses an empty ZDOTDIR as is.
        assert!(!ZSHENV.contains("${ZDOTDIR:-"));
    }

    // KNSH-019 unit test: hooks are appended with add-zsh-hook and the hook arrays are never assigned outright.
    #[test]
    fn hooks_are_added_not_replaced() {
        assert!(ZSHENV.contains("add-zsh-hook preexec $1 && add-zsh-hook precmd $2"));
        assert!(ZSHENV.contains("\\_knsh_add_hooks _knsh_preexec _knsh_precmd\n"));
        assert!(ZSHENV.contains("\\_knsh_add_hooks _knsh_mark_preexec _knsh_mark_precmd\n"));
        assert!(ZSHENV.contains("autoload -Uz add-zsh-hook"));
        for clobber in [
            "preexec_functions=(",
            "precmd_functions=(",
            "\npreexec()",
            "\nprecmd()",
            "functions=()",
        ] {
            assert!(!ZSHENV.contains(clobber), "wrapper must not contain {clobber:?}");
        }
        // The fallback appends after the existing entries and skips an entry already present.
        assert!(ZSHENV.contains("(( ${preexec_functions[(Ie)$1]} )) || preexec_functions+=($1)"));
        assert!(ZSHENV.contains("(( ${precmd_functions[(Ie)$2]} )) || precmd_functions+=($2)"));
        // The marks' hooks move themselves to the end with add-zsh-hook too: removed, then appended again.
        assert!(ZSHENV.contains("add-zsh-hook -d precmd _knsh_mark_precmd && add-zsh-hook precmd _knsh_mark_precmd"));
    }

    // FR-SES-22: every hook is isolated from the user's options and traps, ignores SIGPIPE locally and silences
    // its writes.
    #[test]
    fn hooks_never_print_or_die() {
        for hook in ["_knsh_preexec() {", "_knsh_precmd() {"] {
            let body = &ZSHENV[position(hook)..];
            let body = &body[..body.find("\n}\n").expect("function end")];
            assert!(body.contains("emulate -L zsh"), "{hook}");
            assert!(body.contains("trap '' PIPE"), "{hook}");
            assert!(body.contains("2>/dev/null"), "{hook}");
            assert!(body.contains("return 0"), "{hook}");
            assert!(
                body.contains("[[ -p /dev/fd/$_knsh_telemetry_fd ]] || return 0"),
                "{hook}"
            );
        }
        assert!(ZSHENV.contains("sysopen -w -o cloexec"));
        assert!(position("local -i _knsh_status=$?") < position("_knsh_precmd() {") + 40);
    }

    // AC "With recording off, no telemetry is produced": without a descriptor, the plan passes none and the
    // wrapper removes the hook functions instead of installing them.
    #[test]
    fn recording_off_passes_no_telemetry_descriptor() {
        let plan = launch().plan();
        assert_eq!(env_value(&plan, TELEMETRY_FD_VAR), None);
        assert!(plan.remove_env.iter().any(|name| name == TELEMETRY_FD_VAR));
        assert!(position("\\builtin unfunction _knsh_escape _knsh_preexec _knsh_precmd") > position("source "));
    }

    #[test]
    fn plan_points_zdotdir_at_the_wrapper_and_carries_the_users_value() {
        let plan = ZshLaunch {
            user_zdotdir: Some(OsStr::new("/h/.config/zsh")),
            telemetry_fd: Some(5),
            ..launch()
        }
        .plan();
        assert_eq!(plan.program, Path::new(SYSTEM_ZSH));
        assert_eq!(plan.arg0, "zsh");
        assert_eq!(plan.args.len(), 0);
        assert_eq!(env_value(&plan, ZDOTDIR_VAR), Some(OsStr::new("/h/engine/shell/zsh")));
        assert_eq!(
            env_value(&plan, ORIGINAL_ZDOTDIR_VAR),
            Some(OsStr::new("/h/.config/zsh"))
        );
        assert_eq!(env_value(&plan, TELEMETRY_FD_VAR), Some(OsStr::new("5")));

        // Unset stays distinguishable from empty.
        let unset = launch().plan();
        assert_eq!(env_value(&unset, ORIGINAL_ZDOTDIR_VAR), None);
        let empty = ZshLaunch {
            user_zdotdir: Some(OsStr::new("")),
            ..launch()
        }
        .plan();
        assert_eq!(env_value(&empty, ORIGINAL_ZDOTDIR_VAR), Some(OsStr::new("")));
    }

    #[test]
    fn plan_without_a_startup_dir_is_plain_zsh() {
        let plan = ZshLaunch {
            startup_dir: None,
            user_zdotdir: Some(OsStr::new("/h/z")),
            telemetry_fd: Some(5),
            ..launch()
        }
        .plan();
        assert_eq!(plan.set_env.len(), 0);
        // The user's ZDOTDIR is inherited untouched; only stale knsh variables are dropped.
        assert!(!plan.remove_env.iter().any(|name| name == ZDOTDIR_VAR));
    }

    #[test]
    fn login_and_interactive_flags_follow_plain_zsh() {
        let plan = ZshLaunch {
            login: true,
            force_interactive: true,
            ..launch()
        }
        .plan();
        assert_eq!(plan.arg0, "-zsh");
        assert_eq!(plan.args, [OsString::from("-i")]);
    }

    // KNSH-022 (NFR-COMPAT-10): the marks are asked for in the environment, whatever the recording state, only with
    // the wrapper (which takes the variable out again before any user file runs); a stale value is never inherited.
    #[test]
    fn marks_are_passed_to_the_wrapper_only_when_wanted() {
        let marks = |launch: ZshLaunch<'_>| env_value(&launch.plan(), MARKS_VAR).map(OsStr::to_owned);
        assert_eq!(
            marks(ZshLaunch {
                marks: true,
                ..launch()
            }),
            Some(OsString::from("1"))
        );
        let recorded = ZshLaunch {
            marks: true,
            telemetry_fd: Some(5),
            ..launch()
        };
        assert_eq!(marks(recorded), Some(OsString::from("1")));
        assert_eq!(marks(launch()), None);
        let plain = ZshLaunch {
            marks: true,
            startup_dir: None,
            ..launch()
        };
        assert_eq!(marks(plain), None);
        assert!(launch().plan().remove_env.iter().any(|name| name == MARKS_VAR));
        assert!(position("unset KNSH_TERMINAL_MARKS") < position("source \"${ZDOTDIR-$HOME}/.zshenv\""));
    }

    // KNSH-022: every write of a mark is guarded by a terminal on standard output at that moment, and the hooks are
    // removed when the marks are not wanted.
    #[test]
    fn mark_hooks_write_only_to_a_terminal() {
        for hook in ["_knsh_mark_precmd() {", "_knsh_mark_preexec() {"] {
            let body = &ZSHENV[position(hook)..];
            let body = &body[..body.find("\n}\n").expect("function end")];
            assert!(body.contains("emulate -L zsh"), "{hook}");
            let guard = body.find("[[ -t 1 ]]").expect("terminal check");
            let write = body.find("print -rn").expect("write");
            assert!(guard < write, "{hook}");
            assert!(body.contains("2>/dev/null"), "{hook}");
        }
        // $? is read before anything else can change it.
        assert!(position("local -i _knsh_status=$? _knsh_pct=0") < position("_knsh_mark_precmd() {") + 40);
        assert!(ZSHENV.contains("\\builtin unfunction _knsh_urlenc _knsh_unmark _knsh_mark_precmd _knsh_mark_preexec"));
        // B goes inside %{ %}, and only with prompt_percent (otherwise it would print as text).
        assert!(ZSHENV.contains("PS1+=$'%{\\e]133;B\\a%}'"));
        assert!(position("[[ -o prompt_percent ]]") < position("emulate -L zsh\n  _knsh_unmark"));
    }

    #[test]
    fn only_bare_interactive_invocations_are_hosted() {
        let none: &[OsString] = &[];
        assert!(is_human_interactive(None, none, false, true));
        assert!(is_human_interactive(None, none, true, false));
        assert!(!is_human_interactive(None, none, false, false));
        assert!(!is_human_interactive(Some(OsStr::new("ls")), none, true, true));
        assert!(!is_human_interactive(None, &[OsString::from("script.sh")], true, true));
    }
}
