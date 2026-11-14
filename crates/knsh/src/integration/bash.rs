//! Hosting stock bash: the startup wrapper, the hooks and the launch plan (KNSH-020, FR-SES-20, FR-SES-22,
//! NFR-COMPAT-01, NFR-COMPAT-04).
//!
//! # Which bash
//!
//! `knsh` hosts bash when the user's login shell (`$SHELL`) is a bash, and runs exactly that binary: `/bin/bash`
//! (3.2 on macOS) or, for example, Homebrew's bash 5 ([`user_bash`]). Otherwise it hosts zsh ([`super::zsh`]).
//!
//! # Startup files
//!
//! - **Recording off:** `knsh` runs plain bash, with no file of its own and no variable of its own, so bash reads
//!   `/etc/profile`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.bashrc` and `~/.bash_logout` exactly as
//!   it always does.
//! - **Recording on, non-login shell:** `bash --rcfile <wrapper>`. bash reads the wrapper ([`BASHRC`]) instead of
//!   `~/.bashrc`; the wrapper sources `~/.bashrc` itself, as bash would have, then adds the hooks.
//! - **Recording on, login shell:** a login bash reads `/etc/profile` and the first of `~/.bash_profile`,
//!   `~/.bash_login` and `~/.profile` itself, and no option can replace them. Stock bash 3.2 reads no other file
//!   (`ENV` only in POSIX mode, which bash 3.2 does not honour for a login shell). So bash starts exactly as a plain
//!   login shell, with [`PROMPT_COMMAND_VAR`] set to a bootstrap ([`BOOTSTRAP`]) that sources the wrapper at the
//!   first prompt, once every startup file has run. The wrapper removes the bootstrap again and adds the hooks.
//!   The startup files see that `PROMPT_COMMAND` and the `KNSH_*` variables; this is recorded as a limit in
//!   `specs/08-integrations/terminals-and-shells.md`.
//!
//! # Hooks
//!
//! bash has no `preexec`. The wrapper uses a `DEBUG` trap for the start of a line and `PROMPT_COMMAND` for its end,
//! both chained with whatever the user has:
//!
//! - `PROMPT_COMMAND` (a string, or an array in bash 5.1+) becomes `_knsh_precmd`, then the user's own entries,
//!   then `_knsh_arm`. `_knsh_precmd` reports the status of the line that just ended; `_knsh_arm` marks that the
//!   next command run is the first of a line typed at the prompt.
//! - The `DEBUG` trap runs before every simple command. It reports a line only for the first command after
//!   `_knsh_arm` that is not one of the hooks' own, so a line gives one report however many commands it runs, and
//!   neither the user's `PROMPT_COMMAND` nor programmable completion gives any. The user's own trap runs after ours.
//!   The command text is the newest history entry (the line as typed); when the line did not reach history, the
//!   command bash is about to run.
//! - `$?` and `PIPESTATUS` are captured before the hooks' first command and given back after each of their
//!   `PROMPT_COMMAND` entries, by a pipeline of `(exit n)` subshells when the line ended in a pipeline, so the
//!   user's `PROMPT_COMMAND` and the prompt see the same values as in plain bash. The restore is written as
//!   `… && :` when the status is not 0 (`! …` when the line was inverted), so it never triggers `set -e` or an `ERR`
//!   trap. bash 3.2 does not keep `PIPESTATUS` across a trap, so the trap gives it back itself where no pipeline is
//!   being built: before the first command of a line and of the user's `PROMPT_COMMAND`.
//! - bash 3.2 hides the `DEBUG` trap inside a function and inside a file read with `.`, and puts back on return the
//!   trap it had on entry. So the user's trap is read at the top level (after `~/.bashrc`, or by [`BOOTSTRAP`]), and
//!   ours is set at the top level of the wrapper; when bash undoes it (login shell, user trap), the first
//!   `PROMPT_COMMAND` entry sets it at the next prompt.
//!
//! The hooks must never print, fail, block or change the user's shell:
//!
//! - Stock bash cannot make a descriptor close-on-exec, so the inherited write end stays open in bash and in the
//!   commands it runs. It is passed at [`LOWEST_KEPT_FD`] or above, because an interactive login bash 3.2 closes
//!   the descriptors 3 to 19 it inherits. It is non-blocking, and bash also holds a read end it never reads
//!   ([`TelemetryPipe::inheritable_reader`](knsh_platform::macos::TelemetryPipe::inheritable_reader)): a write
//!   then never blocks and never raises `SIGPIPE` (which kills interactive bash), it only fails once the pipe is full.
//! - Every write first checks that the descriptor is still a pipe and sends its errors to `/dev/null`.
//! - The wrapper is parsed with aliases off, every builtin is called as `builtin`, every variable is read with a
//!   default (`set -u`), and a failing test is always part of an `&&`/`||` list (`set -e`).
//! - The hooks run no external command; the only subshells are `$(history 1)` once per line and per prompt, and
//!   the status restore after a pipeline.
//!
//! The line format is in [`telemetry`](super::telemetry).

use std::ffi::{OsStr, OsString};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use super::zsh::{LaunchPlan, TELEMETRY_FD_VAR};

/// The bash agents' lines use and that macOS ships (bash 3.2, NFR-COMPAT-04).
pub const SYSTEM_BASH: &str = "/bin/bash";

/// The variable that names the user's login shell.
pub const SHELL_VAR: &str = "SHELL";

/// The variable bash runs before each prompt.
pub const PROMPT_COMMAND_VAR: &str = "PROMPT_COMMAND";

/// Carries `knsh`'s process ID to the wrapper while recording, so that only the shell `knsh` started installs
/// hooks: a bash started by a startup file inherits the bootstrap but has another parent. The wrapper removes it.
pub const PARENT_PID_VAR: &str = "KNSH_TELEMETRY_PPID";

/// Carries the wrapper's path to the bootstrap of a recorded login shell. The wrapper removes it.
pub const BOOT_PATH_VAR: &str = "KNSH_BASH_BOOT";

/// The name of the wrapper file inside the startup directory.
pub const STARTUP_FILE: &str = "bashrc";

/// The lowest inherited descriptor an interactive login bash keeps: bash 3.2 closes 3 to 19 before it reads any
/// startup file, so the telemetry descriptors are passed at 20 or above.
pub const LOWEST_KEPT_FD: RawFd = 20;

/// The `PROMPT_COMMAND` a recorded login shell starts with (followed by a line feed and the user's own
/// `PROMPT_COMMAND`, if one was inherited). Fixed text, so the wrapper can find and remove it wherever the startup
/// files moved it; it must stay identical to `_knsh_b=` in [`BASHRC`]. It passes the user's DEBUG trap along, read
/// here because bash 3.2 hides the DEBUG trap from a file read with `.`.
pub const BOOTSTRAP: &str = r#". "${KNSH_BASH_BOOT:-/dev/null}" knsh-boot "$(builtin trap -p DEBUG)""#;

/// The bash wrapper that `knsh` installs in its bash startup directory. Static: everything that varies per session
/// arrives in the environment, so one copy serves every session.
pub const BASHRC: &str = r#"# Kinetic Shell integration mode for bash (KNSH-020). Written by knsh, which overwrites any change.
#
# Read only while a human session is recorded (with recording off knsh runs plain bash), in one of two ways:
# - non-login shell: `bash --rcfile <this file>`. It sources ~/.bashrc, as bash would have, then adds the hooks.
# - login shell: bash reads its profile files itself; at the first prompt PROMPT_COMMAND runs
#   `. <this file> knsh-boot`, which removes that bootstrap and adds the hooks.

# Parsed with aliases off, so no alias of the user's can change the functions below.
# $? as the user's next command would see it without this file; given back at the end.
_knsh_status=$?
\builtin shopt -q expand_aliases && _knsh_aliases=1 || _knsh_aliases=0
\builtin shopt -u expand_aliases

# Taken over and removed from the environment before any user file runs (non-login) or at once (login).
_knsh_fd=${KNSH_TELEMETRY_FD-}
_knsh_parent=${KNSH_TELEMETRY_PPID-}
\builtin unset KNSH_TELEMETRY_FD KNSH_TELEMETRY_PPID KNSH_BASH_BOOT
_knsh_bs='\'

# Gives back the status $1. Called with the $_ to give back as the last argument.
_knsh_give() { return "$1"; }

# Gives back $?, PIPESTATUS and $_ after our PROMPT_COMMAND entries, as `_knsh_restore_from` set them. Built here
# once: `case` on the key, where a pipeline of N commands (2 to 8) is rebuilt from `(exit n)` subshells, which are
# never traced by the DEBUG trap:
#   Nz  its status is 0;
#   Nn  it is not, so `&& :` follows: a failure in an && list never triggers `set -e` or an ERR trap;
#   Nx  $? is the inverse of the last status (`! cmd`), so `!` precedes it (exempt from both too);
#   1x  the same for one command; 0 gives nothing back (extdebug); anything else gives back $? alone.
_knsh_restore='case ${_knsh_rk-} in 0) : "${_knsh_rl-}";; 1x) ! _knsh_give "${_knsh_rps[0]}" "${_knsh_rl-}";;'
_knsh_i=2
while (( _knsh_i <= 8 )); do
  _knsh_j=0 _knsh_k=
  while (( _knsh_j < _knsh_i )); do
    _knsh_k="$_knsh_k${_knsh_k:+|}(exit \"\${_knsh_rps[$_knsh_j]}\")"
    _knsh_j=$((_knsh_j + 1))
  done
  _knsh_restore="$_knsh_restore ${_knsh_i}z) $_knsh_k;; ${_knsh_i}n) $_knsh_k && :;; ${_knsh_i}x) ! $_knsh_k;;"
  _knsh_i=$((_knsh_i + 1))
done
_knsh_restore="$_knsh_restore"' *) _knsh_give "${_knsh_rs-0}" "${_knsh_rl-}" && : "${_knsh_rl-}";; esac'
\builtin unset _knsh_i _knsh_j _knsh_k
# The same code for the DEBUG trap, on its own variables (_knsh_d*), set by `_knsh_debug`.
_knsh_trap_restore=${_knsh_restore//_knsh_r/_knsh_d}

# What the restore code after our PROMPT_COMMAND entries gives back: $? = $1, PIPESTATUS = $2 (space separated),
# $_ = $3.
_knsh_restore_from() {
  _knsh_rs=$1 _knsh_rl=$3
  local IFS=' '
  _knsh_rps=($2)
  _knsh_key "$1" "${#_knsh_rps[@]}" "${_knsh_rps[${#_knsh_rps[@]}-1]-0}"
  _knsh_rk=$_knsh_out
}

# $_knsh_out: the restore key for status $1, a PIPESTATUS of $2 elements whose last is $3 (see _knsh_restore).
# With pipefail, $? may differ from the last status without a `!`; the rebuilt pipeline then gives the same $?.
_knsh_key() {
  if (( $1 != $3 )) && [[ :${SHELLOPTS-}: != *:pipefail:* ]] && (( $2 >= 1 && $2 <= 8 )); then
    _knsh_out=$2x
  elif (( $2 < 2 || $2 > 8 )); then
    _knsh_out=1
  elif (( $1 == 0 )); then
    _knsh_out=$2z
  else
    _knsh_out=$2n
  fi
}

# Escapes $1 for a telemetry field into $_knsh_out: \\ \n \t \r (a bash string holds no NUL).
_knsh_esc() {
  _knsh_out=${1//"$_knsh_bs"/"$_knsh_bs$_knsh_bs"}
  _knsh_out=${_knsh_out//$'\n'/"${_knsh_bs}n"}
  _knsh_out=${_knsh_out//$'\t'/"${_knsh_bs}t"}
  _knsh_out=${_knsh_out//$'\r'/"${_knsh_bs}r"}
}

# Writes one telemetry line: kind $1, fields $2 and $3. Only while the descriptor is still our pipe: after the user
# closes it, a file they open may reuse its number. A full pipe fails the write at once and the line is lost.
_knsh_emit() {
  [[ -p /dev/fd/$_knsh_fd ]] || return 0
  local _knsh_a
  _knsh_esc "$2"
  _knsh_a=$_knsh_out
  _knsh_esc "$3"
  builtin printf 'knsh1\t%s\t%s\t%s\n' "$1" "$_knsh_a" "$_knsh_out" 2>/dev/null >&"$_knsh_fd" || :
  return 0
}

# The newest history entry: its number into $_knsh_n, its text into $_knsh_t (both empty without history).
# `history` prints "%5d%c %s": the number, `*` or a blank, a blank, the line.
_knsh_last_entry() {
  local _knsh_h
  _knsh_h=$(HISTTIMEFORMAT= builtin history 1 2>/dev/null) || _knsh_h=
  _knsh_h=${_knsh_h#"${_knsh_h%%[![:space:]]*}"}
  _knsh_n=${_knsh_h%%[!0-9]*}
  _knsh_h=${_knsh_h#"$_knsh_n"}
  _knsh_t=${_knsh_h#??}
}

# The first command of a line typed at the prompt is about to run (called by the DEBUG trap, after _knsh_arm).
_knsh_started() {
  local _knsh_c=$BASH_COMMAND
  _knsh_last_entry
  if [[ $_knsh_n != "${_knsh_hn-}" || $_knsh_t != "${_knsh_ht-}" ]]; then
    # The line reached history: the newest entry is the line as typed.
    _knsh_hn=$_knsh_n _knsh_ht=$_knsh_t
    _knsh_c=$_knsh_t
  elif [[ "${PROMPT_COMMAND[*]-}" == *"$_knsh_c"* ]]; then
    # A PROMPT_COMMAND entry added after _knsh_arm: not a line. _knsh_precmd moves _knsh_arm back to the end.
    return 1
  elif [[ -n $_knsh_t && $_knsh_t == "$_knsh_c"* ]]; then
    # Not saved, most likely a repeat of the newest entry (HISTCONTROL=ignoredups): that entry is the line.
    _knsh_c=$_knsh_t
  fi
  _knsh_armed=0 _knsh_running=1
  _knsh_emit preexec "$PWD" "$_knsh_c"
  return 0
}

# The DEBUG trap, installed as `_knsh_debug "$_"; <_knsh_trap_restore>` followed by the user's own trap, if any.
# The restore gives $? and $_ back, so the user's trap sees what it would have seen without ours.
_knsh_debug() {
  # PIPESTATUS taken as an array: "${PIPESTATUS[*]}" would join it with the user's IFS.
  local _knsh_s=$? _knsh_pa=("${PIPESTATUS[@]}") _knsh_f=${_knsh_fresh-0} IFS=' '
  local _knsh_p="${_knsh_pa[*]}"
  _knsh_ds=$_knsh_s _knsh_dl=${1-} _knsh_dk=1
  # Not in a subshell (with `set -T` the trap runs there too), nor inside one of our own functions.
  if (( BASH_SUBSHELL == 0 )) && [[ ${FUNCNAME[1]-} != _knsh_* ]]; then
    case $BASH_COMMAND in
      _knsh_precmd|_knsh_arm)
        # The status our PROMPT_COMMAND entries report and give back, as it was before they ran.
        _knsh_tfor=$BASH_COMMAND _knsh_ts=$_knsh_s _knsh_tp=$_knsh_p _knsh_tl=${1-} ;;
      _knsh_*|'case ${_knsh_rk'*|': "${_knsh_rl'*|'[[ -z ${_knsh_trap'*|'builtin trap -- "$_knsh_trap"'*|'builtin unset _knsh_trap'|': "${_knsh_status'*) ;;
      *)
        (( ${_knsh_armed-0} )) && [[ -z ${COMP_LINE-}${READLINE_LINE-} ]] && _knsh_started && _knsh_f=1
        # bash 3.2 does not keep PIPESTATUS across a trap (bash 4 does), and a pipeline may only run here when no
        # pipeline of the user's is being built: before the first command of a line, or of the user's
        # PROMPT_COMMAND (right after _knsh_precmd's restore).
        if (( _knsh_f && BASH_VERSINFO[0] < 4 )) && [[ $_knsh_p == *' '* ]]; then
          local IFS=' '
          _knsh_dps=($_knsh_p)
          _knsh_key "$_knsh_s" "${#_knsh_dps[@]}" "${_knsh_dps[${#_knsh_dps[@]}-1]}"
          _knsh_dk=$_knsh_out
        fi
        _knsh_fresh=0 ;;
    esac
  fi
  # With extdebug a non-zero status would skip the command, so nothing is given back then.
  builtin shopt -q extdebug && _knsh_dk=0
  return 0
}

# The status before one of our PROMPT_COMMAND entries ran: as the DEBUG trap saw it ($1 names the entry), or as
# the function itself sees it when the trap is not ours any more. Sets $_knsh_s, $_knsh_p and $_knsh_l.
_knsh_before() {
  if [[ ${_knsh_tfor-} == "$1" ]]; then
    _knsh_s=$_knsh_ts _knsh_p=$_knsh_tp _knsh_l=$_knsh_tl
  fi
  _knsh_tfor=
}

# Keeps our PROMPT_COMMAND entries first and last, when something added entries around them after installation.
_knsh_heal() {
  local _knsh_i _knsh_k
  _knsh_k=()
  if _knsh_pc_is_array; then
    [[ ${PROMPT_COMMAND[0]-} == "$_knsh_pre" && ${PROMPT_COMMAND[${#PROMPT_COMMAND[@]}-1]} == "$_knsh_post" ]] &&
      return 0
    for _knsh_i in "${PROMPT_COMMAND[@]}"; do
      [[ $_knsh_i == "$_knsh_pre" || $_knsh_i == "$_knsh_post" ]] || _knsh_k+=("$_knsh_i")
    done
    PROMPT_COMMAND=("$_knsh_pre" "${_knsh_k[@]}" "$_knsh_post")
  else
    [[ ${PROMPT_COMMAND-} == "$_knsh_pre"* && ${PROMPT_COMMAND-} == *"$_knsh_post" ]] && return 0
    _knsh_i=${PROMPT_COMMAND-}
    _knsh_i=${_knsh_i/"$_knsh_pre"$'\n'/}
    _knsh_i=${_knsh_i/$'\n'"$_knsh_post"/}
    PROMPT_COMMAND="$_knsh_pre"$'\n'"$_knsh_i"$'\n'"$_knsh_post"
  fi
}

# First PROMPT_COMMAND entry: the prompt is back.
_knsh_precmd() {
  local _knsh_s=$? _knsh_pa=("${PIPESTATUS[@]}") _knsh_l= IFS=' '
  local _knsh_p="${_knsh_pa[*]}"
  # Our DEBUG trap ran just before this: it is in place, nothing left for the entry to set.
  [[ ${_knsh_tfor-} == _knsh_precmd ]] && builtin unset _knsh_trap
  _knsh_before _knsh_precmd
  if (( _knsh_running )); then
    _knsh_running=0
    _knsh_emit precmd "$_knsh_s" "$PWD"
  elif [[ -n ${_knsh_hn+set} ]]; then
    # No command of the last line reached the DEBUG trap (a line that only runs a subshell or defines a function,
    # or the trap was replaced): report it now if it reached history.
    _knsh_last_entry
    if [[ $_knsh_n != "$_knsh_hn" || $_knsh_t != "$_knsh_ht" ]]; then
      _knsh_hn=$_knsh_n _knsh_ht=$_knsh_t
      _knsh_emit preexec "$PWD" "$_knsh_t"
      _knsh_emit precmd "$_knsh_s" "$PWD"
    fi
  fi
  _knsh_armed=0
  _knsh_heal
  _knsh_restore_from "$_knsh_s" "$_knsh_p" "$_knsh_l"
  # The next command not of ours starts the user's PROMPT_COMMAND (see _knsh_debug).
  _knsh_fresh=1
  return 0
}

# Last PROMPT_COMMAND entry: the next command run is the first of a line typed at the prompt.
_knsh_arm() {
  local _knsh_s=$? _knsh_pa=("${PIPESTATUS[@]}") _knsh_l= IFS=' '
  local _knsh_p="${_knsh_pa[*]}"
  _knsh_before _knsh_arm
  # History as it is now, after any `history -n` of the user's PROMPT_COMMAND, so only the next line differs.
  _knsh_last_entry
  _knsh_hn=$_knsh_n _knsh_ht=$_knsh_t
  _knsh_armed=1
  _knsh_restore_from "$_knsh_s" "$_knsh_p" "$_knsh_l"
  return 0
}

# PROMPT_COMMAND is an array (run element by element since bash 5.1).
_knsh_pc_is_array() {
  (( BASH_VERSINFO[0] > 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1) )) || return 1
  (( ${#PROMPT_COMMAND[@]} )) && [[ ${PROMPT_COMMAND@a} == *a* ]]
}

# $_knsh_out: $1 without the bootstrap $2 and the separator next to it; `:` where no separator could go.
_knsh_strip() {
  local _knsh_v=$1 _knsh_x
  if [[ $_knsh_v == "$2" ]]; then
    _knsh_v=
  else
    for _knsh_x in "$2; " "$2;" "$2"$'\n' "; $2" ";$2" $'\n'"$2"; do
      if [[ $_knsh_v == *"$_knsh_x"* ]]; then
        _knsh_v=${_knsh_v/"$_knsh_x"/}
        break
      fi
    done
    _knsh_v=${_knsh_v/"$2"/:}
  fi
  _knsh_out=$_knsh_v
}

# Removes the bootstrap from PROMPT_COMMAND. Sets $_knsh_boot_last when nothing runs after it at this first
# prompt (then the hooks can be armed at once).
_knsh_unboot() {
  local _knsh_b='. "${KNSH_BASH_BOOT:-/dev/null}" knsh-boot "$(builtin trap -p DEBUG)"' _knsh_i _knsh_last=
  _knsh_boot_last=0
  if _knsh_pc_is_array; then
    for _knsh_i in "${!PROMPT_COMMAND[@]}"; do _knsh_last=$_knsh_i; done
    for _knsh_i in "${!PROMPT_COMMAND[@]}"; do
      [[ $_knsh_i == "$_knsh_last" ]] && _knsh_after_boot "${PROMPT_COMMAND[_knsh_i]}" "$_knsh_b"
      _knsh_strip "${PROMPT_COMMAND[_knsh_i]}" "$_knsh_b"
      PROMPT_COMMAND[_knsh_i]=$_knsh_out
    done
  else
    _knsh_after_boot "${PROMPT_COMMAND-}" "$_knsh_b"
    _knsh_strip "${PROMPT_COMMAND-}" "$_knsh_b"
    PROMPT_COMMAND=$_knsh_out
  fi
  builtin export -n PROMPT_COMMAND
}

# Sets $_knsh_boot_last when $1 holds the bootstrap $2 followed by nothing but blanks and semicolons.
_knsh_after_boot() {
  [[ $1 == *"$2"* ]] || return 0
  local _knsh_r=${1#*"$2"}
  [[ $_knsh_r == *[![:space:]\;]* ]] || _knsh_boot_last=1
}

# Adds the hooks ($1: rc or boot; $2: `trap -p DEBUG` as read at the top level), except the DEBUG trap itself: it
# leaves the trap's code in $_knsh_trap for the caller to set at the top level. bash 3.2 hides the DEBUG trap inside
# a function and inside a file read with `.`, and puts back on return the one it had on entry. In the login case
# this file is read with `.`, so when the user already has a DEBUG trap, bash 3.2 undoes ours; the first
# PROMPT_COMMAND entry then sets it from $_knsh_trap, at the top level, at the next prompt.
# Returns 1, installing nothing, without a usable descriptor, in a shell knsh did not start (one started by a
# startup file inherits the bootstrap), or when not interactive; 2 when the hooks are already there.
_knsh_install() {
  case $_knsh_fd in ''|*[!0-9]*|[0-9]|1[0-9]) return 1 ;; esac
  [[ $PPID == "$_knsh_parent" && $- == *i* ]] || return 1
  local _knsh_prior=${2-}
  if [[ -n $_knsh_prior ]]; then
    # bash's own quoting of: trap -- '<code>' DEBUG
    builtin eval "_knsh_prior=( $_knsh_prior )"
    _knsh_prior=${_knsh_prior[2]-}
  fi
  [[ $_knsh_prior == *_knsh_debug* ]] && return 2
  _knsh_armed=0 _knsh_running=0 _knsh_fresh=0 _knsh_tfor=
  _knsh_trap="_knsh_debug \"\$_\"; $_knsh_trap_restore${_knsh_prior:+; $_knsh_prior}"
  _knsh_pre="_knsh_precmd; [[ -z \${_knsh_trap-} ]] || { builtin trap -- \"\$_knsh_trap\" DEBUG; builtin unset _knsh_trap; }; $_knsh_restore"
  _knsh_post="_knsh_arm; $_knsh_restore"
  if _knsh_pc_is_array; then
    PROMPT_COMMAND=("$_knsh_pre" "${PROMPT_COMMAND[@]}" "$_knsh_post")
  else
    PROMPT_COMMAND="$_knsh_pre${PROMPT_COMMAND:+$'\n'$PROMPT_COMMAND}"$'\n'"$_knsh_post"
  fi
  # Commands never inherit the hooks' PROMPT_COMMAND: a nested bash would not find the functions.
  builtin export -n PROMPT_COMMAND
  if [[ $1 == boot ]]; then
    # Installed from the first prompt's PROMPT_COMMAND, whose remaining entries still run now. Armed (as the last
    # command of this file) only if none follows; otherwise _knsh_precmd reports the first line at the next prompt.
    _knsh_last_entry
    _knsh_hn=$_knsh_n _knsh_ht=$_knsh_t
    _knsh_arm_now=$_knsh_boot_last
  fi
  return 0
}

# Removes everything this file defined, when the hooks were not added.
_knsh_remove() {
  \builtin unset -f _knsh_give _knsh_key _knsh_restore_from _knsh_esc _knsh_emit _knsh_last_entry _knsh_started _knsh_debug \
    _knsh_before _knsh_heal _knsh_precmd _knsh_arm _knsh_pc_is_array
  \builtin unset _knsh_fd _knsh_bs _knsh_restore _knsh_trap_restore _knsh_trap
}

if [[ ${1-} == knsh-boot ]]; then
  \_knsh_unboot
  (( _knsh_aliases )) && \builtin shopt -s expand_aliases
  \_knsh_install boot "${2-}"
else
  (( _knsh_aliases )) && \builtin shopt -s expand_aliases
  # What bash itself would have read in place of this file.
  if [[ -e ~/.bashrc ]]; then
    . ~/.bashrc
    _knsh_status=$?
  fi
  \_knsh_install rc "$(\builtin trap -p DEBUG)"
fi
case $? in
  0) \builtin trap -- "$_knsh_trap" DEBUG ;;
  1) \_knsh_remove ;;
esac
\builtin unset -f _knsh_strip _knsh_unboot _knsh_after_boot _knsh_install _knsh_remove
\builtin unset _knsh_aliases _knsh_parent _knsh_boot_last
# Last: once armed, the next command the DEBUG trap sees counts as a typed line. The subshell (never seen by the
# trap) and `:` after it give back the status the user's files left, without `set -e` or ERR seeing a failure; a
# top-level `return` would not set it when bash reads this file with --rcfile.
if [[ -n ${_knsh_arm_now-} ]]; then
  _knsh_armed=$_knsh_arm_now _knsh_arm_now=
fi
(exit "${_knsh_status-0}") && : "${_knsh_status-0}"
"#;

/// The bash of the user's login shell, when `shell` (the value of `$SHELL`) is an absolute path to a program named
/// `bash`; `None` means zsh is hosted. That bash is run as is: `/bin/bash` 3.2, Homebrew's bash 5, or any other.
#[must_use]
pub fn user_bash(shell: Option<&OsStr>) -> Option<&Path> {
    let path = Path::new(shell?);
    (path.is_absolute() && path.file_name() == Some(OsStr::new("bash"))).then_some(path)
}

/// What the wrapper needs while recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BashTelemetry {
    /// The inherited write end of the telemetry pipe.
    pub fd: RawFd,
    /// The process ID of `knsh`, the parent of the hosted bash.
    pub parent_pid: u32,
}

/// Everything that varies when starting bash.
#[derive(Debug, Clone, Copy)]
pub struct BashLaunch<'a> {
    /// The bash binary.
    pub bash: &'a Path,
    /// The installed startup directory, or `None` when it could not be installed: then plain bash starts, without
    /// hooks (FR-SES-22: a human shell is never refused).
    pub startup_dir: Option<&'a Path>,
    /// A login shell (`-l`, `--login`, or `argv[0]` starting with `-`).
    pub login: bool,
    /// `-i` was given.
    pub force_interactive: bool,
    /// Recording: the descriptor and parent to hand the wrapper; `None` when recording is off.
    pub telemetry: Option<BashTelemetry>,
    /// The `PROMPT_COMMAND` `knsh` inherited, kept after the bootstrap of a recorded login shell.
    pub user_prompt_command: Option<&'a OsStr>,
}

impl BashLaunch<'_> {
    /// The plan for this launch. The rest of the environment is inherited unchanged.
    #[must_use]
    pub fn plan(&self) -> LaunchPlan {
        // `-bash` is how `login(1)` starts a login shell, so `$0` and `shopt login_shell` match plain bash.
        let argv0 = if self.login { "-bash" } else { "bash" };
        let mut args = Vec::new();
        // Our own variables never pass through from knsh's environment: a stale value would mislead the wrapper.
        let mut remove_env = vec![
            OsString::from(TELEMETRY_FD_VAR),
            OsString::from(PARENT_PID_VAR),
            OsString::from(BOOT_PATH_VAR),
            // Only a shell that is recorded right now may claim it (FR-SES-25).
            OsString::from(super::RECORDING_VAR),
        ];
        let mut set_env = Vec::new();
        if let (Some(dir), Some(telemetry)) = (self.startup_dir, self.telemetry) {
            let wrapper = wrapper_path(dir);
            // Hooks installed and telemetry flowing: the shell is recorded (KNSH-021).
            set_env.push((OsString::from(super::RECORDING_VAR), OsString::from("1")));
            set_env.push((
                OsString::from(TELEMETRY_FD_VAR),
                OsString::from(telemetry.fd.to_string()),
            ));
            set_env.push((
                OsString::from(PARENT_PID_VAR),
                OsString::from(telemetry.parent_pid.to_string()),
            ));
            if self.login {
                remove_env.push(OsString::from(PROMPT_COMMAND_VAR));
                set_env.push((OsString::from(BOOT_PATH_VAR), wrapper.into_os_string()));
                set_env.push((
                    OsString::from(PROMPT_COMMAND_VAR),
                    bootstrap_prompt_command(self.user_prompt_command),
                ));
            } else {
                // Long options must come before `-i`.
                args.push(OsString::from("--rcfile"));
                args.push(wrapper.into_os_string());
            }
        }
        if self.force_interactive {
            args.push(OsString::from("-i"));
        }
        LaunchPlan {
            program: self.bash.to_path_buf(),
            arg0: OsString::from(argv0),
            args,
            remove_env,
            set_env,
        }
    }
}

/// The `PROMPT_COMMAND` of a recorded login shell: [`BOOTSTRAP`], then the user's own one on the next line, so that
/// what the startup files add to it, and the user's entries, still run at the first prompt.
#[must_use]
pub fn bootstrap_prompt_command(user: Option<&OsStr>) -> OsString {
    let mut value = OsString::from(BOOTSTRAP);
    if let Some(user) = user.filter(|user| !user.is_empty()) {
        value.push("\n");
        value.push(user);
    }
    value
}

/// The wrapper's path inside `startup_dir`.
#[must_use]
pub fn wrapper_path(startup_dir: &Path) -> PathBuf {
    startup_dir.join(STARTUP_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(needle: &str) -> usize {
        BASHRC
            .find(needle)
            .unwrap_or_else(|| panic!("wrapper lacks {needle:?}"))
    }

    fn function_body(name: &str) -> &'static str {
        let start = position(&format!("\n{name}() {{"));
        let body = &BASHRC[start..];
        &body[..body.find("\n}\n").expect("function end")]
    }

    fn launch() -> BashLaunch<'static> {
        BashLaunch {
            bash: Path::new(SYSTEM_BASH),
            startup_dir: Some(Path::new("/h/engine/shell/bash")),
            login: false,
            force_interactive: false,
            telemetry: Some(BashTelemetry { fd: 5, parent_pid: 42 }),
            user_prompt_command: None,
        }
    }

    fn env_value<'a>(plan: &'a LaunchPlan, key: &str) -> Option<&'a OsStr> {
        plan.set_env
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_os_str())
    }

    // KNSH-020 unit test (AC "Existing PROMPT_COMMAND (string or, in bash 5.1+, array) and DEBUG traps of the user
    // still run"): our entries go around the user's PROMPT_COMMAND, never instead of it, in both forms, and the
    // user's DEBUG trap is appended to ours. The behaviour itself is checked against real bash in
    // tests/bash_integration.rs.
    #[test]
    fn wrapper_chains_existing_prompt_command() {
        let install = function_body("_knsh_install");
        assert!(
            install.contains(r#"PROMPT_COMMAND="$_knsh_pre${PROMPT_COMMAND:+$'\n'$PROMPT_COMMAND}"$'\n'"$_knsh_post""#)
        );
        assert!(install.contains(r#"PROMPT_COMMAND=("$_knsh_pre" "${PROMPT_COMMAND[@]}" "$_knsh_post")"#));
        // The user's trap is read at the top level (bash 3.2 hides it inside functions and files read with `.`):
        // after ~/.bashrc, or by the login bootstrap.
        assert!(install.contains("local _knsh_prior=${2-}"));
        assert!(BASHRC.contains(r#"\_knsh_install rc "$(\builtin trap -p DEBUG)""#));
        assert!(BOOTSTRAP.ends_with(r#"knsh-boot "$(builtin trap -p DEBUG)""#));
        assert!(install.contains(r#"${_knsh_prior:+; $_knsh_prior}""#));
        // Ours first, then $? and $_ given back, then the user's: the user's trap sees what it would see alone, and
        // decides what extdebug does with its status.
        assert!(install.contains(r#"_knsh_trap="_knsh_debug \"\$_\"; $_knsh_trap_restore${"#));
        // Set at the top level: bash 3.2 restores, on return from a function, the DEBUG trap it had on entry.
        assert!(BASHRC.contains("\n  0) \\builtin trap -- \"$_knsh_trap\" DEBUG ;;\n"));
        assert!(
            !install.contains("\n  builtin trap"),
            "the function itself never sets the trap"
        );
        // When bash 3.2 undid it (read with `.` over a user's trap), the first PROMPT_COMMAND entry sets it.
        assert!(install.contains(r#"[[ -z \${_knsh_trap-} ]] || { builtin trap -- \"\$_knsh_trap\" DEBUG;"#));
        // Never assigned outright anywhere else.
        assert_eq!(
            BASHRC.matches("PROMPT_COMMAND=(").count(),
            2,
            "install and heal (array)"
        );
        for clobber in ["PROMPT_COMMAND='", "PROMPT_COMMAND=_knsh", "trap - DEBUG"] {
            assert!(!BASHRC.contains(clobber), "wrapper must not contain {clobber:?}");
        }
        // The array form is used only where bash runs it (5.1+); `@a` is never expanded by bash 3.2.
        let is_array = function_body("_knsh_pc_is_array");
        assert!(is_array.find("BASH_VERSINFO") < is_array.find("@a"));
    }

    // NFR-COMPAT-01: in the non-login case the wrapper sources ~/.bashrc, which bash would have read, and nothing
    // else; the profile files of a login shell are always read by bash itself.
    #[test]
    fn wrapper_sources_only_bashrc() {
        assert_eq!(BASHRC.matches("\n    . ").count(), 1);
        assert!(BASHRC.contains("if [[ -e ~/.bashrc ]]; then\n    . ~/.bashrc\n"));
        for other in [".bash_profile", ".bash_login", ".profile", ".bash_logout", "/etc/"] {
            assert!(!BASHRC.contains(other), "{other} is left to bash");
        }
        // Aliases are off while the wrapper is parsed, and back on before the user's file runs.
        assert!(position("shopt -u expand_aliases") < position("_knsh_debug() {"));
        assert!(position("shopt -s expand_aliases") < position(". ~/.bashrc"));
        // The variables are gone before the user's file runs.
        assert!(position("unset KNSH_TELEMETRY_FD KNSH_TELEMETRY_PPID KNSH_BASH_BOOT") < position(". ~/.bashrc"));
    }

    // The bootstrap text in PROMPT_COMMAND is exactly the one the wrapper looks for and removes.
    #[test]
    fn bootstrap_matches_the_wrapper() {
        assert!(BASHRC.contains(&format!("_knsh_b='{BOOTSTRAP}'")));
        assert!(!BOOTSTRAP.contains('\''), "the wrapper quotes it in single quotes");
        assert_eq!(bootstrap_prompt_command(None), BOOTSTRAP);
        assert_eq!(bootstrap_prompt_command(Some(OsStr::new(""))), BOOTSTRAP);
        assert_eq!(
            bootstrap_prompt_command(Some(OsStr::new("history -a"))),
            OsString::from(format!("{BOOTSTRAP}\nhistory -a"))
        );
    }

    // FR-SES-22: the hooks never print, never fail under `set -e`/`set -u`, and give $? back.
    #[test]
    fn hooks_never_print_or_fail() {
        let emit = function_body("_knsh_emit");
        assert!(emit.contains("[[ -p /dev/fd/$_knsh_fd ]] || return 0"));
        assert!(emit.contains(r#"2>/dev/null >&"$_knsh_fd" || :"#));
        let debug = function_body("_knsh_debug");
        assert!(debug.contains("\n  local _knsh_s=$? _knsh_pa=(\"${PIPESTATUS[@]}\")"));
        // Joined with a blank whatever the user's IFS: a status list joined otherwise breaks the arithmetic.
        assert!(!BASHRC.contains("_knsh_p=\"${PIPESTATUS[*]}\""));
        for hook in ["_knsh_debug", "_knsh_precmd", "_knsh_arm"] {
            assert!(
                function_body(hook).contains(" IFS=' '\n  local _knsh_p=\"${_knsh_pa[*]}\""),
                "{hook}"
            );
        }
        // Under extdebug a non-zero trap status would skip the user's command: nothing is given back then.
        assert!(debug.contains("builtin shopt -q extdebug && _knsh_dk=0"));
        assert!(debug.ends_with("return 0"));
        assert!(BASHRC.contains("0) : \"${_knsh_rl-}\";;"));
        assert!(BASHRC.contains("_knsh_trap_restore=${_knsh_restore//_knsh_r/_knsh_d}"));
        // A failing restore is always exempt from errexit and ERR: `&& :` after it, or `!` before it.
        assert!(BASHRC.contains(r#"${_knsh_i}n) $_knsh_k && :;; ${_knsh_i}x) ! $_knsh_k;;""#));
        assert!(BASHRC.contains(r"1x) ! _knsh_give"));
        assert!(BASHRC.contains(r#"*) _knsh_give "${_knsh_rs-0}" "${_knsh_rl-}" && : "${_knsh_rl-}";; esac'"#));
        // The renaming above touches nothing but the restore variables: every `_knsh_r` in the restore code
        // starts one of them.
        let restore = &BASHRC[position("_knsh_restore='")..position("_knsh_trap_restore=")];
        for name in restore.split("_knsh_r").skip(1) {
            assert!(
                ["k", "ps", "s", "l", "estore"].iter().any(|var| name.starts_with(var)),
                "unexpected name _knsh_r{name}"
            );
        }
        // The hooks run no external program: no pipeline into one, no substitution of one.
        for program in ["sed", "awk", "date", "cat", "tr", "printf"] {
            for use_ in [format!("| {program}"), format!("$({program}")] {
                assert!(!BASHRC.contains(&use_), "{use_}");
            }
        }
    }

    #[test]
    fn recording_off_is_plain_bash() {
        let plan = BashLaunch {
            telemetry: None,
            login: true,
            ..launch()
        }
        .plan();
        assert_eq!(plan.arg0, "-bash");
        assert_eq!(plan.args.len(), 0);
        assert_eq!(plan.set_env.len(), 0);
        for name in [TELEMETRY_FD_VAR, PARENT_PID_VAR, BOOT_PATH_VAR] {
            assert!(plan.remove_env.iter().any(|removed| removed == name), "{name}");
        }
        assert!(!plan.remove_env.iter().any(|removed| removed == PROMPT_COMMAND_VAR));

        // Without a startup directory, plain bash too.
        let plan = BashLaunch {
            startup_dir: None,
            ..launch()
        }
        .plan();
        assert_eq!(plan.set_env.len(), 0);
        assert_eq!(plan.args.len(), 0);
    }

    #[test]
    fn recorded_non_login_shell_reads_the_wrapper() {
        let plan = BashLaunch {
            force_interactive: true,
            ..launch()
        }
        .plan();
        assert_eq!(plan.arg0, "bash");
        assert_eq!(
            plan.args,
            [
                OsString::from("--rcfile"),
                OsString::from("/h/engine/shell/bash/bashrc"),
                OsString::from("-i")
            ]
        );
        assert_eq!(env_value(&plan, TELEMETRY_FD_VAR), Some(OsStr::new("5")));
        assert_eq!(env_value(&plan, PARENT_PID_VAR), Some(OsStr::new("42")));
        assert_eq!(env_value(&plan, PROMPT_COMMAND_VAR), None);
    }

    #[test]
    fn recorded_login_shell_starts_with_the_bootstrap() {
        let plan = BashLaunch {
            login: true,
            user_prompt_command: Some(OsStr::new("echo hi")),
            ..launch()
        }
        .plan();
        assert_eq!(plan.arg0, "-bash");
        assert_eq!(plan.args.len(), 0);
        assert_eq!(
            env_value(&plan, BOOT_PATH_VAR),
            Some(OsStr::new("/h/engine/shell/bash/bashrc"))
        );
        assert_eq!(
            env_value(&plan, PROMPT_COMMAND_VAR),
            Some(OsString::from(format!("{BOOTSTRAP}\necho hi")).as_os_str())
        );
        assert!(plan.remove_env.iter().any(|removed| removed == PROMPT_COMMAND_VAR));
    }

    #[test]
    fn only_an_absolute_bash_is_hosted() {
        assert_eq!(user_bash(Some(OsStr::new("/bin/bash"))), Some(Path::new("/bin/bash")));
        assert_eq!(
            user_bash(Some(OsStr::new("/opt/homebrew/bin/bash"))),
            Some(Path::new("/opt/homebrew/bin/bash"))
        );
        for other in ["/bin/zsh", "bash", "/usr/local/bin/knsh", "/bin/bash5", ""] {
            assert_eq!(user_bash(Some(OsStr::new(other))), None, "{other}");
        }
        assert_eq!(user_bash(None), None);
    }
}
