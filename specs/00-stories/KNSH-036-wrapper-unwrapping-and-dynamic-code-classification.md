# KNSH-036 — Wrapper unwrapping and dynamic-code classification

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Classifier | XL (8) | [KNSH-035](KNSH-035-binary-resolution-and-trusted-folders.md) | `knsh-bash` | FR-LC-04, FR-LC-05, FR-POL-20, FR-POL-21, decision 6 |

**Description.** Merged from *Wrapper unwrapping* and *Dynamic-code classification*: they are done and validated together because both are validated by the same classifier table tests over the corpus.

*Wrapper unwrapping.* As the supervisor, I want known wrappers unwrapped so that `env FOO=1 nice -n 5 git push` is decided
as `git push`. Scope: `env` (assignments, `-i`, `-u`), `command` (`-p`; `-v`/`-V` are not execution), `exec`,
`nice`, `nohup`, `time` (keyword and binary), `timeout` (duration and options), `xargs` (the command it runs).
The wrapper is recorded as class `wrapper` and the inner command classified normally.

*Dynamic-code classification.* As the supervisor, I want every form of dynamic code marked, so that policy can allow or ask for it
without letting it inherit classes, network or secrets. Scope: `eval`; `source`/`.` of agent-writable files (any
file under the session's write roots, or not resolvable); `sh -c`, `bash -c`, `zsh -c`; interpreters with `-c` or
`-e` (python, python3, node, ruby, perl, php, deno, bun, osascript); command names from variables or expansions;
here-docs into shells or interpreters (KNSH-031); everything KNSH-032 marks dynamic.

**Acceptance criteria**
*Wrapper unwrapping*

- [x] Each wrapper's option grammar is implemented explicitly; unknown options make the command dynamic
  (fail closed), not mis-parsed.
- [x] Wrappers nest (`env nice timeout 5 git push`).
- [x] `xargs` with no command runs `echo`; with `-I`/`-J` placeholders the inner command is still classified; the
  arguments `xargs` supplies are unknown, so argument-sensitive rules see the inner command as having unknown
  arguments (documented).
- [x] Record `argv` keeps both the wrapper entries (`wrapper`) and the inner command.

*Dynamic-code classification*

- [x] Classification returns `Dynamic { reason }` with one of a closed enum of reasons.
- [x] `source` of a file outside write roots and in a trusted location is not dynamic only if readable and resolved;
  otherwise dynamic.
- [x] Interpreter detection uses the resolved binary's basename family (e.g. `python3.12`), not the raw name.
- [x] Running a script file with an interpreter (`python3 script.py`) is not dynamic per the spec list; the record
  shows it as `static` or `project_executable` by the interpreter's resolution.
- [x] The interpreter list is data, documented, and extendable by profile.

**Unit tests**
*Wrapper unwrapping*

- `unwraps_env_with_assignments_and_flags`.
- `unwraps_nested_wrappers`.
- `command_v_is_not_execution`.
- `timeout_with_signal_option_unwraps`.
- `xargs_inner_command_is_classified`.
- `unknown_wrapper_option_is_dynamic`.

*Dynamic-code classification*

- `eval_is_dynamic`, `bash_dash_c_is_dynamic`, `python_dash_c_is_dynamic`, `node_dash_e_is_dynamic`.
- `source_of_project_file_is_dynamic` — under `${PROJECT}`.
- `variable_command_name_is_dynamic` — `$X`, `${X}`.
- `interpreter_family_matches_versioned_basename`.
- `python_running_a_script_is_not_dynamic`.

**Notes**
*Dynamic-code classification*

— The spec does not say whether a profile can extend the interpreter list; propose a key in
[../05-models/policy-profile.md](../05-models/policy-profile.md). **Done:** `exec.interpreters.<family>` is proposed
there; `knsh_bash::Interpreters::extend` implements it (extend-only: a profile can add families and options, never
remove them). Wiring it into the profile loader is KNSH-039.

*Implementation notes (KNSH-036)*

- `knsh_bash::classify(outcome, line, resolver, interpreters)` returns a `Classification`: one `ClassifiedCommand` per
  `argv` entry (wrappers and the commands they run are separate, linked entries) and the line's dynamic parts. Name
  resolution and the trust of sourced files come through the `Resolver` trait; the `knsh-core` adapter over
  KNSH-035's `resolve` and the session's write roots is supervisor wiring (KNSH-041/KNSH-050).
- The parser now reads the `time` keyword where every bash agrees on it (`time [-p] [!] pipeline` at the start of a
  pipeline); everywhere else (`! time`, `a | time b`, bare `time`, `time --`) the line stays refused, so dynamic.
- `builtin` is unwrapped like `command` (otherwise `builtin eval …` would hide an `eval`), and a wrapper is matched by
  the resolved base name or the name as written whatever it resolved to: `nice command eval x` runs macOS's
  `/usr/bin/command` script, which runs the builtin.
- Interpreters are matched by the resolved binary's family and by the name as written; either can only add a dynamic
  mark. An expansion before an interpreter's script (`python3 "$f"`) or in a wrapper's options is dynamic
  (`expanded_argument`), since it could split into or be a code option.
- Known limits: `env -i` and `command -p` search a default `PATH` the resolver does not model, and a wrapper's inner
  command is looked up with the session `PATH` even when the line sets `PATH` for it; KNSH-038 should rewrite inner
  command names to their resolved absolute paths too (their spans are in `ClassifiedCommand::name_span`). `sudo`,
  `doas`, `ssh` and other launchers outside FR-LC-04 are not unwrapped; profiles deny them by name.
- Review fixes: the shells read a value option inside a cluster from the next argument and go on (`bash -oc errexit
  code` is code; `Interpreter::cluster_values_from_next`); a long option the interpreter table does not know may take
  the next argument, so a code option after it is still found (`zsh --emulate sh -c`, `ruby --disable gems -e`,
  `node --allow-fs-read /tmp -e`); a script path naming standard input (`bash /dev/stdin`, `/dev/fd/0`) reads it; an
  interpreter is checked before a wrapper and a name that only reads like a wrapper (resolving to another binary)
  keeps that binary's class; `trap` with an action, `mapfile -C` and `alias` with a value are `eval`; a variable whose
  value a shell or program runs as code (`BASH_ENV`, `PS4`, `NODE_OPTIONS`, `GIT_PAGER`, `BASH_FUNC_*`, `DYLD_*`, …)
  set for a command, as an `env` operand or by `export`/`declare`/`local`/`readonly`/`typeset` makes it dynamic with
  the new reason `code_variable`. The pager and editor variables (`GIT_PAGER`, `PAGER`, `EDITOR`, …) set to a bare
  program name or to nothing are not code (`GIT_PAGER=cat git push` keeps its classes); any other value is.
- Still open (not detected): bash evaluates array subscripts in arithmetic, so a quoted `'a[$(cmd)]'` given to
  `printf -v`, `let`, `read`, `declare`, `shift`, `wait`, `ulimit`, `printf %d` or used in `$((x))` runs `cmd`
  (observed with `/bin/bash` 3.2); launchers outside FR-LC-04 (`find -exec`, `git -c core.pager=…`, `awk 'system()'`,
  `make`, `npm run`) run code the classifier does not see; `enable -f` loads a shared object; the code-variable list is
  not exhaustive. The sandbox and proxy remain the boundary (FR-POL-21).
- Fuzzing (`bash_parse`, nightly) found a property failure that predates this story (reproduced on `master`): a
  here-document on an unsupported node (`[[ ]]<<O` newline `O`) is not claimed by the tree. The line is dynamic in
  that part, so it fails closed; fixing the claim is a KNSH-031/KNSH-032 follow-up.
