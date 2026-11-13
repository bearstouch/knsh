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

- [ ] Each wrapper's option grammar is implemented explicitly; unknown options make the command dynamic
  (fail closed), not mis-parsed.
- [ ] Wrappers nest (`env nice timeout 5 git push`).
- [ ] `xargs` with no command runs `echo`; with `-I`/`-J` placeholders the inner command is still classified; the
  arguments `xargs` supplies are unknown, so argument-sensitive rules see the inner command as having unknown
  arguments (documented).
- [ ] Record `argv` keeps both the wrapper entries (`wrapper`) and the inner command.

*Dynamic-code classification*

- [ ] Classification returns `Dynamic { reason }` with one of a closed enum of reasons.
- [ ] `source` of a file outside write roots and in a trusted location is not dynamic only if readable and resolved;
  otherwise dynamic.
- [ ] Interpreter detection uses the resolved binary's basename family (e.g. `python3.12`), not the raw name.
- [ ] Running a script file with an interpreter (`python3 script.py`) is not dynamic per the spec list; the record
  shows it as `static` or `project_executable` by the interpreter's resolution.
- [ ] The interpreter list is data, documented, and extendable by profile.

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
[../05-models/policy-profile.md](../05-models/policy-profile.md).
