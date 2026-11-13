# KNSH-031 — Bash parser: command substitution, backticks and here-documents

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Parser | L (5) | [KNSH-029](KNSH-029-bash-parser-simple-commands-assignments-pipelines-lists.md) | `knsh-bash` | FR-LC-02, FR-LC-05, decision 6 |

**Description.** As the supervisor, I want `$( … )` and backticks parsed recursively and here-documents read with
their bodies, so that commands hidden in substitutions are decided and here-docs fed to shells or interpreters are
flagged. Scope: nested substitutions, backticks with escaped backticks, `<<`, `<<-` (tab stripping), quoted vs
unquoted delimiters, `<<<` here-strings, process substitution `<( )`/`>( )` parsed recursively.

**Acceptance criteria**
- [ ] Substitutions in words, assignments and redirection targets are parsed into nested `Script`s;
  `simple_commands()` includes their commands.
- [ ] Backtick bodies are un-escaped per bash rules before recursive parsing.
- [ ] Here-document bodies are captured; multiple here-docs on one line are matched to their operators in order.
- [ ] A here-document or here-string whose consumer is a shell or interpreter (`bash`, `sh`, `zsh`, `python3`,
  `node`, `ruby`, `perl`, …) is marked for dynamic classification (decision 6).
- [ ] Missing here-doc delimiter is a `ParseError`.
- [ ] Nesting depth is bounded (KNSH-032).

**Unit tests**
- `parses_nested_command_substitution` — `echo $(a $(b))` exposes `a` and `b`.
- `parses_backticks_with_escaped_backtick`.
- `substitution_in_assignment_is_visible` — `X=$(curl …) cmd`.
- `parses_heredoc_quoted_delimiter_body_literal`.
- `strips_tabs_for_dash_heredoc`.
- `matches_two_heredocs_on_one_line_in_order`.
- `marks_heredoc_into_bash_as_dynamic_candidate` — `bash <<EOF … EOF`.
- `errors_on_missing_heredoc_delimiter`.
