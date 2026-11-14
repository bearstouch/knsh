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
- [x] Substitutions in words, assignments and redirection targets are parsed into nested `Script`s;
  `simple_commands()` includes their commands.
- [x] Backtick bodies are un-escaped per bash rules before recursive parsing.
- [x] Here-document bodies are captured; multiple here-docs on one line are matched to their operators in order.
- [x] A here-document or here-string whose consumer is a shell or interpreter (`bash`, `sh`, `zsh`, `python3`,
  `node`, `ruby`, `perl`, …) is marked for dynamic classification (decision 6).
- [x] Missing here-doc delimiter is a `ParseError`.
- [x] Nesting depth is bounded (KNSH-032).

**Unit tests**
- `parses_nested_command_substitution` — `echo $(a $(b))` exposes `a` and `b`.
- `parses_backticks_with_escaped_backtick`.
- `substitution_in_assignment_is_visible` — `X=$(curl …) cmd`.
- `parses_heredoc_quoted_delimiter_body_literal`.
- `strips_tabs_for_dash_heredoc`.
- `matches_two_heredocs_on_one_line_in_order`.
- `marks_heredoc_into_bash_as_dynamic_candidate` — `bash <<EOF … EOF`.
- `errors_on_missing_heredoc_delimiter`.

**Notes (clarified during implementation).**
- Every `$( … )`, backtick, `<( … )` and `>( … )` in a command word, assignment value, redirection target, `for` item,
  `case` subject or pattern, function name, or unquoted here-document body (inside double quotes too) becomes a
  `Substitution` holding a nested `Script` (`CommandWord::substitutions`, `Assignment::substitutions`,
  `HereDocument::substitutions`). `Script::commands()`/`simple_commands()` yield each command, then the commands of its
  substitutions, in source order. The body is lexed again exactly as the line's lexer read it (same quote and
  substitution depth, same bash 3.2 comment rules), so neither nesting limit resets inside a substitution.
- Backtick bodies are un-escaped as bash does first: `\$`, `` \` `` and `\\` lose the backslash, so does `\"` when
  the backticks are inside double quotes (not in a here-document body, where bash 3.2 keeps it), and line
  continuations are removed (bash 3.2 checked). When that changes the text, the un-escaped body is kept as
  `Substitution::text` and the nested script's spans index it; `Script::commands_with_source(line)` pairs each command
  with the text its spans index. Errors inside are mapped back onto the line.
- A substitution inside `${ … }`, `$(( … ))` or `$[ … ]` (`${x:-$(rm f)}`) runs commands the lexer keeps inside the
  expansion, so the line is refused (`UnsupportedConstruct::SubstitutionInExpansion`).
- Here-documents: the lexer reads each body at the newline ending its operator's line, in operator order, as a
  `TokenKind::HereDocumentBody` token after that newline; the parser attaches it to the redirection
  (`Redirect::here_document`). The delimiter is the word's text after quote removal; any quoting makes the body
  literal; a delimiter holding an expansion or `$'…'`/`$"…"` is refused (`LexError::HereDocumentDelimiter`). With an
  unquoted delimiter an unescaped `\` newline joins body lines before the comparison (bash 3.2: `foo\` + `EOF` is not
  the end; `EO\` + `F` is), and the body is segmented like double-quoted text with `"` literal. `<<-` strips leading
  tabs before comparing; since bash strips them before expanding the body, a `$( … )` or backtick in an unquoted
  `<<-` body that runs onto a line starting with a tab is refused (`AmbiguousHereDocument`: a nested delimiter `\tX`
  would end in bash and not here). The delimiter line may end the input without a newline.
- "Missing delimiter": a body that starts but never reaches its delimiter line is `LexError::Unterminated` with
  `Construct::HereDocument`; an operator whose line ends the input is `ParseError::MissingHereDocumentBody`. Bash runs
  both with a warning.
- Bash 3.2 finds the end of `$( … )` by matching characters, so for a here-document inside one it may close the
  substitution at a `)` in the body, open a quote at a `'`, or run the lines after `$(cat <<EOF)` as commands. Such
  cases are refused (`LexError::AmbiguousHereDocument`): a body (or delimiter line) inside `$( … )`, `<( … )` or
  `>( … )` holding `(`, `)`, `'`, `"`, `` ` ``, `\` or `$`; an operator inside a substitution whose body never started
  there; a newline inside a substitution while a here-document outside it waits for its body. Bodies inside backticks
  are parsed afresh by every version and are not restricted.
- A `<<` inside `(( … ))` (a shift) is not a redirection: alone on its line it is harmless, but if a newline follows,
  the lines the lexer took for a body would be hidden, so the line is refused (`OpaqueHereDocument`).
- Interpreter consumers (`Redirect::feeds_interpreter`, decision 6): set on a here-document or here-string read by a
  shell or interpreter by base name without version suffix (`bash`, `sh`, `zsh`, `python3.12`, `node`, `ruby`,
  `perl`, `php`, `lua`, `osascript`, `pwsh`, …, plus `ssh` and `su`), by a command with one among its arguments
  (`env bash`, `uv run python`, `docker exec -i c sh`), by a wrapper with an expansion argument or a shell option
  (`sudo -s`), by a name built from an expansion, by a function defined in the same script, or (on a compound command)
  when any command inside qualifies. `cat <<EOF | bash` is not marked here: `bash` reading standard input is dynamic in
  its own right (KNSH-036).
- Calls inside substitutions are never marked as function calls (they run in child shells parsed under conditions the
  line does not show), and definitions inside substitutions never reach the line.
- Cost: each nesting level lexes its body again, so the worst case is depth × length (about 0.9 s in release for a
  1 MiB line nested 32 levels). KNSH-032 may bound it further (token count limit).
