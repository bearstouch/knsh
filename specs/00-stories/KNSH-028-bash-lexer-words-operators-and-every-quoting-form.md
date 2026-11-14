# KNSH-028 — Bash lexer: words, operators and every quoting form

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Parser | L (5) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | `knsh-bash` | FR-LC-02, decision 6, NFR-SEC-05 |

**Description.** As the supervisor, I want a lexer that turns an agent command line into tokens with exact source
spans, so that the parser can classify every part of the line. Scope: words, operators (`|`, `||`, `&&`, `;`, `&`,
`(`, `)`, `{`, `}`, redirection operators including `<<`, `<<-`, `<<<`, `>|`, `&>`, `n>&m`), comments, newlines, and
every quoting form: single quotes, double quotes, `$'…'`, `$"…"`, backslash escapes, line continuation. Words keep
their quoted structure (segments). Out of scope: expansion semantics, here-document bodies (KNSH-031). `{` and `}` are
reserved words in bash, not operators (`echo {}` is one word), so the lexer emits them as words marked as
reserved-word candidates. Until KNSH-031 reads here-document bodies, a line whose here-document body follows is
rejected (`LexError::HereDocumentBody`) rather than lexed as commands. A `#` comment that bash 3.2 would read
differently (inside `<( … )`, or not after a blank inside `$( … )`) is refused (`LexError::AmbiguousComment`).

**Acceptance criteria**
- [x] Pure function `lex(&str) -> Result<Vec<Token>, LexError>`; no I/O, no global state; `#![forbid(unsafe_code)]`.
- [x] Every token carries a byte span into the input; concatenating spans reproduces the input exactly.
- [x] Unterminated quotes return `LexError::Unterminated` with the span, never a guess.
- [x] Input larger than the configured limit is rejected before tokenising (limit defined in KNSH-032).
- [x] Reserved words are recognised only in command position (left to the parser; the lexer marks candidates).
- [x] A fuzz target `bash_lex` exists in `fuzz/` and runs in CI smoke mode.
- [x] Crate `//!` header cites decision 6 and FR-LC-02.

**Unit tests**
- `lexes_single_quoted_word_without_escapes` — `'a\b'` is literal (decision 6, quoting forms).
- `lexes_ansi_c_quoting` — `$'\n\x41'` segments are marked ANSI-C.
- `lexes_double_quotes_with_nested_dollar` — `"a $(b "c") d"` keeps the substitution span.
- `lexes_line_continuation_as_nothing` — `ec\<newline>ho` is one word.
- `splits_all_control_operators` — `a||b&&c;d&e|f` yields the expected operator sequence.
- `recognises_redirection_operators_with_fd_numbers` — `2>&1`, `&>`, `>|`, `<<<`.
- `rejects_unterminated_single_quote` — error with span, no tokens returned.
- `spans_round_trip_to_source` — property test over random inputs.
- `comment_ends_at_newline_only_at_word_start` — `a#b` is a word, `a #b` is a comment.
