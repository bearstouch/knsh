//! Hard limits on what the lexer and parser read (KNSH-032; NFR-SEC-05; CLAUDE.md "Untrusted input": check sizes
//! before allocating and bound recursion).
//!
//! Each limit is checked before the work it bounds grows past it: the size check comes before anything is read, the
//! token count stops the lexer at the first token over the budget, and the nesting check stops the recursion at the
//! first level over it. The excess over a limit is never stored. What a line at the limits may use is bounded
//! linearly by its size (the segments of one word and the lexer's scan state are bounded by [`MAX_INPUT_LEN`], not by
//! [`MAX_TOKENS`]). A line over any limit is never read partly: [`parse`](crate::parse) returns an error and
//! [`parse_line`](crate::parse_line) marks the whole line as dynamic code ([`DynamicReason`](crate::DynamicReason)),
//! never as an allow (decision 6).
//!
//! The values are listed with their rationale in `specs/09-reference/defaults-and-limits.md`.

/// Longest command line [`lex`](crate::lex) and [`parse`](crate::parse) read, in bytes, checked before tokenising.
/// 1 MiB is macOS's `ARG_MAX`, so a line handed to `bash -c` can never be longer, and it equals the 1 MB frame payload
/// limit a line arrives in over `agent.sock`.
pub const MAX_INPUT_LEN: usize = 1024 * 1024;

/// Deepest nesting the lexer and the parser follow. In the lexer it counts quotes and substitutions
/// (`"$(a "$(b)")"` is four levels); in the parser, nested lists (compound command bodies, function bodies and
/// substitution scripts). Both bound recursion on untrusted input. Real agent lines nest a few levels; 32 matches the
/// JSON and TOML nesting limits.
pub const MAX_NESTING_DEPTH: usize = 32;

/// Most tokens one line may produce, counted over the line and every substitution body parsed in it (blanks,
/// comments, newlines and here-document bodies count; each substitution body's tokens count once, when it is parsed).
/// It bounds the memory of the token lists and of the tree built from them, which the input size alone bounds only
/// loosely: a 1 MiB line of one-letter words is about a million tokens. Agent lines hold tens to a few hundred tokens,
/// and a long generated argument list (`git add` of thousands of files) stays well under 65,536.
pub const MAX_TOKENS: usize = 64 * 1024;

/// Most function definitions with matchable names a line may hold for calls to be marked as function calls
/// (KNSH-030). Past it no call is marked, so every call is resolved as a program, which is always safe; it keeps the
/// call analysis linear, since its state then fits two 64-bit sets. Agent lines define a few functions at most.
pub const MAX_FUNCTION_DEFINITIONS: usize = 64;
