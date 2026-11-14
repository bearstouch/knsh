//! Hard limits on what the lexer reads (NFR-SEC-05; CLAUDE.md "Untrusted input": check sizes before allocating and
//! bound recursion).
//!
//! The values are proposed here and listed in `specs/09-reference/defaults-and-limits.md`; KNSH-032 owns the final
//! set of parser limits (adding token count and parser nesting) and the dynamic fallback when one is exceeded.

/// Longest command line [`lex`](crate::lex) reads, in bytes, checked before tokenising. 1 MiB is macOS's
/// `ARG_MAX`, so a line handed to `bash -c` can never be longer, and it equals the 1 MB frame payload limit a line
/// arrives in over `agent.sock`.
pub const MAX_INPUT_LEN: usize = 1024 * 1024;

/// Deepest nesting of quotes and substitutions (`"$(a "$(b)")"` is four levels), which bounds the lexer's
/// recursion. Real agent lines nest a few levels; 32 matches the JSON and TOML nesting limits.
pub const MAX_NESTING_DEPTH: usize = 32;

/// Most function definitions with matchable names a line may hold for calls to be marked as function calls
/// (KNSH-030). Past it no call is marked, so every call is resolved as a program, which is always safe; it keeps the
/// call analysis linear, since its state then fits two 64-bit sets. Agent lines define a few functions at most.
pub const MAX_FUNCTION_DEFINITIONS: usize = 64;
