//! The properties of the `arith_expr` fuzz target (KNSH-097, `specs/07-testing/fuzzing.md`, NFR-SEC-05).
//!
//! Also compiled on stable by `crates/knsh-interp/tests/fuzz_regressions.rs`, which includes this file by path, so it
//! depends on nothing but `knsh-interp` and `std`. A failed property panics, which libFuzzer records as a crash.

use knsh_interp::{ArithmeticError, EVAL_STACK_SIZE, ShellState, evaluate_arithmetic};

/// A shell state with variables that exercise reading, recursion (`a` → `b`, `r` → `r`) and bad values.
fn state() -> ShellState {
    let mut state = ShellState::new("knsh", "/").expect("absolute directory");
    for (name, value) in [("a", "b"), ("b", "3"), ("x", "5"), ("s", "1+"), ("r", "r"), ("e", "")] {
        state.set_variable(name, value);
    }
    state
}

/// The result of an evaluation and the variables afterwards.
type Outcome = (Result<i64, ArithmeticError>, Vec<(String, Option<String>)>);

/// Evaluates `expression` against a fresh [`state`]: the result and the variables afterwards.
fn evaluate(expression: &str) -> Outcome {
    let mut state = state();
    let result = evaluate_arithmetic(expression, &mut state);
    let names = ["a", "b", "x", "s", "r", "e", "i", "y"];
    let variables = names
        .iter()
        .map(|name| {
            let value = state.variable(name).map(|value| value.to_string_lossy().into_owned());
            ((*name).to_owned(), value)
        })
        .collect();
    (result, variables)
}

/// `arith_expr`: evaluating any expression never panics and never overflows the stack (the nesting limit holds), is
/// deterministic, and every error message has bash's shape `expression: message (error token is "…")`.
pub fn arith_expr(data: &[u8]) {
    let input = String::from_utf8_lossy(data).into_owned();
    // On a thread with the interpreter's evaluation stack, as the interpreter evaluates.
    let (first, second) = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(EVAL_STACK_SIZE)
            .spawn_scoped(scope, || (evaluate(&input), evaluate(&input)))
            .expect("evaluation thread")
            .join()
            .expect("evaluation panicked")
    });
    assert_eq!(first, second, "evaluation is not deterministic");
    if let Err(ArithmeticError::Error(message)) = &first.0 {
        assert!(message.ends_with("\")"), "message shape: {message:?}");
        assert!(message.contains(" (error token is \""), "message shape: {message:?}");
    }
}
