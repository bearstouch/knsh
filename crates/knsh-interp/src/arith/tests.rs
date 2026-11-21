//! Arithmetic evaluation against bash's results (KNSH-097). Expected values were checked against bash 3.2 where it
//! agrees with 5.2's `expr.c`; error tokens follow 5.2, which differs from 3.2 after trailing blanks.

use std::collections::BTreeMap;

use super::*;
use crate::state::Key;

/// Variables in a map; `set -u` when `nounset`.
#[derive(Default)]
struct Vars {
    values: BTreeMap<String, String>,
    nounset: bool,
    reads: usize,
}

impl Vars {
    fn with(pairs: &[(&str, &str)]) -> Self {
        Self {
            values: pairs.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect(),
            ..Self::default()
        }
    }
}

impl Variables for Vars {
    fn get(&mut self, name: &str) -> Result<Option<String>> {
        self.reads += 1;
        match self.values.get(name) {
            Some(value) => Ok(Some(value.clone())),
            None if self.nounset => Err(Failure::Unbound(name.to_owned())),
            None => Ok(None),
        }
    }

    fn set(&mut self, name: &str, value: i64) -> Result<()> {
        self.values.insert(name.to_owned(), value.to_string());
        Ok(())
    }

    fn is_assoc(&mut self, name: &str) -> bool {
        name.starts_with('h')
    }

    fn get_element(&mut self, name: &str, key: &Key) -> Result<Option<String>> {
        self.reads += 1;
        Ok(self.values.get(&element_name(name, key)).cloned())
    }

    fn set_element(&mut self, name: &str, key: &Key, value: i64) -> Result<()> {
        self.values.insert(element_name(name, key), value.to_string());
        Ok(())
    }
}

/// How the test variables hold an element: `name[key]`.
fn element_name(name: &str, key: &Key) -> String {
    match key {
        Key::Index(index) => format!("{name}[{index}]"),
        Key::Name(key) => format!("{name}[{key}]"),
    }
}

// KNSH-103: array elements are operands and lvalues; an indexed subscript is an expression evaluated once, an
// associative one a key.
#[test]
fn array_elements_read_and_assign() {
    let mut vars = Vars::default();
    vars.values.insert("a[2]".into(), "5".into());
    vars.values.insert("i".into(), "1".into());
    assert_eq!(evaluate("a[i+1] * 2", &mut vars), Ok(10));
    assert_eq!(evaluate("a[i++]=7, i", &mut vars), Ok(2));
    assert_eq!(vars.values.get("a[1]").map(String::as_str), Some("7"));
    assert_eq!(evaluate("a[2]++ + a[2]", &mut vars), Ok(11));
    assert_eq!(evaluate("h[x y] += 3", &mut vars), Ok(3));
    assert_eq!(vars.values.get("h[x y]").map(String::as_str), Some("3"));
    assert_eq!(evaluate("0 && a[i++]", &mut vars), Ok(0));
    assert_eq!(vars.values.get("i").map(String::as_str), Some("2"));
    assert!(
        matches!(evaluate("a[1", &mut vars), Err(Failure::Error(message)) if message.contains("bad array subscript"))
    );
}

fn eval(expression: &str) -> i64 {
    evaluate(expression, &mut Vars::default()).unwrap_or_else(|e| panic!("{expression}: {e:?}"))
}

fn error(expression: &str) -> String {
    match evaluate(expression, &mut Vars::default()) {
        Err(Failure::Error(message)) => message,
        other => panic!("{expression}: {other:?}"),
    }
}

// NFR-COMPAT-02: every level of bash's precedence table, each against its neighbours.
#[test]
fn precedence_matches_bash_table() {
    for (expression, value) in [
        ("1 + 2 * 3", 7),
        ("(1 + 2) * 3", 9),
        ("10 - 4 - 3", 3),
        ("2 * 3 % 4", 2),
        ("1 << 2 + 1", 8),
        ("1 < 2 == 1", 1),
        ("3 > 2 > 1", 0),
        ("1 == 1 & 2", 0),
        ("6 & 3 ^ 1", 3),
        ("1 ^ 3 | 4", 6),
        ("1 | 2 && 0", 0),
        ("0 && 1 || 1", 1),
        ("1 || 0 ? 7 : 8", 7),
        ("0 ? 1 : 0 ? 2 : 3", 3),
        ("-2 ** 2", 4),
        ("!0 + 1", 2),
        ("~0 * 2", -2),
        ("- -1", 1),
        ("--1", 1),
        ("1 - -1", 2),
        ("+3", 3),
        ("2 ** 3 * 2", 16),
        ("1, 2, 3", 3),
        ("5 >= 5", 1),
        ("4 <= 3", 0),
        ("7 != 7", 0),
        ("-8 >> 1", -4),
        ("", 0),
        ("   ", 0),
        ("\t1 +\n 2 ", 3),
    ] {
        assert_eq!(eval(expression), value, "{expression}");
    }
}

#[test]
fn assignments_are_right_associative_and_return_their_value() {
    let mut vars = Vars::default();
    assert_eq!(evaluate("a = b = 3", &mut vars), Ok(3));
    assert_eq!(vars.values["a"], "3");
    assert_eq!(vars.values["b"], "3");
    assert_eq!(evaluate("x = 4, x * 2", &mut vars), Ok(8));
    for (expression, value, after) in [
        ("x += 2", 6, "6"),
        ("x -= 1", 5, "5"),
        ("x *= 3", 15, "15"),
        ("x /= 2", 7, "7"),
        ("x %= 4", 3, "3"),
        ("x <<= 2", 12, "12"),
        ("x >>= 1", 6, "6"),
        ("x &= 3", 2, "2"),
        ("x |= 5", 7, "7"),
        ("x ^= 1", 6, "6"),
    ] {
        assert_eq!(evaluate(expression, &mut vars), Ok(value), "{expression}");
        assert_eq!(vars.values["x"], after, "{expression}");
    }
}

#[test]
fn increments_and_decrements_like_bash() {
    let mut vars = Vars::with(&[("x", "5")]);
    assert_eq!(evaluate("x++ + ++x", &mut vars), Ok(12));
    assert_eq!(vars.values["x"], "7");
    assert_eq!(evaluate("--x", &mut vars), Ok(6));
    assert_eq!(evaluate("x--", &mut vars), Ok(6));
    assert_eq!(vars.values["x"], "5");
    assert_eq!(evaluate("-- x", &mut vars), Ok(4));
    // Prefix and postfix need a name; otherwise `++` is two signs.
    assert_eq!(evaluate("1++2", &mut vars), Ok(3));
    assert_eq!(evaluate("++1", &mut vars), Ok(1));
}

#[test]
fn exponent_is_right_associative() {
    assert_eq!(eval("2 ** 3 ** 2"), 512);
    assert_eq!(eval("(2 ** 3) ** 2"), 64);
    assert_eq!(eval("0 ** 0"), 1);
    assert_eq!(eval("3 ** 0"), 1);
    assert_eq!(error("2 ** -1"), "2 ** -1: exponent less than 0 (error token is \"1\")");
}

#[test]
fn integer_overflow_wraps() {
    assert_eq!(eval("9223372036854775807 + 1"), i64::MIN);
    assert_eq!(eval("2 ** 63"), i64::MIN);
    assert_eq!(eval("2 ** 64"), 0);
    assert_eq!(eval("-9223372036854775807 - 1"), i64::MIN);
    assert_eq!(eval("(-9223372036854775807 - 1) / -1"), i64::MIN);
    assert_eq!(eval("(-9223372036854775807 - 1) % -1"), 0);
    assert_eq!(eval("- (-9223372036854775807 - 1)"), i64::MIN);
    assert_eq!(eval("99999999999999999999"), 7_766_279_631_452_241_919);
    // Shift counts are taken modulo 64.
    assert_eq!(eval("1 << 64"), 1);
    assert_eq!(eval("1 << 63"), i64::MIN);
    assert_eq!(eval("7 / -2"), -3);
    assert_eq!(eval("-7 % 3"), -1);
}

#[test]
fn base_notation_parses_n_hash_digits() {
    for (expression, value) in [
        ("0x1f", 31),
        ("0X1F", 31),
        ("010", 8),
        ("0", 0),
        ("0x", 0),
        ("2#101", 5),
        ("8#17", 15),
        ("16#ff", 255),
        ("16#FF", 255),
        ("36#z", 35),
        ("36#Z", 35),
        ("62#Z", 61),
        ("64#@_", 62 * 64 + 63),
        ("64#a", 10),
        ("64#A", 36),
    ] {
        assert_eq!(eval(expression), value, "{expression}");
    }
    assert_eq!(error("08"), "08: value too great for base (error token is \"08\")");
    assert_eq!(error("3a"), "3a: value too great for base (error token is \"3a\")");
    // Checked against bash 3.2, whose `strlong` loop reports it the same way as 5.2's.
    assert_eq!(error("2#2"), "2#2: value too great for base (error token is \"2#2\")");
    assert_eq!(error("2#"), "2#: invalid integer constant (error token is \"2#\")");
    assert_eq!(error("65#1"), "65#1: invalid arithmetic base (error token is \"65#1\")");
    assert_eq!(error("1#1"), "1#1: invalid arithmetic base (error token is \"1#1\")");
    assert_eq!(error("0x1#1"), "0x1#1: invalid number (error token is \"0x1#1\")");
}

// The command is not aborted by a panic: the error comes back with bash's message.
#[test]
fn division_by_zero_is_error_not_panic() {
    assert_eq!(error("1/0"), "1/0: division by 0 (error token is \"0\")");
    assert_eq!(error("1 % 0"), "1 % 0: division by 0 (error token is \"0\")");
    // Bash 5.2 names the divisor and what follows it (3.2 named only the token after it).
    assert_eq!(error("4/0+1"), "4/0+1: division by 0 (error token is \"0+1\")");
    assert_eq!(
        error("4 / (0) * 2"),
        "4 / (0) * 2: division by 0 (error token is \"(0) * 2\")"
    );
    // Bash 5.2's token: the last token read, with what follows it.
    assert_eq!(error(" 1/0 "), "1/0 : division by 0 (error token is \"0 \")");
    let mut vars = Vars::with(&[("x", "1")]);
    assert_eq!(
        evaluate("x /= 0", &mut vars),
        Err(Failure::Error(
            "x /= 0: division by 0 (error token is \"0\")".to_owned()
        ))
    );
    assert_eq!(vars.values["x"], "1");
    // Not evaluated: no error, as in bash.
    assert_eq!(eval("0 && 1/0"), 0);
    assert_eq!(eval("1 || 1/0"), 1);
    assert_eq!(eval("1 ? 2 : 1/0"), 2);
}

#[test]
fn syntax_errors_carry_bash_messages() {
    for (expression, message) in [
        ("1 2", "1 2: syntax error in expression (error token is \"2\")"),
        ("1 + ", "1 + : syntax error: operand expected (error token is \"+ \")"),
        (
            "1 = 2",
            "1 = 2: attempted assignment to non-variable (error token is \"= 2\")",
        ),
        (
            "1.5",
            "1.5: syntax error: invalid arithmetic operator (error token is \".5\")",
        ),
        ("(1", "(1: missing `)' (error token is \"1\")"),
        (
            "1 ? 2",
            "1 ? 2: `:' expected for conditional expression (error token is \"2\")",
        ),
        ("1 ? : 2", "1 ? : 2: expression expected (error token is \": 2\")"),
        ("$x", "$x: syntax error: operand expected (error token is \"$x\")"),
        (
            "a + b = 3",
            "a + b = 3: attempted assignment to non-variable (error token is \"= 3\")",
        ),
    ] {
        assert_eq!(error(expression), message, "{expression}");
    }
}

#[test]
fn variables_are_evaluated_as_expressions() {
    let mut vars = Vars::with(&[("a", "b"), ("b", "3"), ("e", ""), ("s", " 2 + 2 "), ("bad", "3a")]);
    assert_eq!(evaluate("a", &mut vars), Ok(3));
    assert_eq!(evaluate("e + unset", &mut vars), Ok(0));
    assert_eq!(evaluate("s * 2", &mut vars), Ok(8));
    // The error names the variable's value, where it went wrong.
    assert_eq!(
        evaluate("bad + 1", &mut vars),
        Err(Failure::Error(
            "3a: value too great for base (error token is \"3a\")".to_owned()
        ))
    );
}

// A plain `=` does not read the variable it assigns: no unbound error under `set -u`. Compound assignments do.
#[test]
fn nounset_applies_to_variables_read() {
    let mut vars = Vars {
        nounset: true,
        ..Vars::default()
    };
    assert_eq!(evaluate("x = 1", &mut vars), Ok(1));
    assert_eq!(evaluate("y + 1", &mut vars), Err(Failure::Unbound("y".to_owned())));
    assert_eq!(evaluate("z += 1", &mut vars), Err(Failure::Unbound("z".to_owned())));
    assert_eq!(evaluate("0 && w", &mut vars), Ok(0));
}

#[test]
fn unevaluated_operands_neither_read_nor_assign() {
    let mut vars = Vars::with(&[("x", "1")]);
    assert_eq!(evaluate("0 && (x = 5)", &mut vars), Ok(0));
    assert_eq!(evaluate("1 || x++", &mut vars), Ok(1));
    assert_eq!(evaluate("1 ? 2 : (x = 9)", &mut vars), Ok(2));
    assert_eq!(vars.values["x"], "1");
    assert_eq!(vars.reads, 0);
}

/// Runs `f` on a thread with the interpreter's evaluation stack, as the interpreter does.
fn on_eval_stack<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(crate::EVAL_STACK_SIZE)
            .spawn_scoped(scope, f)
            .unwrap()
            .join()
            .unwrap()
    })
}

// Bash: `a=b; b=a; $((a))` fails with "expression recursion level exceeded" instead of looping.
#[test]
fn recursive_variable_reference_is_bounded() {
    on_eval_stack(|| {
        let mut vars = Vars::with(&[("a", "b"), ("b", "a")]);
        assert_eq!(
            evaluate("a", &mut vars),
            Err(Failure::Error(
                "b: expression recursion level exceeded (error token is \"b\")".to_owned()
            ))
        );
        let mut vars = Vars::with(&[("a", "a + 1")]);
        assert!(matches!(evaluate("a", &mut vars), Err(Failure::Error(m)) if m.contains("recursion level")));
    });
}

// CLAUDE.md "Untrusted input": nesting is bounded, so a hostile expression is an error, not a stack overflow.
#[test]
fn deep_nesting_is_an_error_not_a_crash() {
    on_eval_stack(|| {
        let deep = |open: &str, close: &str| format!("{}1{}", open.repeat(5000), close.repeat(5000));
        for expression in [
            deep("(", ")"),
            deep("-", ""),
            deep("!", ""),
            deep("1?", ":1"),
            deep("2**", ""),
            deep("a=", ""),
        ] {
            assert!(
                matches!(evaluate(&expression, &mut Vars::default()), Err(Failure::Error(m)) if m.contains("recursion level")),
                "{}",
                &expression[..20]
            );
        }
        let shallow = format!("{}1{}", "(".repeat(500), ")".repeat(500));
        assert_eq!(evaluate(&shallow, &mut Vars::default()), Ok(1));
    });
}
