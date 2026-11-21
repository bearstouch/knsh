//! Arithmetic evaluation for `$(( ))`, `(( ))`, `let` and arithmetic `for` (KNSH-097; NFR-COMPAT-02).
//!
//! A port of bash 5.2's `expr.c`, kept close to its structure so that its quirks carry over: one token of
//! look-ahead (`curtok`) and the token before it (`lasttok`), a recursive-descent evaluator with one function per
//! precedence level, and short-circuit operands read in "no evaluation" mode. In particular:
//!
//! - 64-bit signed integers with two's-complement wrap-around on every operation; `INTMAX_MIN / -1` is
//!   `INTMAX_MIN` and `INTMAX_MIN % -1` is 0, as bash special-cases them; shift counts are taken modulo 64, as the
//!   hardware bash runs on does.
//! - Precedence, lowest first: `,`; `= *= /= %= += -= <<= >>= &= ^= |=` (right to left); `?:` (right to left);
//!   `||`; `&&`; `|`; `^`; `&`; `== !=`; `< > <= >=`; `<< >>`; `+ -`; `* / %`; `**` (right to left); unary
//!   `! ~ - +` and prefix `++ --`; operands, postfix `++ --` and parentheses. Unary minus binds tighter than `**`
//!   (`-2**2` is 4), as in bash.
//! - Constants: decimal, `0x` hexadecimal, leading-`0` octal and `base#digits` for bases 2 to 64 (digits `0-9`,
//!   `a-z`, `A-Z`, `@`, `_`; letters of either case are the same digit up to base 36).
//! - A variable named in an expression is read as an expression itself when its value is not a number (`a=b; b=3;
//!   $((a))` is 3); unset or empty is 0. That recursion is bounded by bash's own limit, [`MAX_ARITH_DEPTH`], which
//!   also bounds nesting of parentheses and operators here so a hostile expression cannot exhaust the stack.
//! - An array element (`a[i]`, KNSH-103) is an operand and an lvalue: the subscript, read up to its matching `]`, is
//!   evaluated as an expression for an indexed array (once, when the element is read) and taken as written for an
//!   associative one.
//! - Errors carry bash's message shape: `expression: message (error token is "rest")`, the expression with its
//!   leading blanks removed and the rest from the start of the last token read.

use crate::error::Unsupported;
use crate::state::Key;

/// Deepest nesting of variable values evaluated as expressions, parentheses, unary operators and right-associative
/// chains together. Bash's `MAX_EXPR_RECURSION_LEVEL` for variables; bash leaves parentheses unbounded, and this
/// bounds them too, far above anything written by hand, so evaluation never overflows the stack.
pub const MAX_ARITH_DEPTH: usize = 1024;

/// Why an arithmetic expression could not be evaluated (exported as [`ArithmeticError`](crate::ArithmeticError)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// A bash arithmetic error, formatted as bash prints it after the command name: `1/0: division by 0 (error
    /// token is "0")`.
    Error(String),
    /// `set -u` is on and the variable named was read while unset. Bash treats this as fatal, not as an arithmetic
    /// error.
    Unbound(String),
    /// Something the interpreter does not evaluate yet (an array element, a variable bash computes).
    Unsupported(Unsupported),
    /// The expression assigns this read-only variable (KNSH-101). Bash reports `name: readonly variable` and abandons
    /// the expression, as for an arithmetic error.
    Readonly(String),
}

type Result<T> = std::result::Result<T, Failure>;

/// The shell variables an expression reads and assigns.
pub(crate) trait Variables {
    /// The value of variable `name`, or `None` if it is unset.
    ///
    /// # Errors
    ///
    /// [`Failure::Unbound`] if it is unset under `set -u`; [`Failure::Unsupported`] for a variable the
    /// interpreter does not emulate.
    fn get(&mut self, name: &str) -> Result<Option<String>>;

    /// Sets variable `name` to `value` written in decimal.
    ///
    /// # Errors
    ///
    /// [`Failure::Readonly`] for a read-only variable; [`Failure::Unsupported`] for one bash maintains itself.
    fn set(&mut self, name: &str, value: i64) -> Result<()>;

    /// Whether `name` is an associative array, whose subscripts are keys rather than expressions (KNSH-103).
    fn is_assoc(&mut self, name: &str) -> bool;

    /// Element `key` of array `name`, or `None` if it is unset.
    ///
    /// # Errors
    ///
    /// As [`Variables::get`].
    fn get_element(&mut self, name: &str, key: &Key) -> Result<Option<String>>;

    /// Sets element `key` of array `name` to `value` written in decimal.
    ///
    /// # Errors
    ///
    /// As [`Variables::set`].
    fn set_element(&mut self, name: &str, key: &Key, value: i64) -> Result<()>;
}

/// Evaluates `expression` against the variables of `state`, as `$(( expression ))` does once the expression has
/// been expanded: blank or empty is 0, variables are read and assigned in `state`, and `set -u` applies.
///
/// # Errors
///
/// See [`Failure`]. Never panics, whatever the input: it is fuzzed (`fuzz/fuzz_targets/arith_expr.rs`).
pub fn evaluate_arithmetic(expression: &str, state: &mut crate::ShellState) -> Result<i64> {
    evaluate(expression, &mut StateVariables { state })
}

/// The variables of a shell state, for [`evaluate_arithmetic`].
struct StateVariables<'s> {
    state: &'s mut crate::ShellState,
}

impl Variables for StateVariables<'_> {
    fn get(&mut self, name: &str) -> Result<Option<String>> {
        if self.state.is_unemulated(name) {
            return Err(Failure::Unsupported(Unsupported::ShellVariable));
        }
        match self.state.variable(name) {
            Some(value) => value
                .to_str()
                .map(|value| Some(value.to_owned()))
                .ok_or(Failure::Unsupported(Unsupported::NonUtf8Value)),
            None if self.state.options().nounset => Err(Failure::Unbound(name.to_owned())),
            None => Ok(None),
        }
    }

    fn set(&mut self, name: &str, value: i64) -> Result<()> {
        if crate::state::refuses_assignment(name) {
            return Err(Failure::Unsupported(Unsupported::ShellVariable));
        }
        assigned(name, self.state.assign(name, value.to_string().into(), false))
    }

    fn is_assoc(&mut self, name: &str) -> bool {
        self.state.kind(name) == crate::state::Kind::Assoc
    }

    fn get_element(&mut self, name: &str, key: &Key) -> Result<Option<String>> {
        element_value(self.state, name, key)
    }

    fn set_element(&mut self, name: &str, key: &Key, value: i64) -> Result<()> {
        assigned(
            name,
            self.state.assign_element(name, key, value.to_string().into(), false),
        )
    }
}

/// Element `key` of `name` in `state` for an expression: a bad subscript is bash's message and 0, as bash goes on.
pub(crate) fn element_value(state: &crate::ShellState, name: &str, key: &Key) -> Result<Option<String>> {
    if state.is_unemulated(name) {
        return Err(Failure::Unsupported(Unsupported::ShellVariable));
    }
    match state.element(name, key) {
        Ok(Some(value)) => value
            .into_string()
            .map(Some)
            .map_err(|_| Failure::Unsupported(Unsupported::NonUtf8Value)),
        Ok(None) if state.options().nounset => Err(Failure::Unbound(name.to_owned())),
        Ok(None) => Ok(None),
        Err(crate::state::ElementError::BadSubscript) => {
            state.note(format!("{name}: bad array subscript"));
            Ok(None)
        }
        Err(crate::state::ElementError::Unsupported(feature)) => Err(Failure::Unsupported(feature)),
    }
}

/// An arithmetic assignment's outcome as a [`Failure`].
pub(crate) fn assigned(name: &str, result: std::result::Result<(), crate::state::AssignError>) -> Result<()> {
    use crate::state::AssignError;
    match result {
        Ok(()) => Ok(()),
        Err(AssignError::Readonly) => Err(Failure::Readonly(name.to_owned())),
        Err(AssignError::Arithmetic(failure)) => Err(failure),
        Err(AssignError::Unsupported(feature)) => Err(Failure::Unsupported(feature)),
        // A bad subscript or an array of the other kind: bash's messages there are not reproduced.
        Err(AssignError::BadSubscript | AssignError::Kind) => Err(Failure::Unsupported(Unsupported::Array)),
        // The evaluator only assigns names it read as identifiers.
        Err(AssignError::Invalid) => Err(Failure::Error(format!("{name}: invalid variable name"))),
    }
}

/// Evaluates `expression` as bash's `evalexp` does: blank or empty is 0.
///
/// # Errors
///
/// See [`Failure`].
pub(crate) fn evaluate(expression: &str, variables: &mut dyn Variables) -> Result<i64> {
    let mut depth = 0;
    subexpr(expression, variables, &mut depth)
}

/// Evaluates `text` as a whole expression one level deeper, the way bash evaluates a variable's value.
fn subexpr(text: &str, variables: &mut dyn Variables, depth: &mut usize) -> Result<i64> {
    if text.bytes().all(is_blank) {
        return Ok(0);
    }
    let mut expr = Expr {
        text,
        tp: 0,
        lasttp: 0,
        curtok: Tok::Eof,
        lasttok: Tok::Eof,
        tokstr: None,
        tokval: 0,
        assigntok: Tok::Eof,
        noeval: 0,
        variables,
        depth,
    };
    // One level per expression, counted before its first token is read: reading a variable evaluates its value.
    *expr.depth += 1;
    let result = expr.whole();
    *expr.depth -= 1;
    result
}

/// A token, as bash's `readtok` classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    /// End of the expression (bash's 0).
    Eof,
    /// A number constant.
    Num,
    /// A variable name.
    Str,
    /// Set as `lasttok` after a conditional expression.
    Cond,
    Eq,
    Not,
    Lt,
    Gt,
    BAnd,
    BOr,
    BXor,
    BNot,
    Plus,
    Minus,
    Mul,
    Div,
    Mod,
    Ques,
    Col,
    LPar,
    RPar,
    Comma,
    EqEq,
    Neq,
    Leq,
    Geq,
    Lsh,
    Rsh,
    LAnd,
    LOr,
    Power,
    PreInc,
    PreDec,
    PostInc,
    PostDec,
    /// `op=`, with the operator in `assigntok`.
    OpAssign,
}

impl Tok {
    /// The one-character operator `byte`, if it is one.
    const fn single(byte: u8) -> Option<Self> {
        Some(match byte {
            b'=' => Self::Eq,
            b'!' => Self::Not,
            b'<' => Self::Lt,
            b'>' => Self::Gt,
            b'&' => Self::BAnd,
            b'|' => Self::BOr,
            b'^' => Self::BXor,
            b'~' => Self::BNot,
            b'+' => Self::Plus,
            b'-' => Self::Minus,
            b'*' => Self::Mul,
            b'/' => Self::Div,
            b'%' => Self::Mod,
            b'?' => Self::Ques,
            b':' => Self::Col,
            b'(' => Self::LPar,
            b')' => Self::RPar,
            b',' => Self::Comma,
            _ => return None,
        })
    }

    /// Whether, as the token before a character that is no operator, bash reports "operand expected" rather than
    /// "invalid arithmetic operator": at the start, or after an operator (bash's `_is_arithop` or `_is_multiop`).
    const fn expects_operand(self) -> bool {
        match self {
            Self::Eof
            | Self::Eq
            | Self::Not
            | Self::Lt
            | Self::Gt
            | Self::BAnd
            | Self::BOr
            | Self::BXor
            | Self::BNot
            | Self::Plus
            | Self::Minus
            | Self::Mul
            | Self::Div
            | Self::Mod
            | Self::Ques
            | Self::Col
            | Self::LPar
            | Self::RPar
            | Self::Comma
            | Self::EqEq
            | Self::Neq
            | Self::Leq
            | Self::Geq
            | Self::Lsh
            | Self::Rsh
            | Self::LAnd
            | Self::LOr
            | Self::Power
            | Self::OpAssign
            | Self::Cond => true,
            Self::Num | Self::Str | Self::PreInc | Self::PreDec | Self::PostInc | Self::PostDec => false,
        }
    }
}

/// Bash's `cr_whitespace`: the characters skipped between tokens.
const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// Bash's `whitespace`: what is trimmed from the front of an expression in error messages.
const fn is_blank(byte: u8) -> bool {
    is_space(byte)
}

const fn is_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

const fn is_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// A variable an expression names: `name`, or element `key` of array `name`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Lvalue {
    name: String,
    /// The element, `None` for a plain variable. While not evaluating (`noeval`) a subscript is not evaluated, and
    /// is element 0 here; nothing is read or assigned then.
    key: Option<Key>,
}

/// One expression being read: bash's token state for it.
struct Expr<'t, 'v> {
    /// The expression.
    text: &'t str,
    /// Where the next token starts being read.
    tp: usize,
    /// Where the last token read starts (bash's `lasttp`), for error messages.
    lasttp: usize,
    curtok: Tok,
    lasttok: Tok,
    /// The last variable token read: its name, and the element it names (`a[i]`, KNSH-103).
    tokstr: Option<Lvalue>,
    /// The value of the last number or variable token read.
    tokval: i64,
    /// The operator of the last `op=` read.
    assigntok: Tok,
    /// Greater than zero while reading an operand that is not evaluated (`0 && x`, the branch of `?:` not taken).
    noeval: usize,
    variables: &'v mut dyn Variables,
    /// Nesting so far, shared with the expressions this one is evaluated within.
    depth: &'v mut usize,
}

impl Expr<'_, '_> {
    /// Bash's `evalerror`: the error `message` at the last token read.
    fn error(&self, message: &str) -> Failure {
        let expression = self.text.trim_start_matches([' ', '\t']);
        let token = self.text.get(self.lasttp..).unwrap_or("");
        Failure::Error(format!("{expression}: {message} (error token is \"{token}\")"))
    }

    /// The whole expression: bash's `subexpr` after its set-up.
    fn whole(&mut self) -> Result<i64> {
        self.readtok()?;
        let value = self.expcomma_here()?;
        if self.curtok != Tok::Eof {
            return Err(self.error("syntax error in expression"));
        }
        Ok(value)
    }

    /// Enters one more level of nesting, or fails past [`MAX_ARITH_DEPTH`].
    fn descend(&mut self) -> Result<()> {
        if *self.depth >= MAX_ARITH_DEPTH {
            return Err(self.error("expression recursion level exceeded"));
        }
        *self.depth += 1;
        Ok(())
    }

    fn ascend(&mut self) {
        *self.depth -= 1;
    }

    /// `expr` one level deeper.
    fn nested(&mut self, expr: fn(&mut Self) -> Result<i64>) -> Result<i64> {
        self.descend()?;
        let value = expr(self);
        self.ascend();
        value
    }

    /// The value of variable `name` in an expression: its value read as an expression, 0 if unset or empty, and
    /// nothing read at all while not evaluating.
    fn streval(&mut self, lvalue: &Lvalue) -> Result<i64> {
        if self.noeval > 0 {
            return Ok(0);
        }
        let value = match &lvalue.key {
            None => self.variables.get(&lvalue.name)?,
            Some(key) => self.variables.get_element(&lvalue.name, key)?,
        };
        let Some(value) = value else {
            return Ok(0);
        };
        // Checked here, so the message names this expression, as bash's does; the nested one counts its level in
        // `subexpr`.
        if *self.depth >= MAX_ARITH_DEPTH {
            return Err(self.error("expression recursion level exceeded"));
        }
        subexpr(&value, self.variables, self.depth)
    }

    fn assign(&mut self, lvalue: &Lvalue, value: i64) -> Result<()> {
        if self.noeval == 0 {
            match &lvalue.key {
                None => self.variables.set(&lvalue.name, value)?,
                Some(key) => self.variables.set_element(&lvalue.name, key, value)?,
            }
        }
        Ok(())
    }

    /// The last variable token, which an assignment needs.
    fn lvalue(&self) -> Result<Lvalue> {
        self.tokstr
            .clone()
            .ok_or_else(|| self.error("attempted assignment to non-variable"))
    }

    // ---- Precedence levels, lowest first ----

    /// `a, b`.
    fn expcomma(&mut self) -> Result<i64> {
        self.descend()?;
        let result = self.expcomma_here();
        self.ascend();
        result
    }

    fn expcomma_here(&mut self) -> Result<i64> {
        let mut value = self.expassign()?;
        while self.curtok == Tok::Comma {
            self.readtok()?;
            value = self.expassign()?;
        }
        Ok(value)
    }

    /// `name = value` and `name op= value`, right to left.
    fn expassign(&mut self) -> Result<i64> {
        let mut value = self.expcond()?;
        if matches!(self.curtok, Tok::Eq | Tok::OpAssign) {
            let special = self.curtok == Tok::OpAssign;
            if self.lasttok != Tok::Str {
                return Err(self.error("attempted assignment to non-variable"));
            }
            let op = self.assigntok;
            let lvalue = value;
            let name = self.lvalue()?;
            self.readtok()?;
            value = self.nested(Self::expassign)?;
            if special {
                value = self.binary(op, lvalue, value)?;
            }
            self.assign(&name, value)?;
        }
        Ok(value)
    }

    /// `test ? a : b`, right to left; only the branch taken is evaluated.
    fn expcond(&mut self) -> Result<i64> {
        let condition = self.explor()?;
        if self.curtok != Tok::Ques {
            return Ok(condition);
        }
        let skip_true = condition == 0;
        self.noeval += usize::from(skip_true);
        self.readtok()?;
        if matches!(self.curtok, Tok::Eof | Tok::Col) {
            return Err(self.error("expression expected"));
        }
        let when_true = self.expcomma()?;
        self.noeval -= usize::from(skip_true);
        if self.curtok != Tok::Col {
            return Err(self.error("`:' expected for conditional expression"));
        }
        let skip_false = condition != 0;
        self.noeval += usize::from(skip_false);
        self.readtok()?;
        if self.curtok == Tok::Eof {
            return Err(self.error("expression expected"));
        }
        let when_false = self.nested(Self::expcond)?;
        self.noeval -= usize::from(skip_false);
        self.lasttok = Tok::Cond;
        Ok(if condition == 0 { when_false } else { when_true })
    }

    /// `a || b`: `b` is not evaluated when `a` is true.
    fn explor(&mut self) -> Result<i64> {
        let mut left = self.expland()?;
        while self.curtok == Tok::LOr {
            let skip = left != 0;
            self.noeval += usize::from(skip);
            self.readtok()?;
            let right = self.expland()?;
            self.noeval -= usize::from(skip);
            left = i64::from(left != 0 || right != 0);
            self.lasttok = Tok::LOr;
        }
        Ok(left)
    }

    /// `a && b`: `b` is not evaluated when `a` is false.
    fn expland(&mut self) -> Result<i64> {
        let mut left = self.expbor()?;
        while self.curtok == Tok::LAnd {
            let skip = left == 0;
            self.noeval += usize::from(skip);
            self.readtok()?;
            let right = self.expbor()?;
            self.noeval -= usize::from(skip);
            left = i64::from(left != 0 && right != 0);
            self.lasttok = Tok::LAnd;
        }
        Ok(left)
    }

    /// A left-associative level: operands from `next`, joined by any of `ops`.
    fn left_assoc(&mut self, ops: &[Tok], next: fn(&mut Self) -> Result<i64>) -> Result<i64> {
        let mut left = next(self)?;
        while ops.contains(&self.curtok) {
            let op = self.curtok;
            // Bash 5.2's `expmuldiv` reports division by zero from the start of the divisor (`4/0+1`: error token
            // `0+1`), not from the last token read.
            let divisor_at = self.tp;
            self.readtok()?;
            let right = next(self)?;
            if matches!(op, Tok::Div | Tok::Mod) && right == 0 && self.noeval == 0 {
                let bytes = self.text.as_bytes();
                let mut at = divisor_at;
                while bytes.get(at).copied().is_some_and(is_blank) {
                    at += 1;
                }
                self.lasttp = at;
                return Err(self.error("division by 0"));
            }
            left = self.binary(op, left, right)?;
            self.lasttok = Tok::Num;
        }
        Ok(left)
    }

    fn expbor(&mut self) -> Result<i64> {
        self.left_assoc(&[Tok::BOr], Self::expbxor)
    }

    fn expbxor(&mut self) -> Result<i64> {
        self.left_assoc(&[Tok::BXor], Self::expband)
    }

    fn expband(&mut self) -> Result<i64> {
        self.left_assoc(&[Tok::BAnd], Self::exp5)
    }

    fn exp5(&mut self) -> Result<i64> {
        self.left_assoc(&[Tok::EqEq, Tok::Neq], Self::exp4)
    }

    fn exp4(&mut self) -> Result<i64> {
        self.left_assoc(&[Tok::Lt, Tok::Gt, Tok::Leq, Tok::Geq], Self::expshift)
    }

    fn expshift(&mut self) -> Result<i64> {
        self.left_assoc(&[Tok::Lsh, Tok::Rsh], Self::exp3)
    }

    fn exp3(&mut self) -> Result<i64> {
        self.left_assoc(&[Tok::Plus, Tok::Minus], Self::expmuldiv)
    }

    fn expmuldiv(&mut self) -> Result<i64> {
        self.left_assoc(&[Tok::Mul, Tok::Div, Tok::Mod], Self::exppower)
    }

    /// `a ** b`, right to left. A negative exponent is an error; a zero one makes the whole level 1, as in bash.
    fn exppower(&mut self) -> Result<i64> {
        let mut base = self.exp1()?;
        while self.curtok == Tok::Power {
            self.readtok()?;
            let exponent = self.nested(Self::exppower)?;
            self.lasttok = Tok::Num;
            if exponent == 0 {
                return Ok(1);
            }
            if exponent < 0 {
                return Err(self.error("exponent less than 0"));
            }
            base = ipow(base, exponent);
        }
        Ok(base)
    }

    /// Unary `!`, `~`, `-` and `+`.
    fn exp1(&mut self) -> Result<i64> {
        let op = self.curtok;
        if !matches!(op, Tok::Not | Tok::BNot | Tok::Minus | Tok::Plus) {
            return self.exp0();
        }
        self.readtok()?;
        let operand = self.nested(Self::exp1)?;
        self.lasttok = Tok::Num;
        Ok(match op {
            Tok::Not => i64::from(operand == 0),
            Tok::BNot => !operand,
            Tok::Minus => operand.wrapping_neg(),
            _ => operand,
        })
    }

    /// An operand: prefix `++`/`--`, a parenthesised expression, a number, or a variable with optional postfix
    /// `++`/`--`.
    fn exp0(&mut self) -> Result<i64> {
        match self.curtok {
            Tok::PreInc | Tok::PreDec => {
                let op = self.curtok;
                self.lasttok = op;
                self.readtok()?;
                if self.curtok != Tok::Str {
                    return Err(self.error("identifier expected after pre-increment or pre-decrement"));
                }
                let value = self.tokval.wrapping_add(if op == Tok::PreInc { 1 } else { -1 });
                let name = self.lvalue()?;
                self.assign(&name, value)?;
                // So that `--x=7` is an error, as in bash.
                self.curtok = Tok::Num;
                self.readtok()?;
                Ok(value)
            }
            Tok::LPar => {
                self.readtok()?;
                let value = self.expcomma()?;
                if self.curtok != Tok::RPar {
                    return Err(self.error("missing `)'"));
                }
                self.readtok()?;
                Ok(value)
            }
            Tok::Num => {
                let value = self.tokval;
                self.readtok()?;
                Ok(value)
            }
            Tok::Str => {
                let value = self.tokval;
                // Peek at the next token for a postfix `++` or `--`, without evaluating anything it names.
                let saved = (
                    self.tp,
                    self.lasttp,
                    self.curtok,
                    self.lasttok,
                    self.tokstr.clone(),
                    self.tokval,
                );
                self.noeval += 1;
                let peeked = self.readtok();
                self.noeval -= 1;
                peeked?;
                let next = self.curtok;
                if matches!(next, Tok::PostInc | Tok::PostDec) {
                    self.tokstr = saved.4;
                    self.lasttok = Tok::Str;
                    let name = self.lvalue()?;
                    let updated = value.wrapping_add(if next == Tok::PostInc { 1 } else { -1 });
                    self.assign(&name, updated)?;
                    // So that `x++=7` is an error, as in bash.
                    self.curtok = Tok::Num;
                } else {
                    (
                        self.tp,
                        self.lasttp,
                        self.curtok,
                        self.lasttok,
                        self.tokstr,
                        self.tokval,
                    ) = saved;
                }
                self.readtok()?;
                Ok(value)
            }
            _ => Err(self.error("syntax error: operand expected")),
        }
    }

    /// `left op right` for a binary or compound-assignment operator, wrapping like bash. Division by zero is an
    /// error, except while not evaluating, where bash divides by 1 instead.
    fn binary(&self, op: Tok, left: i64, right: i64) -> Result<i64> {
        let divisor = |right: i64| {
            if right != 0 {
                Ok(right)
            } else if self.noeval > 0 {
                Ok(1)
            } else {
                Err(self.error("division by 0"))
            }
        };
        Ok(match op {
            Tok::BOr => left | right,
            Tok::BXor => left ^ right,
            Tok::BAnd => left & right,
            Tok::EqEq => i64::from(left == right),
            Tok::Neq => i64::from(left != right),
            Tok::Lt => i64::from(left < right),
            Tok::Gt => i64::from(left > right),
            Tok::Leq => i64::from(left <= right),
            Tok::Geq => i64::from(left >= right),
            // The count is taken modulo 64, as the shift instructions of the machines bash runs on do.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Tok::Lsh => left.wrapping_shl(right as u32),
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Tok::Rsh => left.wrapping_shr(right as u32),
            Tok::Plus => left.wrapping_add(right),
            Tok::Minus => left.wrapping_sub(right),
            Tok::Mul => left.wrapping_mul(right),
            // `wrapping_div` and `wrapping_rem` give bash's results for `INTMAX_MIN` and -1.
            Tok::Div => left.wrapping_div(divisor(right)?),
            Tok::Mod => left.wrapping_rem(divisor(right)?),
            _ => return Err(self.error("bug: bad expassign token")),
        })
    }

    // ---- Tokens ----

    /// Reads the next token into `curtok` (and its value into `tokval` and `tokstr`), moving the old one to
    /// `lasttok`. A variable is evaluated as it is read unless a plain `=` follows it, as in bash.
    fn readtok(&mut self) -> Result<()> {
        let bytes = self.text.as_bytes();
        let mut cp = self.tp;
        while bytes.get(cp).copied().is_some_and(is_space) {
            cp += 1;
        }
        let Some(&c) = bytes.get(cp) else {
            self.lasttok = self.curtok;
            self.curtok = Tok::Eof;
            self.tp = cp;
            return Ok(());
        };
        let start = cp;
        self.lasttp = start;
        cp += 1;
        if is_name_start(c) {
            return self.read_name(start);
        }
        if c.is_ascii_digit() {
            while bytes
                .get(cp)
                .is_some_and(|&b| b.is_ascii_alphanumeric() || matches!(b, b'#' | b'@' | b'_'))
            {
                cp += 1;
            }
            self.tokval = self.strlong(self.text.get(start..cp).unwrap_or_default())?;
            self.lasttok = self.curtok;
            self.curtok = Tok::Num;
            self.tp = cp;
            return Ok(());
        }
        let c1 = bytes.get(cp).copied().unwrap_or(0);
        cp += 1;
        let token = match (c, c1) {
            (b'=', b'=') => Tok::EqEq,
            (b'!', b'=') => Tok::Neq,
            (b'>', b'=') => Tok::Geq,
            (b'<', b'=') => Tok::Leq,
            (b'<', b'<') | (b'>', b'>') => {
                let shift = if c == b'<' { Tok::Lsh } else { Tok::Rsh };
                if bytes.get(cp) == Some(&b'=') {
                    cp += 1;
                    self.assigntok = shift;
                    Tok::OpAssign
                } else {
                    shift
                }
            }
            (b'&', b'&') => Tok::LAnd,
            (b'|', b'|') => Tok::LOr,
            (b'*', b'*') => Tok::Power,
            (b'-' | b'+', _) if c1 == c && self.curtok == Tok::Str => {
                if c == b'-' {
                    Tok::PostDec
                } else {
                    Tok::PostInc
                }
            }
            (b'-' | b'+', _)
                if c1 == c && self.curtok == Tok::Num && matches!(self.lasttok, Tok::PreInc | Tok::PreDec) =>
            {
                // `--x++`.
                return Err(self.error(if c == b'-' {
                    "--: assignment requires lvalue"
                } else {
                    "++: assignment requires lvalue"
                }));
            }
            (b'-' | b'+', _) if c1 == c => {
                // A prefix operator only if a name follows, possibly after blanks; otherwise two signs.
                let mut ahead = cp;
                while bytes.get(ahead).copied().is_some_and(is_space) {
                    ahead += 1;
                }
                if bytes.get(ahead).copied().is_some_and(is_name_start) {
                    if c == b'-' { Tok::PreDec } else { Tok::PreInc }
                } else {
                    cp -= 1;
                    if c == b'-' { Tok::Minus } else { Tok::Plus }
                }
            }
            (b'*' | b'/' | b'%' | b'+' | b'-' | b'&' | b'^' | b'|', b'=') => {
                self.assigntok = Tok::single(c).unwrap_or(Tok::Eof);
                Tok::OpAssign
            }
            _ => {
                cp -= 1;
                match Tok::single(c) {
                    Some(token) => token,
                    None if self.curtok.expects_operand() => {
                        return Err(self.error("syntax error: operand expected"));
                    }
                    None => return Err(self.error("syntax error: invalid arithmetic operator")),
                }
            }
        };
        self.lasttok = self.curtok;
        self.curtok = token;
        self.tp = cp;
        Ok(())
    }

    /// Reads the variable name starting at `start`, with its subscript if one follows (`a[i]`), as a [`Tok::Str`]
    /// token.
    fn read_name(&mut self, start: usize) -> Result<()> {
        let bytes = self.text.as_bytes();
        let mut cp = start + 1;
        while bytes.get(cp).copied().is_some_and(is_name_char) {
            cp += 1;
        }
        let name = self.text.get(start..cp).unwrap_or_default().to_owned();
        let mut subscript = None;
        if bytes.get(cp) == Some(&b'[') {
            let inner = self.text.get(cp + 1..).unwrap_or_default();
            let Some(close) = crate::scan::subscript_end(inner).filter(|close| *close > 0) else {
                self.lasttp = cp;
                return Err(self.error("bad array subscript"));
            };
            subscript = Some(inner[..close].to_owned());
            cp += close + 2;
        }
        let mut peek = cp;
        while bytes.get(peek).copied().is_some_and(is_space) {
            peek += 1;
        }
        let assigned = bytes.get(peek) == Some(&b'=') && bytes.get(peek + 1) != Some(&b'=');
        self.tp = cp;
        let key = match subscript {
            None => None,
            Some(_) if self.noeval > 0 => Some(Key::Index(0)),
            Some(text) if self.variables.is_assoc(&name) => Some(Key::Name(text)),
            Some(text) => {
                // Bash evaluates an indexed subscript as an expression of its own, once.
                if *self.depth >= MAX_ARITH_DEPTH {
                    return Err(self.error("expression recursion level exceeded"));
                }
                Some(Key::Index(subexpr(&text, self.variables, self.depth)?))
            }
        };
        let lvalue = Lvalue { name, key };
        self.tokval = if matches!(self.lasttok, Tok::PreInc | Tok::PreDec) || !assigned {
            self.streval(&lvalue)?
        } else {
            0
        };
        self.tokstr = Some(lvalue);
        self.lasttok = self.curtok;
        self.curtok = Tok::Str;
        Ok(())
    }

    /// Bash's `strlong`: a number constant in base 10, `0x` hexadecimal, `0` octal or `base#digits`.
    fn strlong(&self, number: &str) -> Result<i64> {
        let bytes = number.as_bytes();
        let mut i = 0;
        let mut base: i64 = 10;
        let mut found_base = false;
        if bytes.first() == Some(&b'0') {
            i = 1;
            if bytes.len() == 1 {
                return Ok(0);
            }
            if matches!(bytes.get(1), Some(b'x' | b'X')) {
                base = 16;
                i = 2;
            } else {
                base = 8;
            }
            found_base = true;
        }
        let mut value: i64 = 0;
        while let Some(&c) = bytes.get(i) {
            i += 1;
            if c == b'#' {
                if found_base {
                    return Err(self.error("invalid number"));
                }
                if !(2..=64).contains(&value) {
                    return Err(self.error("invalid arithmetic base"));
                }
                base = value;
                value = 0;
                found_base = true;
                // Bash's `VALID_NUMCHAR`: only whether a digit character follows; one too great for the base is
                // reported as such by the loop (`2#2`).
                if bytes.get(i).is_none_or(|&next| digit_value(next, base).is_none()) {
                    return Err(self.error("invalid integer constant"));
                }
                continue;
            }
            let Some(digit) = digit_value(c, base) else {
                break;
            };
            if digit >= base {
                return Err(self.error("value too great for base"));
            }
            value = value.wrapping_mul(base).wrapping_add(digit);
        }
        Ok(value)
    }
}

/// The value of digit `c` in `base`: `0-9`, then `a-z`, then `A-Z` (the same as `a-z` up to base 36), `@` and `_`.
fn digit_value(c: u8, base: i64) -> Option<i64> {
    Some(i64::from(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'z' => c - b'a' + 10,
        b'A'..=b'Z' if base <= 36 => c - b'A' + 10,
        b'A'..=b'Z' => c - b'A' + 36,
        b'@' => 62,
        b'_' => 63,
        _ => return None,
    }))
}

/// `base ** exponent` by squaring, wrapping, for `exponent > 0`.
fn ipow(mut base: i64, mut exponent: i64) -> i64 {
    let mut result: i64 = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result.wrapping_mul(base);
        }
        exponent >>= 1;
        base = base.wrapping_mul(base);
    }
    result
}

#[cfg(test)]
mod tests;
