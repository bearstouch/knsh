//! `test` and `[` (KNSH-102; NFR-COMPAT-02), and the unary and binary tests `[[ … ]]` shares with them.
//!
//! Follows bash 5.2's `test.c`: with up to four arguments the POSIX rules decide by count (`posixtest`: one argument
//! is true when not empty; two are `! word` or a unary operator; three are a binary operator, `-a`/`-o` between two
//! words, `! two-argument-test` or `( word )`; four are `! three-argument-test` or `( two-argument-test )`), and
//! anything else is parsed as an expression (`!`, `(` `)`, `-a` binding tighter than `-o`). A syntax error is bash's
//! message (`[: b: binary operator expected`) and status 2; `[` without a last `]` is `` [: missing `]' ``.
//!
//! File tests stat the path as bash's `sh_stat` does, relative names from the shell's working directory, through
//! [`knsh_platform::Fs`]. `/dev/stdin`, `/dev/stdout`, `/dev/stderr` and `/dev/fd/N` name the shell's own
//! descriptors (bash's `sh_stat` uses `fstat` on them), which the interpreter's descriptor table holds; `-t N` asks
//! whether the shell's descriptor `N` is a terminal. A standard descriptor the host did not give
//! ([`Interpreter::with_standard_descriptors`](crate::Interpreter::with_standard_descriptors)) is refused
//! ([`Unsupported::StandardDescriptor`]) rather than guessed.

use std::path::{Path, PathBuf};

use knsh_bash::Span;
use knsh_platform::{Access, ChildDescriptor, FileStatus, FileType, StandardStream};

use super::control::legal_number;
use super::{Flow, Interpreter, Run, Stop, unsupported};
use crate::error::Unsupported;
use crate::state::is_name;
use crate::status::Status;

/// Why a test expression stopped before giving an answer.
pub(super) enum Abort {
    /// Bash's syntax error (without the `[: ` prefix): status 2.
    Syntax(String),
    /// Evaluation stopped (a refusal).
    Stop(Stop),
}

impl From<Stop> for Abort {
    fn from(stop: Stop) -> Self {
        Self::Stop(stop)
    }
}

/// Whether `op` is one of bash's unary test operators (`test_unop`).
pub(crate) fn is_unary_operator(op: &str) -> bool {
    let bytes = op.as_bytes();
    bytes.len() == 2
        && bytes[0] == b'-'
        && matches!(
            bytes[1],
            b'a' | b'b'
                | b'c'
                | b'd'
                | b'e'
                | b'f'
                | b'g'
                | b'h'
                | b'k'
                | b'n'
                | b'o'
                | b'p'
                | b'r'
                | b's'
                | b't'
                | b'u'
                | b'v'
                | b'w'
                | b'x'
                | b'z'
                | b'G'
                | b'L'
                | b'O'
                | b'S'
                | b'N'
                | b'R'
        )
}

/// Whether `op` is one of bash's binary test operators (`test_binop`): `= == != < >` and the `-xx` ones. `=~` is
/// `[[`'s alone.
pub(crate) fn is_binary_operator(op: &str) -> bool {
    matches!(
        op,
        "=" | "==" | "!=" | "<" | ">" | "-nt" | "-ot" | "-ef" | "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge"
    )
}

/// Whether `op` compares integers.
pub(super) fn is_arithmetic_operator(op: &str) -> bool {
    matches!(op, "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge")
}

/// `l op r` for an integer operator.
pub(super) fn compare_integers(op: &str, left: i64, right: i64) -> bool {
    match op {
        "-eq" => left == right,
        "-ne" => left != right,
        "-lt" => left < right,
        "-le" => left <= right,
        "-gt" => left > right,
        _ => left >= right,
    }
}

/// The shell descriptor bash's special file name `path` stands for (`/dev/stdin`, `/dev/stdout`, `/dev/stderr`,
/// `/dev/fd/N`), as `sh_stat` reads them.
fn descriptor_name(path: &str) -> Option<u32> {
    match path {
        "/dev/stdin" => Some(0),
        "/dev/stdout" => Some(1),
        "/dev/stderr" => Some(2),
        _ => {
            let number = legal_number(path.strip_prefix("/dev/fd/")?)?;
            u32::try_from(number).ok()
        }
    }
}

/// The permission bits of `status` that apply to this process (owner, group or other), for `-r`, `-w`, `-x` on a
/// descriptor name (bash's `sh_stataccess`).
fn permitted(status: &FileStatus, access: Access) -> bool {
    let shift = if status.owned_by_effective_user {
        6
    } else if status.owned_by_effective_group {
        3
    } else {
        0
    };
    let bit = match access {
        Access::Read => 0o4,
        Access::Write => 0o2,
        Access::Execute => 0o1,
    };
    (status.mode >> shift) & bit != 0
}

impl Interpreter {
    /// `test` and `[` (`name`) with `args`.
    pub(super) fn test_builtin(&mut self, name: &str, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let args = if name == "[" {
            match args.split_last() {
                Some((last, rest)) if last == "]" => rest,
                _ => {
                    self.report(span, run, format_args!("[: missing `]'"));
                    return Ok(Status::new(2));
                }
            }
        } else {
            args
        };
        let mut parser = TestParser {
            shell: self,
            run,
            args,
            pos: 0,
            span,
            depth: 0,
        };
        match parser.posix() {
            Ok(true) => Ok(Status::SUCCESS),
            Ok(false) => Ok(Status::FAILURE),
            Err(Abort::Syntax(message)) => {
                self.report(span, run, format_args!("{name}: {message}"));
                Ok(Status::new(2))
            }
            Err(Abort::Stop(stop)) => Err(stop),
        }
    }

    /// Bash's `unary_test`: unary operator `op` (validated by [`is_unary_operator`]) applied to `arg`.
    pub(super) fn unary_test(&mut self, op: &str, arg: &str, span: Span, run: &Run<'_>) -> Flow<bool> {
        let letter = op.as_bytes().get(1).copied().unwrap_or(b'n');
        let status = |shell: &mut Self, follow| shell.test_status(arg, follow, span);
        Ok(match letter {
            b'a' | b'e' => status(self, true)?.is_some(),
            b'r' => self.test_access(arg, Access::Read, span)?,
            b'w' => self.test_access(arg, Access::Write, span)?,
            b'x' => self.test_access(arg, Access::Execute, span)?,
            b'O' => status(self, true)?.is_some_and(|found| found.owned_by_effective_user),
            b'G' => status(self, true)?.is_some_and(|found| found.owned_by_effective_group),
            b'N' => status(self, true)?.is_some_and(|found| found.modified > found.accessed),
            b'f' => status(self, true)?.is_some_and(|found| found.file_type == FileType::Regular),
            b'd' => status(self, true)?.is_some_and(|found| found.file_type == FileType::Directory),
            b's' => status(self, true)?.is_some_and(|found| found.len > 0),
            b'S' => status(self, true)?.is_some_and(|found| found.file_type == FileType::Socket),
            b'c' => status(self, true)?.is_some_and(|found| found.file_type == FileType::CharacterDevice),
            b'b' => status(self, true)?.is_some_and(|found| found.file_type == FileType::BlockDevice),
            b'p' => status(self, true)?.is_some_and(|found| found.file_type == FileType::Fifo),
            b'h' | b'L' => {
                !arg.is_empty() && status(self, false)?.is_some_and(|found| found.file_type == FileType::Symlink)
            }
            b'u' => status(self, true)?.is_some_and(|found| found.mode & 0o4000 != 0),
            b'g' => status(self, true)?.is_some_and(|found| found.mode & 0o2000 != 0),
            b'k' => status(self, true)?.is_some_and(|found| found.mode & 0o1000 != 0),
            b't' => match legal_number(arg).and_then(|fd| u32::try_from(fd).ok()) {
                Some(fd) => self.descriptor_is_terminal(fd, span)?,
                None => false,
            },
            b'z' => arg.is_empty(),
            b'o' => self.option_is_set(arg, span)?,
            b'v' => self.variable_is_set(arg, span, run)?,
            // `-R`: a name reference with a value (KNSH-103).
            b'R' => {
                is_name(arg)
                    && self
                        .state
                        .own_attributes(arg)
                        .is_some_and(|attributes| attributes.nameref)
                    && self.state.own_value(arg).is_some()
            }
            _ => !arg.is_empty(),
        })
    }

    /// Bash's `binary_test` for the operators that compare strings as strings or files (`=`, `==`, `!=`, `<`, `>`,
    /// `-nt`, `-ot`, `-ef`); `collate`: `<` and `>` use the locale's collation, as `[[` does.
    pub(super) fn string_or_file_test(
        &mut self,
        op: &str,
        left: &str,
        right: &str,
        collate: bool,
        span: Span,
    ) -> Flow<bool> {
        Ok(match op {
            "=" | "==" => left == right,
            "!=" => left != right,
            "<" | ">" => {
                let order = if collate {
                    self.collate(left, right, span)?
                } else {
                    left.as_bytes().cmp(right.as_bytes())
                };
                if op == "<" { order.is_lt() } else { order.is_gt() }
            }
            _ => {
                let first = self.test_status(left, true, span)?;
                let second = self.test_status(right, true, span)?;
                match (op, first, second) {
                    ("-ef", Some(a), Some(b)) => a.device == b.device && a.inode == b.inode,
                    ("-nt", Some(a), Some(b)) => a.modified > b.modified,
                    ("-ot", Some(a), Some(b)) => a.modified < b.modified,
                    // A file that exists is newer than one that does not, and the missing one older.
                    ("-nt", Some(_), None) | ("-ot", None, Some(_)) => true,
                    _ => false,
                }
            }
        })
    }

    /// `left` against `right` in the collation of the shell's locale (bash's `strcoll`).
    fn collate(&mut self, left: &str, right: &str, span: Span) -> Flow<std::cmp::Ordering> {
        if left == right {
            return Ok(std::cmp::Ordering::Equal);
        }
        let locale = self.locale_for(&["LC_ALL", "LC_COLLATE", "LANG"], span)?;
        let mut pair = [left.to_owned(), right.to_owned()];
        self.collation.sort(&locale, &mut pair);
        Ok(if pair[0] == left {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        })
    }

    /// The locale named by the first of `variables` that is set and not empty, or the C locale (`""`).
    pub(super) fn locale_for(&self, variables: &[&str], span: Span) -> Flow<String> {
        for name in variables {
            if let Some(value) = self.state.variable(name) {
                let value = value
                    .to_str()
                    .ok_or_else(|| Stop::Error(unsupported(Unsupported::NonUtf8Value, span)))?;
                if !value.is_empty() {
                    return Ok(value.to_owned());
                }
            }
        }
        Ok(String::new())
    }

    /// The path a file test names: relative to the shell's working directory.
    fn test_path(&self, arg: &str) -> PathBuf {
        let path = Path::new(arg);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.state.cwd().join(path)
        }
    }

    /// The status of the file `arg` names (`follow`: symlinks followed), `None` when it cannot be stat'ed. An empty
    /// name is never a file.
    fn test_status(&mut self, arg: &str, follow: bool, span: Span) -> Flow<Option<FileStatus>> {
        if arg.is_empty() {
            return Ok(None);
        }
        if let Some(fd) = descriptor_name(arg) {
            return self.descriptor_status(fd, span);
        }
        Ok(self.fs.status(&self.test_path(arg), follow).ok())
    }

    /// `fstat` of the shell's descriptor `fd`; `None` when it is closed.
    fn descriptor_status(&mut self, fd: u32, span: Span) -> Flow<Option<FileStatus>> {
        let Some(open) = self.shell_descriptor(fd, span)? else {
            return Ok(None);
        };
        Ok(self.descriptors.status(&open).ok())
    }

    /// Whether the shell's descriptor `fd` is a terminal.
    fn descriptor_is_terminal(&mut self, fd: u32, span: Span) -> Flow<bool> {
        Ok(match self.shell_descriptor(fd, span)? {
            Some(open) => self.descriptors.is_terminal(&open),
            None => false,
        })
    }

    /// The open descriptor behind the shell's descriptor `fd`, `None` when it is closed. A standard descriptor the
    /// host did not give is refused.
    pub(super) fn shell_descriptor(&self, fd: u32, span: Span) -> Flow<Option<knsh_platform::SharedFd>> {
        match self.fds.get(fd) {
            None => Ok(None),
            Some(ChildDescriptor::Open(open)) => Ok(Some(open.clone())),
            Some(ChildDescriptor::Standard(stream)) => {
                let index = match stream {
                    StandardStream::Input => 0,
                    StandardStream::Output => 1,
                    StandardStream::Error => 2,
                };
                match self.standard.as_ref() {
                    Some(standard) => Ok(Some(standard[index].clone())),
                    None => Err(unsupported(Unsupported::StandardDescriptor, span).into()),
                }
            }
        }
    }

    /// `-r`, `-w`, `-x`: `access` with the effective ids (bash's `sh_eaccess`), or the permission bits of a
    /// descriptor name.
    fn test_access(&mut self, arg: &str, access: Access, span: Span) -> Flow<bool> {
        if arg.is_empty() {
            return Ok(false);
        }
        if let Some(fd) = descriptor_name(arg) {
            return Ok(self
                .descriptor_status(fd, span)?
                .is_some_and(|status| permitted(&status, access)));
        }
        Ok(self.fs.accessible(&self.test_path(arg), access).unwrap_or(false))
    }

    /// `-o name`: whether shell option `name` is on; `false` for a name `set -o` does not know. The options the
    /// interpreter does not implement have bash's default value; the line-editing and history options of an
    /// interactive shell are refused (KNSH-107).
    fn option_is_set(&self, name: &str, span: Span) -> Flow<bool> {
        // KNSH-104: every `set -o` option bash has; a name it does not know is false.
        match crate::options::set_o(self.state.options(), name) {
            Ok(on) => Ok(on),
            Err(crate::options::OptionError::Unknown) => Ok(false),
            Err(crate::options::OptionError::Refused(feature)) => Err(unsupported(feature, span).into()),
        }
    }

    /// `-v name`: whether variable `name` is set (has a value): for an array, its element 0; `name[subscript]`
    /// one element, `name[@]` any (KNSH-103). A variable bash maintains itself is refused.
    fn variable_is_set(&mut self, name: &str, span: Span, run: &Run<'_>) -> Flow<bool> {
        let Some(named) = self.named(name, span, run)? else {
            return Ok(false);
        };
        let array = match &named {
            super::function::Named::Variable(array)
            | super::function::Named::Element(array, _)
            | super::function::Named::All(array) => array.clone(),
        };
        if self.state.is_unemulated(&array) {
            return Err(unsupported(Unsupported::ShellVariable, span).into());
        }
        let refused = |feature| Stop::Error(unsupported(feature, span));
        Ok(match named {
            super::function::Named::Variable(name) => self
                .state
                .value(&name)
                .map_err(refused)?
                .is_some_and(|value| value.first().is_some()),
            super::function::Named::All(name) => self
                .state
                .value(&name)
                .map_err(refused)?
                .is_some_and(|value| value.count() > 0),
            super::function::Named::Element(name, key) => match self.state.element(&name, &key) {
                Ok(found) => found.is_some(),
                Err(crate::state::ElementError::BadSubscript) => {
                    self.state.note(format!("{name}: bad array subscript"));
                    false
                }
                Err(crate::state::ElementError::Unsupported(feature)) => return Err(refused(feature)),
            },
        })
    }
}

/// Bash's `test` argument parser over `args` (without `[`'s `]`).
struct TestParser<'a, 'r> {
    shell: &'a mut Interpreter,
    /// What the command is part of, for subscripts' errors (KNSH-103).
    run: &'a Run<'r>,
    args: &'a [String],
    /// The next argument.
    pos: usize,
    span: Span,
    /// Parentheses open: bounded by [`MAX_EVAL_DEPTH`](crate::MAX_EVAL_DEPTH), since the arguments may come from an
    /// expansion of any size (`test "$@"`) and each level recurses.
    depth: usize,
}

type Answer = Result<bool, Abort>;

impl TestParser<'_, '_> {
    fn arg(&self, at: usize) -> &str {
        self.args.get(at).map_or("", String::as_str)
    }

    fn argc(&self) -> usize {
        self.args.len()
    }

    /// Bash's `posixtest`, then the check that every argument was used.
    fn posix(&mut self) -> Answer {
        let value = match self.argc() {
            0 => false,
            1 => {
                self.pos = 1;
                !self.arg(0).is_empty()
            }
            2 => {
                let value = self.two()?;
                self.pos = 2;
                value
            }
            3 => self.three()?,
            4 if self.arg(0) == "!" => {
                self.pos = 1;
                !self.three()?
            }
            4 if self.arg(0) == "(" && self.arg(3) == ")" => {
                self.pos = 1;
                let value = self.two()?;
                self.pos = 4;
                value
            }
            _ => self.expr()?,
        };
        if self.pos < self.argc() {
            let at = self.arg(self.pos);
            return Err(Abort::Syntax(if at.starts_with('-') {
                format!("syntax error: `{at}' unexpected")
            } else {
                "too many arguments".to_owned()
            }));
        }
        Ok(value)
    }

    /// Two arguments at `pos`: `! word` or a unary operator and its argument.
    fn two(&mut self) -> Answer {
        let first = self.arg(self.pos).to_owned();
        if first == "!" {
            return Ok(self.arg(self.pos + 1).is_empty());
        }
        if is_unary_operator(&first) {
            return self.unary();
        }
        Err(Abort::Syntax(format!("{first}: unary operator expected")))
    }

    /// Three arguments at `pos`.
    fn three(&mut self) -> Answer {
        let middle = self.arg(self.pos + 1).to_owned();
        let first = self.arg(self.pos).to_owned();
        let value = if is_binary_operator(&middle) {
            self.binary()?
        } else if middle == "-a" || middle == "-o" {
            let (left, right) = (!first.is_empty(), !self.arg(self.pos + 2).is_empty());
            if middle == "-a" { left && right } else { left || right }
        } else if first == "!" {
            self.pos += 1;
            !self.two()?
        } else if first == "(" && self.arg(self.pos + 2) == ")" {
            !self.arg(self.pos + 1).is_empty()
        } else {
            return Err(Abort::Syntax(format!("{middle}: binary operator expected")));
        };
        self.pos = self.argc();
        Ok(value)
    }

    /// Bash's `expr`: at least one argument must be left.
    fn expr(&mut self) -> Answer {
        if self.pos >= self.argc() {
            return Err(Abort::Syntax("argument expected".to_owned()));
        }
        self.or()
    }

    /// Bash's `or`, which recurses once per `-o`: read as a loop here, since a chain from an expansion may be as
    /// long as the words allow and must not exhaust the stack. Every operand is still evaluated, as in bash.
    fn or(&mut self) -> Answer {
        let mut value = self.and()?;
        while self.pos < self.argc() && self.arg(self.pos) == "-o" {
            self.pos += 1;
            let rest = self.and()?;
            value = value || rest;
        }
        Ok(value)
    }

    /// Bash's `and`, as a loop for the same reason as [`TestParser::or`].
    fn and(&mut self) -> Answer {
        let mut value = self.term()?;
        while self.pos < self.argc() && self.arg(self.pos) == "-a" {
            self.pos += 1;
            let rest = self.term()?;
            value = value && rest;
        }
        Ok(value)
    }

    /// Advances past one argument; with `needed`, one more must follow.
    fn advance(&mut self, needed: bool) -> Result<(), Abort> {
        self.pos += 1;
        if needed && self.pos >= self.argc() {
            return Err(Abort::Syntax("argument expected".to_owned()));
        }
        Ok(())
    }

    fn term(&mut self) -> Answer {
        if self.pos >= self.argc() {
            return Err(Abort::Syntax("argument expected".to_owned()));
        }
        if self.arg(self.pos) == "!" {
            let mut negate = false;
            while self.pos < self.argc() && self.arg(self.pos) == "!" {
                self.advance(true)?;
                negate = !negate;
            }
            let value = self.term()?;
            return Ok(value != negate);
        }
        if self.arg(self.pos) == "(" {
            self.advance(true)?;
            if self.depth >= crate::MAX_EVAL_DEPTH {
                return Err(Abort::Stop(Stop::Error(crate::InterpError::DepthExceeded {
                    limit: crate::MAX_EVAL_DEPTH,
                })));
            }
            self.depth += 1;
            let value = self.expr();
            self.depth -= 1;
            let value = value?;
            match self.args.get(self.pos) {
                None => return Err(Abort::Syntax("`)' expected".to_owned())),
                Some(close) if close != ")" => {
                    return Err(Abort::Syntax(format!("`)' expected, found {close}")));
                }
                Some(_) => {}
            }
            self.pos += 1;
            return Ok(value);
        }
        if self.pos + 3 <= self.argc() && is_binary_operator(self.arg(self.pos + 1)) {
            return self.binary();
        }
        if self.pos + 2 <= self.argc() && is_unary_operator(self.arg(self.pos)) {
            return self.unary();
        }
        let value = !self.arg(self.pos).is_empty();
        self.pos += 1;
        Ok(value)
    }

    /// The unary operator at `pos` and its argument. `-t` alone tests descriptor 1, and takes the next argument only
    /// when it is a number.
    fn unary(&mut self) -> Answer {
        let op = self.arg(self.pos).to_owned();
        if op == "-t" {
            self.pos += 1;
            if self.pos < self.argc() {
                if legal_number(self.arg(self.pos)).is_none() {
                    return Ok(false);
                }
                let fd = self.arg(self.pos).to_owned();
                self.pos += 1;
                return Ok(self.shell.unary_test(&op, &fd, self.span, self.run)?);
            }
            return Ok(self.shell.unary_test(&op, "1", self.span, self.run)?);
        }
        if self.pos + 1 >= self.argc() {
            return Err(Abort::Syntax("argument expected".to_owned()));
        }
        let arg = self.arg(self.pos + 1).to_owned();
        self.pos += 2;
        Ok(self.shell.unary_test(&op, &arg, self.span, self.run)?)
    }

    /// The binary operator at `pos + 1` between the arguments around it.
    fn binary(&mut self) -> Answer {
        let left = self.arg(self.pos).to_owned();
        let op = self.arg(self.pos + 1).to_owned();
        let right = self.arg(self.pos + 2).to_owned();
        self.pos += 3;
        if is_arithmetic_operator(&op) {
            let number = |text: &str| {
                legal_number(text).ok_or_else(|| Abort::Syntax(format!("{text}: integer expression expected")))
            };
            let (left, right) = (number(&left)?, number(&right)?);
            return Ok(compare_integers(&op, left, right));
        }
        Ok(self.shell.string_or_file_test(&op, &left, &right, false, self.span)?)
    }
}
