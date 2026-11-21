//! `test`, `[`, `[[ … ]]`, `printf` and `read` over the fake filesystem and descriptors (KNSH-102; NFR-COMPAT-02).
//! Statuses and messages were checked against bash 3.2 (`/bin/bash` here); where bash 5.2 differs, its source is
//! followed and the case says so.

use knsh_platform::testing::FakeLocalTime;
use knsh_platform::{FileTime, FileType, TerminalInput};

use super::*;

fn var(h: &Harness, name: &str) -> Option<String> {
    h.interpreter
        .state()
        .variable(name)
        .map(|value| value.to_string_lossy().into_owned())
}

/// A harness whose standard input holds `input` (then end of file, or with `held_open` nothing more ever), with
/// standard output and error given too; `terminal` makes standard input a terminal.
fn with_input(input: &[u8], held_open: bool, terminal: bool) -> Harness {
    Harness::with_descriptors(|interpreter, descriptors| {
        let stdin = descriptors.input(input, held_open).unwrap();
        if terminal {
            descriptors.set_terminal(&stdin);
        }
        let stdout = descriptors.input(b"", false).unwrap();
        let stderr = descriptors.input(b"", false).unwrap();
        interpreter.with_standard_descriptors([stdin, stdout, stderr])
    })
}

// KNSH-102 acceptance: `test` decides by argument count as POSIX and bash do (each status checked against bash).
#[test]
fn test_argument_count_rules() {
    let mut h = Harness::new();
    let cases: &[(&str, u8)] = &[
        // No argument is false; one is true when not empty, whatever it says.
        ("test", 1),
        ("[ ]", 1),
        ("[ '' ]", 1),
        ("[ ! ]", 0),
        ("[ -n ]", 0),
        ("[ -z ]", 0),
        ("test -t", 0),
        // Two: `!` and a word, or a unary operator.
        ("[ ! '' ]", 0),
        ("[ ! x ]", 1),
        ("[ -z '' ]", 0),
        ("[ -n '' ]", 1),
        // Three: a binary operator first, then `-a`/`-o`, `!`, parentheses.
        ("[ a = a ]", 0),
        ("[ '!' = '!' ]", 0),
        ("[ -n = -n ]", 0),
        ("[ a -a '' ]", 1),
        ("[ a -o '' ]", 0),
        ("[ ! a = b ]", 0),
        ("[ \\( a \\) ]", 0),
        ("[ ' 12 ' -eq 12 ]", 0),
        ("[ 2 -lt 10 ]", 0),
        ("[ b \\< a ]", 1),
        // Four: `!` and three, or a parenthesised two.
        ("[ ! a = a ]", 1),
        ("test '(' -n x ')'", 0),
        // More: an expression, `-a` binding tighter than `-o`.
        ("[ ! -z a -a b ]", 0),
        ("[ a -a b -o '' ]", 0),
        ("[ '' -a b -o c ]", 0),
        ("[ \\( a = a \\) -a \\( b \\) ]", 0),
        ("[ ! ! a = a -a x ]", 0),
        ("test \"(\" a = a \")\"", 0),
    ];
    for (line, status) in cases {
        assert_eq!(h.status(line), *status, "{line}");
    }
    assert!(h.diagnostics.text().is_empty(), "{}", h.diagnostics.text());
    // Syntax errors are bash's messages and status 2.
    let errors: &[(&str, &str)] = &[
        ("[ a b c ]", "[: b: binary operator expected"),
        ("[ 1 -eq x ]", "[: x: integer expression expected"),
        ("[ a", "[: missing `]'"),
        ("test a b", "test: a: unary operator expected"),
        ("test -x", ""),
        ("test a a a a a", "test: too many arguments"),
        ("[ a = b c d e ]", "[: too many arguments"),
        ("[ \\( a ]", "[: (: unary operator expected"),
        ("[ -t 1 2 ]", "[: 1: binary operator expected"),
        ("[ a =~ a ]", "[: =~: binary operator expected"),
    ];
    for (line, message) in errors {
        let before = h.diagnostics.text().len();
        let status = h.status(line);
        let said = h.diagnostics.text()[before..].to_owned();
        if message.is_empty() {
            // One argument: a non-empty string, true.
            assert_eq!(status, 0, "{line}");
        } else {
            assert_eq!(status, 2, "{line}");
            assert_eq!(said, format!("knsh: line 1: {message}\n"), "{line}");
        }
    }
    assert_eq!(h.ran(), Vec::<String>::new());
    // Parentheses from an expansion of any size end in the nesting limit, not a stack overflow.
    let deep: Vec<String> = std::iter::repeat_n("(".to_owned(), 5000)
        .chain(std::iter::once("a".to_owned()))
        .chain(std::iter::repeat_n(")".to_owned(), 5000))
        .collect();
    let state = h.interpreter.state().clone().with_positional(deep);
    *h.interpreter.state_mut() = state;
    assert_eq!(
        h.run("test \"$@\""),
        Err(InterpError::DepthExceeded { limit: MAX_EVAL_DEPTH })
    );
}

// KNSH-102: file tests through the filesystem, relative to the working directory.
#[test]
fn file_tests_read_the_filesystem() {
    let mut h = Harness::new();
    h.fs.write(Path::new("/work/file"), b"data", 0o644).unwrap();
    h.fs.write(Path::new("/work/empty"), b"", 0o755).unwrap();
    h.fs.write(Path::new("/work/fifo"), b"", 0o644).unwrap();
    h.fs.set_file_type(Path::new("/work/fifo"), FileType::Fifo).unwrap();
    h.fs.add_symlink(Path::new("/work/link"), Path::new("file")).unwrap();
    h.fs.add_symlink(Path::new("/work/dangling"), Path::new("nowhere"))
        .unwrap();
    h.fs.write(Path::new("/work/theirs"), b"", 0o4600).unwrap();
    h.fs.set_owner(Path::new("/work/theirs"), 0).unwrap();
    let late = FileTime {
        seconds: 200,
        nanoseconds: 5,
    };
    h.fs.set_times(Path::new("/work/file"), late, late).unwrap();
    h.fs.set_times(Path::new("/work/empty"), FileTime::default(), late)
        .unwrap();
    let cases: &[(&str, u8)] = &[
        ("[ -e file ]", 0),
        ("[ -a /work/file ]", 0),
        ("[ -e missing ]", 1),
        ("[ -e '' ]", 1),
        ("[ -f file ]", 0),
        ("[ -f /work ]", 1),
        ("[ -d /work ]", 0),
        ("[ -s file ]", 0),
        ("[ -s empty ]", 1),
        ("[ -p fifo ]", 0),
        ("[ -f fifo ]", 1),
        ("[ -h link ]", 0),
        ("[ -L file ]", 1),
        ("[ -f link ]", 0),
        ("[ -h dangling ]", 0),
        ("[ -e dangling ]", 1),
        ("[ -r file ]", 0),
        ("[ -w file ]", 0),
        ("[ -x file ]", 1),
        ("[ -x empty ]", 0),
        ("[ -O file ]", 0),
        ("[ -O theirs ]", 1),
        ("[ -G file ]", 0),
        ("[ -u theirs ]", 0),
        ("[ -u file ]", 1),
        ("[ -r theirs ]", 1),
        ("[ -N file ]", 1),
        ("[ -N empty ]", 0),
        ("[ file -nt empty ]", 1),
        ("[ empty -nt fifo ]", 0),
        ("[ fifo -ot file ]", 0),
        ("[ file -nt missing ]", 0),
        ("[ missing -ot file ]", 0),
        ("[ missing -nt file ]", 1),
        ("[ link -ef file ]", 0),
        ("[ file -ef empty ]", 1),
        ("[ missing -ef missing ]", 1),
    ];
    for (line, status) in cases {
        assert_eq!(h.status(line), *status, "{line}");
    }
}

// KNSH-102: `-v`, `-o`, `-t` and the shell's descriptor names.
#[test]
fn variable_option_and_descriptor_tests() {
    let mut h = with_input(b"", false, true);
    h.interpreter.state_mut().set_variable("set_one", "");
    assert_eq!(h.status("[ -v set_one ]"), 0);
    assert_eq!(h.status("[ -v unset_one ]"), 1);
    assert_eq!(h.status("declare -x valueless; [ -v valueless ]"), 1);
    assert_eq!(h.status("[ -v PIPESTATUS ]"), 0);
    assert_eq!(h.status("[ -o noglob ]"), 1);
    h.interpreter.state_mut().options_mut().noglob = true;
    assert_eq!(h.status("[ -o noglob ]"), 0);
    assert_eq!(h.status("[ -o hashall ] && [ ! -o nonsense ]"), 0);
    // Descriptor 0 is a terminal here, 1 is not; a closed one is not.
    assert_eq!(h.status("[ -t 0 ]"), 0);
    assert_eq!(h.status("[ -t 1 ]"), 1);
    assert_eq!(h.status("[ -t 7 ]"), 1);
    assert_eq!(h.status("[ -t 0 ] <<< x"), 1);
    // `/dev/stdin` is the shell's descriptor 0: a here-string is a pipe, a redirected file a regular file.
    assert_eq!(h.status("[ -p /dev/stdin ] <<< x"), 0);
    h.fs.write(Path::new("/work/in"), b"", 0o644).unwrap();
    assert_eq!(
        h.status("[ -f /dev/stdin ] < in && [ -e /dev/fd/0 ] && [ ! -e /dev/fd/9 ]"),
        0
    );
    assert_eq!(refused(h.run("[ -v RANDOM ]")), Unsupported::ShellVariable);
    // KNSH-103: an element is set or not.
    assert_eq!(h.status("[ -v a[1] ]"), 1);
    assert_eq!(h.status("a[1]=x; [ -v a[1] ] && [ ! -v a[0] ] && [ -v a[@] ]"), 0);
    // Without standard descriptors from the host, asking about one is refused rather than guessed.
    let mut bare = Harness::new();
    assert_eq!(refused(bare.run("[ -t 1 ]")), Unsupported::StandardDescriptor);
    assert_eq!(bare.status("[ -t 0 ] < /dev/null"), 1);
}

// KNSH-102 acceptance: inside `[[ … ]]` words are neither split nor matched against file names.
#[test]
fn double_bracket_does_not_split_words() {
    let mut h = Harness::new();
    h.fs.write(Path::new("/work/aa"), b"", 0o644).unwrap();
    h.interpreter.state_mut().set_variable("x", "a b");
    h.interpreter.state_mut().set_variable("star", "*");
    h.interpreter.state_mut().set_variable("empty", "");
    let cases: &[(&str, u8)] = &[
        ("[[ $x == \"a b\" ]]", 0),
        ("[[ $x = a* ]]", 0),
        ("[[ -n $x ]]", 0),
        ("[[ $empty ]]", 1),
        ("[[ -z $empty && -n $x ]]", 0),
        // `$star` is `*`, compared as a pattern on the right, as text on the left; never `aa`.
        ("[[ $star == \\* ]]", 0),
        ("[[ aa == $star ]]", 0),
        ("[[ aa == \"$star\" ]]", 1),
        ("[[ $star = aa ]]", 1),
        ("[[ ab == \"a\"* ]]", 0),
        ("[[ ab == @(a|b)b ]]", 0),
        ("[[ ab != a? ]]", 1),
        ("[[ a < b ]]", 0),
        ("[[ b > a && ! a > b ]]", 0),
        ("[[ 1 -eq 1+0 ]]", 0),
        ("[[ 010 -eq 8 ]]", 0),
        ("[[ -n \"\" || x ]]", 0),
        ("[[ ! ( a == b ) && c ]]", 0),
        ("[[ -f /work/aa && -d /work ]]", 0),
        ("[[ \"-f\" ]]", 0),
    ];
    for (line, status) in cases {
        assert_eq!(h.status(line), *status, "{line}");
    }
    // An arithmetic error is bash's message and a false test (`unset_one` is 0, as in bash).
    assert_eq!(h.status("[[ unset_one -eq 1+ ]]"), 1);
    assert!(
        h.diagnostics.text().contains("knsh: line 1: [[: 1+: "),
        "{}",
        h.diagnostics.text()
    );
    // Short-circuit: the right side's expansion never runs.
    assert_eq!(h.status("[[ -n x || ${undefined?never} ]]"), 0);
}

// KNSH-102 acceptance: `=~` is a POSIX extended regular expression, as bash matches it; `BASH_REMATCH` holds the
// match and each subexpression (empty for one that took no part), and is emptied by a failed match.
#[test]
fn regex_match_sets_bash_rematch() {
    let mut h = Harness::new();
    assert_eq!(h.status("[[ abc =~ ^a(b)(x)?c$ ]]"), 0);
    assert_eq!(h.interpreter.state().bash_rematch(), ["abc", "b", ""]);
    assert_eq!(
        h.status("printf '%s|' \"$BASH_REMATCH\" \"${BASH_REMATCH[1]}\" \"${#BASH_REMATCH[@]}\" ${BASH_REMATCH[@]}"),
        0
    );
    assert_eq!(h.output.text(), "abc|b|3|abc|b|");
    assert_eq!(h.status("[[ ab =~ (a|b)+ ]] && [[ 'a b' =~ (a b) ]]"), 0);
    assert_eq!(h.interpreter.state().bash_rematch(), ["a b", "a b"]);
    h.interpreter.state_mut().set_variable("pattern", "[0-9]+");
    assert_eq!(h.status("[[ a12 =~ $pattern ]]"), 0);
    assert_eq!(h.interpreter.state().bash_rematch(), ["12"]);
    // Quoted characters match themselves.
    assert_eq!(h.status("[[ a.c =~ \"a.c\" ]]"), 0);
    assert_eq!(h.status("[[ abc =~ \"a.c\" ]]"), 1);
    assert_eq!(h.interpreter.state().bash_rematch().len(), 0);
    assert_eq!(h.status("[[ x.y =~ x[.]y ]]"), 0);
    // An invalid expression is status 2, without a message; a quoted `(` is a literal one, valid.
    assert_eq!(h.status("open='('; [[ a =~ $open ]]"), 2);
    assert_eq!(h.status("[[ a =~ \"(\" ]]"), 1);
    assert_eq!(h.diagnostics.text(), "");
    // Assigning it is refused, as for PIPESTATUS.
    assert_eq!(refused(h.run("BASH_REMATCH=x")), Unsupported::ShellVariable);
}

// KNSH-102: the regex engine works in the shell's locale: `.` is one UTF-8 character there, one byte in C, where a
// match splitting a character is refused rather than altered.
#[test]
fn regex_follows_the_shell_locale() {
    let mut h = Harness::new();
    assert_eq!(h.status("LC_ALL=en_US.UTF-8; [[ é =~ ^.$ ]]"), 0);
    assert_eq!(h.status("LC_ALL=C; [[ é =~ ^.$ ]]"), 1);
    assert_eq!(refused(h.run("LC_ALL=C; [[ é =~ ^(.) ]]")), Unsupported::RegexText);
}

// KNSH-102: `printf` runs in the shell: `-v`, `%q`, missing arguments, errors before output, status.
#[test]
fn printf_builtin_assigns_quotes_and_reports() {
    let mut h = Harness::new();
    assert_eq!(h.status("printf -v out '%s=%d;' a 1 b 2; printf '%s\\n' \"$out\""), 0);
    assert_eq!(h.output.text(), "a=1;b=2;\n");
    assert_eq!(var(&h, "out").as_deref(), Some("a=1;b=2;"));
    assert_eq!(h.status("printf -vname %q 'a b'"), 0);
    assert_eq!(var(&h, "name").as_deref(), Some("a\\ b"));
    // `%n` and `-v` cut at NUL, as bash's strings.
    assert_eq!(h.status("printf -v cut 'a\\0b'; printf 'xy%n' count"), 0);
    assert_eq!(var(&h, "cut").as_deref(), Some("a"));
    assert_eq!(var(&h, "count").as_deref(), Some("2"));
    assert_eq!(h.status("printf '%d\\n' 12abc"), 1);
    assert_eq!(h.diagnostics.text(), "knsh: line 1: printf: 12abc: invalid number\n");
    let before = h.diagnostics.text().len();
    assert_eq!(h.status("printf"), 2);
    assert_eq!(h.status("printf -x"), 2);
    assert_eq!(h.status("printf -v 1x a"), 2);
    assert_eq!(
        &h.diagnostics.text()[before..],
        "printf: usage: printf [-v var] format [arguments]\nknsh: line 1: printf: -x: invalid option\n\
         printf: usage: printf [-v var] format [arguments]\nknsh: line 1: printf: `1x': not a valid identifier\n"
    );
    assert_eq!(h.status("readonly r=1; printf -v r x"), 1);
    // KNSH-103: `-v` assigns an element.
    assert_eq!(h.status("printf -v 'a[1]' %s-%s x y"), 0);
    assert_eq!(h.status("[ \"${a[1]}\" = x-y ]"), 0);
    // A grouped number in a locale that groups, or `%T` without a clock, is refused.
    assert_eq!(
        refused(h.run("LC_ALL=en_US.UTF-8; printf \"%'d\" 1000")),
        Unsupported::PrintfLocale
    );
    assert_eq!(refused(h.run("printf '%(%Y)T' 0")), Unsupported::PrintfLocale);
    assert_eq!(h.ran(), Vec::<String>::new());
}

// KNSH-102: `%(…)T` through the host's local time: now, the shell's start, an explicit time; a `TZ` the host does
// not convert in is refused.
#[test]
fn printf_time_uses_the_host_clock() {
    let mut h = Harness::with(|interpreter| {
        interpreter
            .with_local_time(Arc::new(FakeLocalTime::new(951_782_400)))
            .unwrap()
    });
    assert_eq!(h.status("printf '%(%F)T|%(%s)T|%(%s)T|%()T' 86400 -1 -2"), 0);
    assert_eq!(h.output.text(), "1970-01-02|951782400|951782400|%X");
    assert_eq!(refused(h.run("TZ=UTC; printf '%(%s)T'")), Unsupported::PrintfLocale);
}

// KNSH-102 acceptance: without `-r` a backslash quotes the next character and is removed; with it, kept.
#[test]
fn read_raw_keeps_backslashes() {
    let mut h = Harness::new();
    assert_eq!(h.status("read -r a <<< 'x\\ny'; read b <<< 'x\\ny'"), 0);
    assert_eq!(var(&h, "a").as_deref(), Some("x\\ny"));
    assert_eq!(var(&h, "b").as_deref(), Some("xny"));
    // An escaped separator stays in its field; a backslash-newline joins lines.
    assert_eq!(h.status("read c d <<< 'p\\ q r'; read -r e f <<< 'p\\ q r'"), 0);
    assert_eq!(
        (var(&h, "c"), var(&h, "d"), var(&h, "e"), var(&h, "f")),
        (
            Some("p q".into()),
            Some("r".into()),
            Some("p\\".into()),
            Some("q r".into())
        )
    );
    h.fs.write(Path::new("/work/joined"), b"a\\\nb\nc\n", 0o644).unwrap();
    assert_eq!(h.status("read g < joined; read -r i < joined"), 0);
    assert_eq!((var(&h, "g"), var(&h, "i")), (Some("ab".into()), Some("a\\".into())));
}

// KNSH-102 acceptance: a `-t` timeout is status 142 (above 128), with what was read assigned; `-t 0` only checks.
#[test]
fn read_timeout_status_above_128() {
    let mut h = with_input(b"partial", true, false);
    assert_eq!(h.status("read -t 0.5 x"), 142);
    assert_eq!(var(&h, "x").as_deref(), Some("partial"));
    assert_eq!(h.status("read -t 0 y"), 1);
    assert_eq!(var(&h, "y"), None);
    let mut ready = with_input(b"line\n", false, false);
    assert_eq!(ready.status("read -t 0 y; echo $?; read -t 5 z"), 0);
    assert_eq!(ready.output.text(), "0\n");
    assert_eq!(var(&ready, "z").as_deref(), Some("line"));
}

// KNSH-102: lines from standard input one at a time (the rest left for later reads), `IFS`, `REPLY`, `-d`, `-n`,
// `-N`, end of file.
#[test]
fn read_splits_lines_like_bash() {
    let mut h = with_input(b"one two three\n  spaced  \nlast", false, false);
    assert_eq!(h.status("read a b"), 0);
    assert_eq!(
        (var(&h, "a"), var(&h, "b")),
        (Some("one".into()), Some("two three".into()))
    );
    assert_eq!(h.status("read"), 0);
    assert_eq!(var(&h, "REPLY").as_deref(), Some("  spaced  "));
    // The last line has no newline: assigned, status 1; then nothing is left.
    assert_eq!(h.status("read c"), 1);
    assert_eq!(var(&h, "c").as_deref(), Some("last"));
    assert_eq!(h.status("read d"), 1);
    assert_eq!(var(&h, "d").as_deref(), Some(""));
    let mut h = Harness::new();
    assert_eq!(h.status("IFS=: read a b <<< 'x:y:z:'"), 0);
    assert_eq!((var(&h, "a"), var(&h, "b")), (Some("x".into()), Some("y:z:".into())));
    // The temporary `IFS` is gone afterwards.
    assert_eq!(var(&h, "IFS").as_deref(), Some(" \t\n"));
    assert_eq!(h.status("read -d , a b <<< 'p q,r'"), 0);
    assert_eq!((var(&h, "a"), var(&h, "b")), (Some("p".into()), Some("q".into())));
    assert_eq!(h.status("read -n 2 a <<< xyz; read -N 4 b <<< 'a\nbcd'"), 0);
    assert_eq!((var(&h, "a"), var(&h, "b")), (Some("xy".into()), Some("a\nbc".into())));
    assert_eq!(h.status("LC_ALL=en_US.UTF-8; read -n 2 a <<< éèx"), 0);
    assert_eq!(var(&h, "a").as_deref(), Some("éè"));
    assert_eq!(h.status("read -d '' a <<< 'x y'"), 1);
    assert_eq!(var(&h, "a").as_deref(), Some("x y"));
    // A while-read loop over a file.
    h.fs.write(Path::new("/work/list"), b"1\n2\n3\n", 0o644).unwrap();
    assert_eq!(h.status("while read n; do printf '<%s>' $n; done < list"), 0);
    assert_eq!(h.output.text(), "<1><2><3>");
    assert_eq!(h.ran(), Vec::<String>::new());
}

// KNSH-102: `-u`, option errors, invalid names, read-only variables, refusals.
#[test]
fn read_options_and_errors() {
    let mut h = Harness::new();
    h.fs.write(Path::new("/work/three"), b"from three\n", 0o644).unwrap();
    assert_eq!(h.status("exec 3< three; read -u 3 a b; exec 3<&-"), 0);
    assert_eq!(
        (var(&h, "a"), var(&h, "b")),
        (Some("from".into()), Some("three".into()))
    );
    let errors: &[(&str, u8, &str)] = &[
        ("read 1a <<< x", 1, "knsh: line 1: read: `1a': not a valid identifier\n"),
        (
            "read -u 9 a",
            1,
            "knsh: line 1: read: 9: invalid file descriptor: Bad file descriptor\n",
        ),
        (
            "read -u x a",
            1,
            "knsh: line 1: read: x: invalid file descriptor specification\n",
        ),
        (
            "read -t x a",
            1,
            "knsh: line 1: read: x: invalid timeout specification\n",
        ),
        ("read -n x a", 1, "knsh: line 1: read: x: invalid number\n"),
        (
            "read -z a",
            2,
            "knsh: line 1: read: -z: invalid option\nread: usage: read [-ers] [-a array] [-d delim] [-i text] \
             [-n nchars] [-N nchars] [-p prompt] [-t timeout] [-u fd] [name ...]\n",
        ),
        (
            "readonly ro=1; read ro <<< x",
            1,
            "knsh: line 1: ro: readonly variable\n",
        ),
        (
            "read a <&-",
            1,
            "knsh: line 1: read: read error: 0: Bad file descriptor\n",
        ),
    ];
    for (line, status, message) in errors {
        let before = h.diagnostics.text().len();
        assert_eq!(h.status(line), *status, "{line}");
        assert_eq!(&h.diagnostics.text()[before..], *message, "{line}");
    }
    // `-e` off a terminal is ignored, as bash turns it off; `-a` fills an array and a name may be an element
    // (KNSH-103).
    assert_eq!(h.status("read -e a <<< x"), 0);
    assert_eq!(
        h.status("opts=-a; read $opts a <<< 'x  y'; [ \"${#a[@]}:${a[1]}\" = 2:y ]"),
        0
    );
    assert_eq!(h.status("read 'b[2]' c <<< 'p q'; [ \"${b[2]}$c\" = pq ]"), 0);
    // Standard input the host did not give is refused rather than guessed.
    assert_eq!(refused(h.run("read a")), Unsupported::StandardDescriptor);
}

// KNSH-102: on a terminal `-p` prompts on standard error, `-s` turns echo off and `-n` reads a character at a time;
// the settings are put back. Off a terminal neither prompts nor changes anything.
#[test]
fn read_prompts_and_sets_the_terminal() {
    let mut h = with_input(b"secret\nk", false, true);
    assert_eq!(h.status("read -s -p 'Password: ' pw; read -n 1 key"), 0);
    assert_eq!(h.diagnostics.text(), "Password: ");
    assert_eq!(
        (var(&h, "pw"), var(&h, "key")),
        (Some("secret".into()), Some("k".into()))
    );
    assert_eq!(
        h.descriptors.terminal_changes(),
        [
            Some(TerminalInput {
                echo: false,
                canonical: true
            }),
            None,
            Some(TerminalInput {
                echo: true,
                canonical: false
            }),
            None,
        ]
    );
    let mut h = with_input(b"x\n", false, false);
    assert_eq!(h.status("read -s -p 'Prompt: ' a"), 0);
    assert_eq!(h.diagnostics.text(), "");
    assert_eq!(h.descriptors.terminal_changes().len(), 0);
    // `-e` on a terminal needs line editing (KNSH-107).
    let mut h = with_input(b"x\n", false, true);
    assert_eq!(refused(h.run("read -e a")), Unsupported::ReadOption);
}

// KNSH-102 (review): `!`, `&&` and `||` in `[[` see an invalid regular expression's status 2 as false, as bash's
// `execute_cond_node` does (each status checked against /bin/bash 3.2).
#[test]
fn invalid_regex_status_is_false_to_conditional_operators() {
    let mut h = Harness::new();
    let cases: &[(&str, u8)] = &[
        ("r='('; [[ ! a =~ $r ]]", 0),
        ("r='('; [[ ! ( a =~ $r ) ]]", 0),
        ("r='('; [[ a =~ $r || b ]]", 0),
        ("r='('; [[ a =~ $r || a =~ $r ]]", 2),
        ("r='('; [[ a =~ $r && b ]]", 2),
        ("r='('; [[ b && a =~ $r ]]", 2),
        ("r='('; ! [[ a =~ $r ]]", 0),
    ];
    for (line, status) in cases {
        assert_eq!(h.status(line), *status, "{line}");
    }
}

// KNSH-102 (review): a `-o`/`-a` chain as long as an expansion allows is read without recursing per operator, so it
// ends in an answer rather than a stack overflow.
#[test]
fn long_test_chains_do_not_exhaust_the_stack() {
    let mut h = Harness::new();
    for (op, last, status) in [("-o", "a", 0), ("-a", "", 1)] {
        let chain: Vec<String> = std::iter::repeat_n(["a".to_owned(), op.to_owned()], 400_000)
            .flatten()
            .chain(std::iter::once(last.to_owned()))
            .collect();
        let state = h.interpreter.state().clone().with_positional(chain);
        *h.interpreter.state_mut() = state;
        assert_eq!(h.status("test \"$@\""), status, "{op}");
    }
    // Every operand is still evaluated in order and `-a` binds tighter than `-o`.
    assert_eq!(h.status("[ '' -o a -a '' -o '' ]"), 1);
    assert_eq!(h.status("[ '' -o a -a b -o '' ]"), 0);
}

// KNSH-102 (review): a `-t` timeout too long for the clock waits without end instead of panicking; a terminal's
// settings are put back however the read ends (a timeout, a refusal while reading).
#[test]
fn read_timeouts_and_terminal_restore_on_every_end() {
    let mut h = with_input(b"ab\n", false, false);
    assert_eq!(h.status("read -t 18446744073709551615 x"), 0);
    assert_eq!(var(&h, "x").as_deref(), Some("ab"));
    let mut h = with_input(b"part", true, true);
    assert_eq!(h.status("read -s -t 0.01 x"), 142);
    assert_eq!(h.descriptors.terminal_changes().last(), Some(&None));
    // An invalid `IFS` value after the terminal changed (a non-UTF-8 locale variable) also puts it back.
    let mut h = with_input(b"ab\n", false, true);
    h.interpreter.state_mut().set_variable(
        "LC_ALL",
        <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b"\xff"),
    );
    assert_eq!(refused(h.run("read -s x")), Unsupported::NonUtf8Value);
    assert_eq!(h.descriptors.terminal_changes().last(), Some(&None));
}
