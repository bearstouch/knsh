//! Expansion against bash 5.2's results (KNSH-097; NFR-COMPAT-02). Each case was checked against bash 3.2 where the
//! two agree; the forms 3.2 lacks or treats differently follow bash 5.2 and are listed in
//! `specs/04-non-functional-requirements/compatibility.md`.

use std::ffi::OsStr;

use knsh_bash::{Command, CommandWord, parse};
use knsh_platform::testing::FakeUserHomes;

use super::*;
use crate::status::Status;

/// A shell state with `$0` `knsh`, positional parameters `args` and the variables `vars`.
fn state(args: &[&str], vars: &[(&str, &str)]) -> ShellState {
    let mut state = ShellState::new("knsh", "/work")
        .unwrap()
        .with_environment([("HOME".into(), "/Users/me".into())])
        .with_positional(args.iter().map(|arg| (*arg).to_owned()).collect())
        .with_pid(4242);
    for (name, value) in vars {
        state.set_variable(name, *value);
    }
    state
}

fn homes() -> FakeUserHomes {
    FakeUserHomes::new()
        .with_user("alice", "/Users/alice")
        .with_current("/Users/me")
}

/// The words of the single simple command `line` after `echo`.
fn words(line: &str) -> Vec<CommandWord> {
    let script = parse(line).unwrap_or_else(|e| panic!("{line}: {e:?}"));
    let Command::Simple(simple) = &script.items[0].and_or.first.first else {
        panic!("not a simple command: {line}");
    };
    simple.words[1..].to_vec()
}

/// The arguments `echo <args>` would get.
fn expand_in(state: &mut ShellState, args: &str) -> Result<Vec<String>> {
    let line = format!("echo {args}");
    let homes = homes();
    let mut out = Vec::new();
    for command_word in words(&line) {
        let parts = word::parts(&command_word.word.segments, &line, 0)?;
        let mut expander = Expander::new(state, &homes, &line, &[]);
        out.extend(expander.arguments(&parts, command_word.span)?);
    }
    Ok(out)
}

fn expand_with(args: &[&str], vars: &[(&str, &str)], words: &str) -> Vec<String> {
    expand_in(&mut state(args, vars), words).unwrap_or_else(|e| panic!("{words}: {e:?}"))
}

fn expand(vars: &[(&str, &str)], words: &str) -> Vec<String> {
    expand_with(&[], vars, words)
}

/// Each `(words, expected)` expanded with `vars`.
fn table(vars: &[(&str, &str)], cases: &[(&str, &[&str])]) {
    for (words, expected) in cases {
        assert_eq!(expand(vars, words), *expected, "{words}");
    }
}

fn error_in(state: &mut ShellState, words: &str) -> ExpandError {
    match expand_in(state, words) {
        Err(error) => error,
        Ok(found) => panic!("{words}: expanded to {found:?}"),
    }
}

fn error(vars: &[(&str, &str)], words: &str) -> ExpandError {
    error_in(&mut state(&[], vars), words)
}

fn refusal(vars: &[(&str, &str)], words: &str) -> Unsupported {
    match error(vars, words) {
        ExpandError::Interp(InterpError::Unsupported { feature, .. }) => feature,
        other => panic!("{words}: {other:?}"),
    }
}

// ---- Special and positional parameters ----

#[test]
fn quoted_at_preserves_argument_boundaries() {
    let args = ["a b", "", "c"];
    assert_eq!(expand_with(&args, &[], r#""$@""#), ["a b", "", "c"]);
    assert_eq!(expand_with(&args, &[], r#""${@}""#), ["a b", "", "c"]);
    assert_eq!(expand_with(&args, &[], r#"x"$@"y"#), ["xa b", "", "cy"]);
    assert_eq!(expand_with(&args, &[], r#""<$@>""#), ["<a b", "", "c>"]);
    // No parameters: no word at all, not an empty one; other quoted text keeps the word.
    assert_eq!(expand_with(&[], &[], r#""$@""#), Vec::<String>::new());
    assert_eq!(expand_with(&[], &[], r#""$@" "" x"$@""#), ["", "x"]);
    // Unquoted, each parameter is a field; empty ones vanish (splitting would remove them too).
    assert_eq!(expand_with(&["a", "", "b"], &[], "$@"), ["a", "b"]);
    assert_eq!(expand_with(&["a", "b"], &[], "$*"), ["a", "b"]);
}

#[test]
fn quoted_star_joins_with_first_ifs_char() {
    let args = ["a", "b", "c"];
    assert_eq!(expand_with(&args, &[], r#""$*""#), ["a b c"]);
    assert_eq!(expand_with(&args, &[("IFS", ":-")], r#""$*""#), ["a:b:c"]);
    assert_eq!(expand_with(&args, &[("IFS", "")], r#""$*""#), ["abc"]);
    let mut unset_ifs = state(&args, &[]);
    unset_ifs.unset_variable("IFS");
    assert_eq!(expand_in(&mut unset_ifs, r#""$*""#).unwrap(), ["a b c"]);
}

#[test]
fn special_parameters() {
    let mut state = state(&["one", "two"], &[]);
    state.set_last_status(Status::new(3));
    assert_eq!(
        expand_in(&mut state, "$# ${#} $? $$ $0 $1 ${2} ${10}x $-").unwrap(),
        ["2", "2", "3", "4242", "knsh", "one", "two", "x", "hBc"]
    );
    state.options_mut().nounset = true;
    assert_eq!(expand_in(&mut state, "$-").unwrap(), ["huBc"]);
    // `$!` stays unset: nothing has run in the background.
    state.options_mut().nounset = false;
    assert_eq!(expand_in(&mut state, r#""$!""#).unwrap(), [""]);
}

// ---- Operators ----

#[test]
fn default_and_assign_operators_match_bash() {
    let vars = [("x", "set"), ("e", "")];
    table(
        &vars,
        &[
            (
                "${x:-d} ${x-d} ${e:-d} ${e-d}x ${u:-d} ${u-d}",
                &["set", "set", "d", "x", "d", "d"],
            ),
            (
                "${x:+a} ${x+a} ${e:+a}x ${e+a} ${u:+a}x ${u+a}x",
                &["a", "a", "x", "a", "x", "x"],
            ),
            (r#""${u:-a b}" ${u:-"a b"}"#, &["a b", "a b"]),
            // A word inside double quotes keeps single quotes as text.
            (r#""${u:-'q'}""#, &["'q'"]),
            ("${u:-$x}${u:-${e:-n}}", &["setn"]),
            ("${u:-~}/ ${u:-~alice}", &["/Users/me/", "/Users/alice"]),
            ("${#:-x} ${#-x}", &["0", "0"]),
        ],
    );
    // An unquoted default holding blanks would be split: refused until KNSH-098.
    assert_eq!(refusal(&[], "${u:-a b}"), Unsupported::WordSplitting);

    let mut state = state(&[], &[("e", "")]);
    assert_eq!(
        expand_in(&mut state, "${a:=one} ${a:=two} ${e=kept}x ${e:=now}").unwrap(),
        ["one", "one", "x", "now"]
    );
    assert_eq!(state.variable("a"), Some(OsStr::new("one")));
    assert_eq!(state.variable("e"), Some(OsStr::new("now")));
    assert_eq!(
        error_in(&mut state, "${1:=x}"),
        ExpandError::Discard("$1: cannot assign in this way".to_owned())
    );
    assert_eq!(
        error_in(&mut state, "${@:=x}"),
        ExpandError::Discard("$@: cannot assign in this way".to_owned())
    );
}

#[test]
fn error_operator_is_fatal_with_bash_messages() {
    let vars = [("e", "")];
    assert_eq!(
        error(&vars, "${u?}"),
        ExpandError::Fatal("u: parameter not set".to_owned())
    );
    assert_eq!(
        error(&vars, "${e:?}"),
        ExpandError::Fatal("e: parameter null or not set".to_owned())
    );
    assert_eq!(
        error(&vars, "${u:?no $e value}"),
        ExpandError::Fatal("u: no  value".to_owned())
    );
    assert_eq!(
        error(&vars, "${1:?missing}"),
        ExpandError::Fatal("1: missing".to_owned())
    );
    assert_eq!(expand(&vars, "${e?}x"), ["x"]);
}

#[test]
fn length_of_values_and_parameters() {
    let vars = [("x", "héllo"), ("e", "")];
    assert_eq!(
        expand_with(&["a", "bc"], &vars, "${#x} ${#e} ${#u} ${#1} ${#@} ${#*} ${##}"),
        ["5", "0", "0", "1", "2", "2", "1"]
    );
}

#[test]
fn pattern_removal_shortest_and_longest() {
    let vars = [("p", "/usr/local/lib/file.tar.gz"), ("s", "a*b*c"), ("star", "*")];
    table(
        &vars,
        &[
            (
                r#""${p#*/}" "${p##*/}" "${p%.*}" "${p%%.*}""#,
                &[
                    "usr/local/lib/file.tar.gz",
                    "file.tar.gz",
                    "/usr/local/lib/file.tar",
                    "/usr/local/lib/file",
                ],
            ),
            (
                r#""${p#nomatch}" "${p%[.]gz}" "${p##}""#,
                &[
                    "/usr/local/lib/file.tar.gz",
                    "/usr/local/lib/file.tar",
                    "/usr/local/lib/file.tar.gz",
                ],
            ),
            // A quoted `*` matches only itself; an unquoted expansion stays a pattern.
            (
                r#""${s#a"*"}" "${s#a\*}" "${s##*$star}" "${s#*"$star"}""#,
                &["b*c", "b*c", "", "b*c"],
            ),
        ],
    );
    assert_eq!(expand_with(&["x.c", "y.c"], &[], r#""${@%.c}""#), ["x", "y"]);
}

#[test]
fn substitution_anchored_prefix_and_suffix() {
    let vars = [("x", "aXbXc"), ("p", "/usr/lib/a.so")];
    table(
        &vars,
        &[
            (
                r#""${x/X/-}" "${x//X/-}" "${x/#a/-}" "${x/#X/-}" "${x/%c/-}" "${x/%X/-}""#,
                &["a-bXc", "a-b-c", "-XbXc", "aXbXc", "aXbX-", "aXbXc"],
            ),
            (
                r#""${x/X}" "${x//X}" "${x//}" "${x/#/>}" "${x/%/<}""#,
                &["abXc", "abc", "aXbXc", ">aXbXc", "aXbXc<"],
            ),
            // The longest match at the first place it matches.
            (r#""${x/X*/-}" "${p//\//|}""#, &["a-", "|usr|lib|a.so"]),
            // Bash 5.2's patsub_replacement: an unquoted `&` is the match, a quoted one is literal.
            (
                r#""${x//X/<&>}" "${x//X/\&}" "${x/X/"&"}""#,
                &["a<X>b<X>c", "a&b&c", "a&bXc"],
            ),
        ],
    );
}

#[test]
fn case_modification_operators() {
    let vars = [("x", "hello world"), ("y", "HELLO")];
    table(
        &vars,
        &[
            (
                r#""${x^}" "${x^^}" "${y,}" "${y,,}""#,
                &["Hello world", "HELLO WORLD", "hELLO", "hello"],
            ),
            (
                r#""${x^^[lo]}" "${x^[h]}" "${x^[e]}""#,
                &["heLLO wOrLd", "Hello world", "hello world"],
            ),
            (r#""${y~}" "${y~~}""#, &["hELLO", "hello"]),
            (
                r#""${x@U}" "${x@u}" "${y@L}""#,
                &["HELLO WORLD", "Hello world", "hello"],
            ),
        ],
    );
}

#[test]
fn substrings_of_values_and_positional_parameters() {
    let vars = [("x", "abcdef")];
    table(
        &vars,
        &[
            (
                r#""${x:2}" "${x:1:3}" "${x: -2}" "${x:(-3):2}" "${x:10}" "${x: -10}" "${x:1:-2}" "${x::2}""#,
                &["cdef", "bcd", "ef", "de", "", "", "bcd", "ab"],
            ),
            (r#""${x:1+1:2*1}""#, &["cd"]),
        ],
    );
    assert_eq!(
        error(&vars, "${x:4:-3}"),
        ExpandError::Discard("-3: substring expression < 0".to_owned())
    );
    let args = ["a", "b", "c"];
    assert_eq!(expand_with(&args, &[], r#""${@:2}""#), ["b", "c"]);
}

#[test]
fn substring_length_error_names_it_as_written() {
    // Bash's `verify_substring_values` names the length expression as written, before expansion and untrimmed
    // (bash 3.2 does the same for a negative length it rejects).
    assert_eq!(
        error(&[("x", "abc"), ("n", "-5")], r#""${x:1:$n}""#),
        ExpandError::Discard("$n: substring expression < 0".to_owned())
    );
    assert_eq!(
        error(&[("x", "abc")], r#""${x:2: -2 }""#),
        ExpandError::Discard(" -2 : substring expression < 0".to_owned())
    );
}

#[test]
fn substrings_of_positional_parameters() {
    let args = ["a", "b", "c"];
    assert_eq!(expand_with(&args, &[], r#""${@:0:2}""#), ["knsh", "a"]);
    assert_eq!(expand_with(&args, &[], r#""${@: -1}""#), ["c"]);
    assert_eq!(expand_with(&args, &[], r#""${*:2}""#), ["b c"]);
    assert_eq!(expand_with(&args, &[], r#""${@:9}""#), Vec::<String>::new());
}

#[test]
fn indirection_reads_named_variable() {
    let vars = [
        ("ref", "target"),
        ("target", "value"),
        ("num", "2"),
        ("empty", ""),
        ("bad", "a-b"),
    ];
    let args = ["one", "two"];
    assert_eq!(
        expand_with(&args, &vars, r#"${!ref} "${!ref:-d}" ${!num} ${!#} "${!ref/val/VAL}""#),
        ["value", "value", "two", "two", "VALue"]
    );
    let names_vars = [("pre_a", "1"), ("pre_b", "2"), ("prf", "3")];
    assert_eq!(
        expand(&names_vars, r#""${!pre*}" "${!pre_@}""#),
        ["pre_a pre_b", "pre_a", "pre_b"]
    );
    assert_eq!(
        error(&vars, "${!unset}"),
        ExpandError::Discard("unset: invalid indirect expansion".to_owned())
    );
    assert_eq!(
        error(&vars, "${!empty}"),
        ExpandError::Discard(": invalid variable name".to_owned())
    );
    assert_eq!(
        error(&vars, "${!bad}"),
        ExpandError::Discard("a-b: invalid variable name".to_owned())
    );
    assert_eq!(refusal(&[("arr", "a[1]")], "${!arr}"), Unsupported::Array);
}

#[test]
fn transformations() {
    let mut state = state(&[], &[("q", "it's"), ("c", "a\tb\x1b"), ("e", "a\\tb\\x41\\101")]);
    state.set_variable("X", "1");
    let found = expand_in(
        &mut state,
        r#""${q@Q}" "${c@Q}" "${e@E}" "${q@A}" "${HOME@A}" "${HOME@a}" "${q@a}x" "${u@Q}x""#,
    )
    .unwrap();
    assert_eq!(
        found,
        [
            r"'it'\''s'",
            r"$'a\tb\E'",
            "a\tbAA",
            r"q='it'\''s'",
            "declare -x HOME='/Users/me'",
            "x",
            "x",
            "x",
        ]
    );
    assert_eq!(quote(""), "''");
    assert_eq!(refusal(&[("x", "1")], "${x@P}"), Unsupported::PromptExpansion);
}

#[test]
fn bad_substitutions_discard_with_the_whole_expansion_in_the_message() {
    for words in ["${x!}", "${:-x}", "${x:}", "${x@Z}", "${#x:-y}"] {
        assert_eq!(
            error(&[], words),
            ExpandError::Discard(format!("{words}: bad substitution")),
            "{words}"
        );
    }
}

// ---- set -u ----

#[test]
fn nounset_errors_on_unset_parameter() {
    let mut state = state(&["one"], &[("e", "")]);
    state.options_mut().nounset = true;
    for (words, message) in [
        ("$u", "u: unbound variable"),
        ("${u}", "u: unbound variable"),
        ("$2", "$2: unbound variable"),
        ("${2}", "2: unbound variable"),
        ("${#u}", "u: unbound variable"),
        ("${u#x}", "u: unbound variable"),
        ("${u:1}", "u: unbound variable"),
        ("${u@Q}", "u: unbound variable"),
        ("$!", "$!: unbound variable"),
        ("$((u + 1))", "u: unbound variable"),
    ] {
        assert_eq!(
            error_in(&mut state, words),
            ExpandError::Fatal(message.to_owned()),
            "{words}"
        );
    }
    // Set, empty, defaulted or a list: no error.
    assert_eq!(
        expand_in(&mut state, r#""$e" ${u:-d} ${u-d} "${u+x}" "$@" "$*" $# $1"#).unwrap(),
        ["", "d", "d", "", "one", "one", "1", "one"]
    );
    let mut none = self::state(&[], &[]);
    none.options_mut().nounset = true;
    assert_eq!(expand_in(&mut none, r#""$@""#).unwrap(), Vec::<String>::new());
}

// ---- Tilde ----

#[test]
fn tilde_expands_home_and_user() {
    table(
        &[("PWD", "/work")],
        &[
            (
                "~ ~/x ~alice ~alice/y ~+ ~nobody/z",
                &[
                    "/Users/me",
                    "/Users/me/x",
                    "/Users/alice",
                    "/Users/alice/y",
                    "/work",
                    "~nobody/z",
                ],
            ),
            // Quoted or not first: no expansion; a quoted slash keeps the prefix going, as in bash.
            (
                r#""~" \~ a~ ~"/x" ~/"x" ~'alice'"#,
                &["~", "~", "a~", "~/x", "/Users/me/x", "~alice"],
            ),
            // Words spelled like assignments expand after `=` and `:`.
            (
                "a=~ x=~:~/b host:~",
                &["a=/Users/me", "x=/Users/me:/Users/me/b", "host:~"],
            ),
        ],
    );
    // HOME unset: the user database; HOME empty: empty.
    let mut state = state(&[], &[]);
    state.unset_variable("HOME");
    assert_eq!(expand_in(&mut state, "~").unwrap(), ["/Users/me"]);
    state.set_variable("HOME", "");
    assert_eq!(expand_in(&mut state, "~").unwrap(), [""]);
    for words in ["~-", "~1", "~+2"] {
        assert_eq!(refusal(&[], words), Unsupported::DirectoryStack, "{words}");
    }
}

// Fail closed: bash would pass a home directory that is not UTF-8 as its bytes, not `~name` as written.
#[test]
fn tilde_with_a_home_that_is_not_utf8_is_refused() {
    use std::os::unix::ffi::OsStrExt;

    let line = "echo ~bob";
    let command_word = &words(line)[0];
    let parts = word::parts(&command_word.word.segments, line, 0).unwrap();
    let homes = FakeUserHomes::new().with_user("bob", OsStr::from_bytes(b"/Users/b\xffb"));
    let mut state = state(&[], &[]);
    let found = Expander::new(&mut state, &homes, line, &[]).arguments(&parts, command_word.span);
    assert!(
        matches!(
            found,
            Err(ExpandError::Interp(InterpError::Unsupported {
                feature: Unsupported::NonUtf8Value,
                ..
            }))
        ),
        "{found:?}"
    );
}

#[test]
fn assignment_values_expand_tilde_after_colons() {
    let line = "PATH=~/bin:~alice/bin:$X:~ ";
    let script = parse(line).unwrap();
    let Command::Simple(simple) = &script.items[0].and_or.first.first else {
        panic!()
    };
    let assignment = &simple.assignments[0];
    let parts = word::parts(&assignment.word.segments, line, assignment.value.start).unwrap();
    let mut state = state(&[], &[("X", "x")]);
    let homes = homes();
    let value = Expander::new(&mut state, &homes, line, &[])
        .assignment_value(&parts, assignment.span)
        .unwrap();
    assert_eq!(value, "/Users/me/bin:/Users/alice/bin:x:/Users/me");
}

// ---- Fields, splitting and refusals ----

#[test]
fn unquoted_expansions_are_removed_when_empty_and_refused_when_split() {
    let vars = [
        ("e", ""),
        ("one", "word"),
        ("two", "a b"),
        ("glob", "*.rs"),
        ("colon", "a:b"),
    ];
    table(
        &vars,
        &[
            ("$e x $e", &["x"]),
            (r#""$e" ''$e $e"""#, &["", "", ""]),
            ("$one ${one}s", &["word", "words"]),
            (r#""$two" "$glob""#, &["a b", "*.rs"]),
            // Characters outside IFS never split.
            ("$colon", &["a:b"]),
        ],
    );
    assert_eq!(refusal(&vars, "$two"), Unsupported::WordSplitting);
    assert_eq!(refusal(&vars, "$glob"), Unsupported::PathnameExpansion);
    assert_eq!(
        refusal(&[("IFS", ":"), ("colon", "a:b")], "$colon"),
        Unsupported::WordSplitting
    );
    // With an empty IFS nothing splits.
    assert_eq!(expand(&[("IFS", ""), ("two", "a b")], "$two"), ["a b"]);
}

#[test]
fn arithmetic_expansion_inside_words() {
    let mut state = state(&["4"], &[("n", "3"), ("expr", "2*3")]);
    assert_eq!(
        expand_in(
            &mut state,
            r#"$((n + 1)) x$(( $1 * 2 ))y "$(( n++ ))" $[n] $((expr)) $(("1" + 2))"#
        )
        .unwrap(),
        ["4", "x8y", "3", "4", "6", "3"]
    );
    assert_eq!(state.variable("n"), Some(OsStr::new("4")));
    assert_eq!(
        error_in(&mut state, "$((1/0))"),
        ExpandError::Discard("1/0: division by 0 (error token is \"0\")".to_owned())
    );
    assert_eq!(refusal(&[], "$((a[1]))"), Unsupported::Array);
}

#[test]
fn variables_bash_maintains_are_refused() {
    assert_eq!(refusal(&[], "$RANDOM"), Unsupported::ShellVariable);
    assert_eq!(refusal(&[], "$((LINENO + 1))"), Unsupported::ShellVariable);
    assert_eq!(refusal(&[("ref", "BASHPID")], "${!ref}"), Unsupported::ShellVariable);
    assert_eq!(refusal(&[], "${!SEC*}"), Unsupported::ShellVariable);
    assert_eq!(refusal(&[], "$HOSTNAME"), Unsupported::ShellVariable);
    assert_eq!(expand(&[("HOSTNAME", "box")], "$HOSTNAME"), ["box"]);
    // Bash sets a default `PATH` when the environment has none, and `COMP_WORDBREAKS` always.
    assert_eq!(refusal(&[], r#""$PATH""#), Unsupported::ShellVariable);
    assert_eq!(expand(&[("PATH", "/bin")], "$PATH"), ["/bin"]);
    assert_eq!(refusal(&[], r#""$COMP_WORDBREAKS""#), Unsupported::ShellVariable);
    // `${!prefix*}` would list the variables bash sets at start-up when the environment does not.
    assert_eq!(refusal(&[], r#""${!HO*}""#), Unsupported::ShellVariable);
    assert_eq!(
        expand(&[("HOSTNAME", "box"), ("HOSTTYPE", "arm64")], r#""${!HO*}""#),
        ["HOME HOSTNAME HOSTTYPE"]
    );
    assert_eq!(refusal(&[], r#""${!COMP*}""#), Unsupported::ShellVariable);
}

#[test]
fn the_command_s_own_assignments_are_seen_first() {
    let line = "echo $a";
    let command_word = &words(line)[0];
    let parts = word::parts(&command_word.word.segments, line, 0).unwrap();
    let mut state = state(&[], &[("a", "shell")]);
    let homes = homes();
    let overlay = [("a".to_owned(), OsString::from("temporary"))];
    let found = Expander::new(&mut state, &homes, line, &overlay)
        .arguments(&parts, command_word.span)
        .unwrap();
    assert_eq!(found, ["temporary"]);
}

// CLAUDE.md "Untrusted input": nesting is bounded.
#[test]
fn deeply_nested_expansions_are_bounded() {
    let depth = MAX_EXPANSION_DEPTH + 10;
    let words = format!("{}x{}", "${u:-".repeat(depth), "}".repeat(depth));
    let line = format!("echo {words}");
    // The parser has its own nesting limit, which may stop this first; either way nothing overflows.
    if let Ok(script) = parse(&line) {
        let Command::Simple(simple) = &script.items[0].and_or.first.first else {
            panic!()
        };
        let command_word = &simple.words[1];
        let parts = word::parts(&command_word.word.segments, &line, 0).unwrap();
        let mut state = state(&[], &[]);
        let homes = homes();
        let result = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(crate::EVAL_STACK_SIZE)
                .spawn_scoped(scope, || {
                    Expander::new(&mut state, &homes, &line, &[]).arguments(&parts, command_word.span)
                })
                .unwrap()
                .join()
                .unwrap()
        });
        assert_eq!(
            result,
            Err(ExpandError::Interp(InterpError::DepthExceeded {
                limit: MAX_EXPANSION_DEPTH
            }))
        );
    }
}
