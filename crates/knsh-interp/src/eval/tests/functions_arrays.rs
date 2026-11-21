//! Functions, dynamic scopes, indexed and associative arrays, name references and `mapfile` over the fake
//! filesystem (KNSH-103; NFR-COMPAT-02). Outputs were checked against bash 3.2 (`/bin/bash` here) for what it has;
//! associative arrays, negative subscripts, name references and `mapfile` (bash 4 and later) follow bash 5.2's
//! source, and each such case says so.

use super::*;

/// Runs `script` and returns what the shell itself wrote to standard output.
fn output(script: &str) -> String {
    let mut h = Harness::new();
    h.run(script).unwrap();
    assert!(h.diagnostics.text().is_empty(), "{script}: {}", h.diagnostics.text());
    h.output.text()
}

/// Runs `script` and returns its status, standard output and diagnostics.
fn outcome(script: &str) -> (u8, String, String) {
    let mut h = Harness::new();
    let status = h.status(script);
    (status, h.output.text(), h.diagnostics.text())
}

// KNSH-103 acceptance: dynamic scoping matches bash, including `local` shadowing and unset behaviour (checked
// against bash 3.2). A function sees its caller's locals; `unset` of a local of the running function leaves it
// unset but local; a function's assignment to a name nobody declared local is global.
#[test]
fn local_shadows_and_restores_global() {
    let script = r#"x=global
show() { echo "show:$x"; }
f() { local x=local1; show; g; show; }
g() { local x=local2; show; unset x; show; x=again; show; }
f; echo "top:$x"
h() { x=changed-by-h; }; h; echo "after-h:$x"
k() { local y; y=inner; echo "k:${y}"; }; y=outer; k; echo "y:$y""#;
    assert_eq!(
        output(script),
        "show:local1\nshow:local2\nshow:\nshow:again\nshow:local1\ntop:global\nafter-h:changed-by-h\nk:inner\ny:outer\n"
    );
}

// Unsetting a caller's local removes it, so the global shows again (bash's dynamic unset, checked against 3.2).
#[test]
fn unset_of_a_callers_local_reveals_the_global() {
    let script = r#"x=g
f() { local x=l; g; echo "f:$x"; }
g() { unset x; echo "g:${x-unset}"; }
f; echo "top:$x""#;
    assert_eq!(output(script), "g:g\nf:g\ntop:g\n");
}

// Locals: `declare` inside a function is local unless `-g`; a local of an exported variable is exported; a local
// cannot shadow a read-only variable (checked against bash 3.2; `-g` is bash 4.2).
#[test]
fn declare_in_a_function_is_local_and_local_follows_bash() {
    let script = r#"f2() { declare Y=in; declare -g G=global; }; Y=out; f2; echo "Y=$Y G=$G"
export X=1; f() { local X=2; env; }; f
readonly R=1; f3() { local R=2; echo "st=$? R=$R"; }; f3"#;
    let mut h = Harness::new();
    h.on("env", &[exited(0)]);
    h.run(script).unwrap();
    assert!(h.output.text().starts_with("Y=out G=global\n"), "{}", h.output.text());
    assert!(h.output.text().ends_with("st=1 R=1\n"), "{}", h.output.text());
    assert_eq!(h.diagnostics.text(), "knsh: line 3: local: R: readonly variable\n");
    let env = &h.commands.runs()[0].env;
    assert!(env.contains(&("X".into(), "2".into())), "{env:?}");
    // Outside a function `local` is an error.
    let (status, _, diagnostics) = outcome("local x=1");
    assert_eq!(status, 1);
    assert_eq!(diagnostics, "knsh: line 1: local: can only be used in a function\n");
}

// Calls: arguments are the positional parameters (`$0` unchanged) and are put back; `$?` is the status before the
// call; `return` without a number is the last status; assignments before a call are the function's and exported
// (checked against bash 3.2).
#[test]
fn calls_take_arguments_and_return_statuses() {
    let script = r#"f8() { echo "args:$#:$1:$0"; shift; echo "$1"; }; set -- a b; f8 x y; echo "$1"
g() { echo "status:$?"; }; false; g
f6() { return 7; echo no; }; f6; echo "st=$?"
f7() { false; return; }; f7; echo "st=$?"
k() { echo "k:$v"; v=changed; }; v=orig; v=temp k; echo "v=$v"
function w { echo word-form; }; w
p() ( v=sub; echo "p:$v" ); p; echo "v=$v""#;
    assert_eq!(
        output(script),
        "args:2:x:knsh\ny\na\nstatus:1\nst=7\nst=1\nk:temp\nv=orig\nword-form\np:sub\nv=orig\n"
    );
}

// Bash 4.4 and later reset the loop state in a function: `break` there is not the caller's.
#[test]
fn break_inside_a_function_is_not_the_callers() {
    let (status, out, diagnostics) = outcome("f(){ break; }; for i in 1 2; do echo i$i; f; done; echo st=$?");
    assert_eq!(status, 0);
    assert_eq!(out, "i1\ni2\nst=0\n");
    assert_eq!(
        diagnostics,
        "knsh: line 1: break: only meaningful in a `for', `while', or `until' loop\n\
         knsh: line 1: break: only meaningful in a `for', `while', or `until' loop\n"
    );
}

// KNSH-103: `FUNCNAME` lists the call chain innermost first (bash -c has no `main` frame), `BASH_LINENO` the lines
// each was called on; outside functions `FUNCNAME` is unset (checked against bash 3.2 but for its -c line numbers,
// which start at 0; bash 5.2 numbers them as its messages do).
#[test]
fn funcname_stack_matches_call_chain() {
    let script = r#"outer() { echo "o:${FUNCNAME[*]}|${#FUNCNAME[@]}|${FUNCNAME[0]}|${BASH_LINENO[*]}"; inner; }
inner() { echo "i:${FUNCNAME[*]}|${FUNCNAME[1]}|$FUNCNAME|${BASH_LINENO[*]}"; }
outer
echo "top:${#FUNCNAME[@]}:${FUNCNAME-unset}""#;
    assert_eq!(
        output(script),
        "o:outer|1|outer|3\ni:inner outer|outer|inner|1 3\ntop:0:unset\n"
    );
}

// A sourced file is a frame: `source` in `FUNCNAME` inside a function, its file in `BASH_SOURCE` (checked against
// bash 3.2). A function defined in the main script has the `BASH_SOURCE` element bash 5.2 calls `main` and bash 3.2
// leaves out: reading it is refused, reading the file's elements is not.
#[test]
fn bash_source_names_sourced_files() {
    let mut h = Harness::new();
    h.fs.write(
        Path::new("/work/lib.sh"),
        b"q() { echo \"q:${FUNCNAME[*]}|${BASH_SOURCE[0]}|${BASH_SOURCE[1]}|${BASH_LINENO[*]}\"; }\nq\n",
        0o644,
    )
    .unwrap();
    h.run(". ./lib.sh\nq").unwrap();
    assert_eq!(h.output.text(), "q:q source|./lib.sh|./lib.sh|2 1\nq:q|./lib.sh||2\n");
    assert_eq!(
        refused(h.run("r() { echo \"${BASH_SOURCE[0]}\"; }; r")),
        Unsupported::ShellVariable
    );
}

// FUNCNEST: past it a call is bash's error and the line is abandoned; the script goes on.
#[test]
fn funcnest_limits_recursion() {
    let (status, out, diagnostics) =
        outcome("FUNCNEST=3; f() { echo d$1; f $(( $1 + 1 )); }; f 1; echo next=$?\necho after");
    assert_eq!(status, 0);
    assert_eq!(out, "d1\nd2\nd3\nafter\n");
    assert_eq!(
        diagnostics,
        "knsh: line 1: f: maximum function nesting level exceeded (3)\n"
    );
    // Without FUNCNEST the evaluator's own limit stops endless recursion with an error, not a crash.
    let mut h = Harness::with(|interpreter| interpreter.with_max_depth(50));
    assert!(matches!(h.run("f() { f; }; f"), Err(InterpError::DepthExceeded { .. })));
}

// Definitions: a name bash refuses, a read-only function, `unset -f`, and `unset` falling back to a function
// (checked against bash 3.2).
#[test]
fn definitions_follow_bash() {
    let (status, out, diagnostics) = outcome(
        "h(){ :; }; readonly -f h; h(){ echo 2; }; echo st=$?; unset -f h; echo st=$?\n\
         g(){ :; }; unset g; declare -F g; echo st=$?\n\
         f(){ :; }; type -t f; command -v f; declare -F f; declare -F",
    );
    assert_eq!(status, 0);
    assert_eq!(out, "st=1\nst=1\nst=1\nfunction\nf\nf\ndeclare -f f\ndeclare -fr h\n");
    assert_eq!(
        diagnostics,
        "knsh: line 1: h: readonly function\nknsh: line 1: unset: h: cannot unset: readonly function\n"
    );
    // A function overrides a builtin; `command` and `builtin` skip it.
    assert_eq!(
        output("echo() { builtin echo fn:$1; }; echo x; command echo y; builtin echo z"),
        "fn:x\ny\nz\n"
    );
}

// A function in a pipeline stage runs beside the other stages; one named by an expansion is refused there.
#[test]
fn functions_run_in_pipelines() {
    let mut h = Harness::new();
    h.on("x", &[exited(0)]);
    assert_eq!(h.status("f() { x; return 3; }; f | x; echo ${PIPESTATUS[*]}"), 0);
    assert_eq!(h.output.text(), "3 0\n");
    assert_eq!(refused(h.run("g() { :; }; n=g; $n | x")), Unsupported::PipelineFunction);
}

// KNSH-103 acceptance: sparse indexed arrays list their indices in order; `+=` appends after the greatest index;
// `[@]`, `[*]`, counts, slices by index and per-element operators match bash (checked against bash 3.2; `^` is
// bash 4).
#[test]
fn sparse_array_indices_listed_in_order() {
    let script = r#"a=(zero one two)
a[10]=ten; a[5]=five
echo "${!a[@]}"
echo "${a[@]}"
echo "${#a[@]} ${#a[10]} ${#a}"
unset 'a[1]'
echo "${!a[*]}"
a+=(eleven)
echo "${!a[@]} last=${a[11]}"
for i in "${!a[@]}"; do printf '%s=%s,' "$i" "${a[$i]}"; done; echo
b=("x y" z); printf '<%s>' "${b[@]}"; printf '<%s>' ${b[@]}; printf '<%s>' "${b[*]}"; echo
IFS=:; echo "${b[*]}"; unset IFS
echo "${a[@]:5:2}" "${a[@]:11}"
c=(abc abd xbc); echo "${c[@]#a}" "${c[@]/b/B}" "${c[@]^}"
d=(); echo "${#d[@]}" "${d[@]-empty}"
e[3]=x; declare -p e
f=(1 2 3); f=([1]=q); declare -p f
i=1; g=([i+1]=two z); declare -p g
s=str; s[2]=two; declare -p s; echo "$s""#;
    assert_eq!(
        output(script),
        "0 1 2 5 10\nzero one two five ten\n5 3 4\n0 2 5 10\n0 2 5 10 11 last=eleven\n\
         0=zero,2=two,5=five,10=ten,11=eleven,\n<x y><z><x><y><z><x y z>\nx y:z\nfive ten eleven\n\
         bc bd xbc aBc aBd xBc Abc Abd Xbc\n0 empty\ndeclare -a e=([3]=\"x\")\ndeclare -a f=([1]=\"q\")\n\
         declare -a g=([2]=\"two\" [3]=\"z\")\ndeclare -a s=([0]=\"str\" [2]=\"two\")\nstr\n"
    );
}

// KNSH-103 acceptance: negative indices read from the end, as bash 5.2 (4.3 and later); one before the first
// element is bash's `bad array subscript`: reported and read as unset, and an assignment abandons the line.
#[test]
fn negative_index_reads_from_end() {
    let (status, out, diagnostics) = outcome(
        "a=(a b c); a[7]=h; echo \"${a[-1]}|${a[-8]}|${a[-2]-unset}|${a[@]: -2}|${a[@]: -9}\"\n\
         echo \"<${a[-9]}>\"; echo st=$?\n\
         a[-1]=H; unset 'a[-8]'; echo \"${a[*]}\"\n\
         a[-9]=x; echo never\n\
         echo $(( a[-1] == 0 )) end",
    );
    assert_eq!(status, 0);
    assert_eq!(out, "h|a|unset|h|\n<>\nst=0\nb c H\n1 end\n");
    assert_eq!(
        diagnostics,
        "knsh: line 2: a: bad array subscript\nknsh: line 4: a[-9]: bad array subscript\n"
    );
}

// KNSH-103 acceptance: associative arrays (bash 4, following 5.2's source): assignment by key, lookup, `+=`, unset,
// counts and the key-value list form; keys are strings, expanded but never evaluated.
#[test]
fn associative_array_assignment_and_lookup() {
    let script = r#"declare -A h=([one]=1 ["two words"]=2)
h[three]=3; k=one; h[$k]+=1
echo "${h[one]}|${h["two words"]}|${h[three]}|${#h[@]}|${h[missing]-none}"
unset 'h[three]'; echo "${#h[@]}"
declare -A kv=(a 1 b 2); echo "${kv[a]}${kv[b]}"
declare -A n; n[1+1]=x; echo "${!n[@]}"
declare -A q; q[z]=1; q[a]=2; q[m]=3
printf '%s=%s ' "${!q[@]}" "${q[@]}"; echo
declare -p q"#;
    // Bash's bucket order for z, a and m (FNV-1 hash of each key modulo 1024).
    let mut keys = ["z", "a", "m"];
    keys.sort_by_key(|key| crate::vars::bash_hash(key.as_bytes()) & 1023);
    let value = |key: &str| match key {
        "z" => "1",
        "a" => "2",
        _ => "3",
    };
    let out = output(script);
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some("11|2|3|3|none"));
    assert_eq!(lines.next(), Some("2"));
    assert_eq!(lines.next(), Some("12"));
    assert_eq!(lines.next(), Some("1+1"));
    // `printf '%s=%s '` takes the keys, then the values, two at a time.
    let args: Vec<&str> = keys.iter().copied().chain(keys.iter().map(|key| value(key))).collect();
    let printed: String = args.chunks(2).flat_map(|pair| [pair[0], "=", pair[1], " "]).collect();
    assert_eq!(lines.next(), Some(printed.as_str()));
    let declared: String = keys
        .iter()
        .flat_map(|key| ["[", key, "]=\"", value(key), "\" "])
        .collect();
    assert_eq!(lines.next(), Some(format!("declare -A q=({declared})").as_str()));
    // An indexed array cannot become associative (bash's message).
    let (_, _, diagnostics) = outcome("a=(1); declare -A a");
    assert_eq!(
        diagnostics,
        "knsh: line 1: declare: a: cannot convert indexed to associative array\n"
    );
}

// KNSH-103 acceptance: a name reference reads, assigns and unsets the variable it names, follows it across scopes,
// and `${!ref}` is the name; `local -n` gives a function its caller's variable (bash 4.3, following 5.2's source).
#[test]
fn nameref_reads_and_writes_target() {
    let script = r#"x=1; declare -n r=x
echo "$r ${!r}"; r=2; echo "$x"
r+=3; echo "$x"
declare -p r
set_it() { local -n out=$1; out=from-function; }
set_it target; echo "$target"
fill() { local -n arr=$1; arr+=(new); arr[0]=first; }
list=(a b); fill list; echo "${list[*]}"
declare -n loose; loose=x; echo "$loose"
unset r; echo "${x-gone}"; declare -p r
[ -R loose ] && echo is-ref"#;
    assert_eq!(
        output(script),
        "1 x\n2\n23\ndeclare -n r=\"x\"\nfrom-function\nfirst b new\n23\ngone\ndeclare -n r=\"x\"\nis-ref\n"
    );
}

// KNSH-103 acceptance: a reference to itself is refused when declared, and a circular chain is bash's warning
// when read (bash 5.2's `nameref variable self references not allowed` and `circular name reference`).
#[test]
fn circular_nameref_is_error() {
    let (status, out, diagnostics) = outcome("declare -n x=x; echo st=$?");
    assert_eq!((status, out.as_str()), (0, "st=1\n"));
    assert_eq!(
        diagnostics,
        "knsh: line 1: declare: x: nameref variable self references not allowed\n"
    );
    let (status, out, diagnostics) = outcome("declare -n a=b; declare -n b=a; echo \"<$a>\"");
    assert_eq!((status, out.as_str()), (0, "<>\n"));
    assert_eq!(diagnostics, "knsh: line 1: warning: a: circular name reference\n");
    // Assigning through a circular chain is refused rather than guessed.
    let mut h = Harness::new();
    assert_eq!(refused(h.run("declare -n a=b b=a; a=1")), Unsupported::Nameref);
    // An invalid target is bash's error.
    let (_, _, diagnostics) = outcome("declare -n r=1x");
    assert_eq!(
        diagnostics,
        "knsh: line 1: declare: `1x': invalid variable name for name reference\n"
    );
}

// `mapfile` (bash 4, following 5.2's source): lines with their newlines, `-t`, `-n`, `-s`, `-O`, `-d`, and the
// default `MAPFILE`.
#[test]
fn mapfile_reads_lines_into_array() {
    let mut h = Harness::new();
    h.fs.write(Path::new("/work/in"), b"one\ntwo\nthree\nfour", 0o644)
        .unwrap();
    h.run(
        "mapfile -t lines < in; echo \"${#lines[@]}:${lines[3]}\"\n\
         mapfile < in; printf '<%s>' \"${MAPFILE[@]}\"; echo\n\
         readarray -t -s 1 -n 2 part < in; echo \"${part[*]}\"\n\
         part=(x y z); mapfile -t -O 5 part < in; echo \"${!part[*]}\"\n\
         mapfile -t -d o by < in; echo \"${#by[@]}:${by[0]}\"",
    )
    .unwrap();
    assert_eq!(
        h.output.text(),
        "4:four\n<one\n><two\n><three\n><four>\ntwo three\n0 1 2 5 6 7 8\n4:\n"
    );
    assert!(h.diagnostics.text().is_empty(), "{}", h.diagnostics.text());
    let (status, _, diagnostics) = outcome("declare -A h; mapfile h < /dev/null");
    assert_eq!(status, 1);
    assert_eq!(diagnostics, "knsh: line 1: mapfile: h: not an indexed array\n");
}

// Integer and case attributes apply to every element; `declare -p` prints arrays as bash 5.2.
#[test]
fn attributes_apply_to_elements() {
    assert_eq!(
        output(
            "declare -ai n=(1+1 3*3); n[2]=4/2; n+=(5); echo ${n[*]}; declare -u up=(a b); echo ${up[@]}; declare -p n"
        ),
        "2 9 2 5\nA B\ndeclare -ai n=([0]=\"2\" [1]=\"9\" [2]=\"2\" [3]=\"5\")\n"
    );
    // Read-only arrays refuse every change.
    let (_, out, diagnostics) = outcome("declare -ra r=(1); r[1]=2; echo no\necho ${r[*]}");
    assert_eq!(out, "1\n");
    assert_eq!(diagnostics, "knsh: line 1: r: readonly variable\n");
}

// Functions defined in `eval` text and sourced files outlive it; arrays are not exported.
#[test]
fn functions_outlive_the_text_that_defined_them() {
    let mut h = Harness::new();
    h.on("env", &[exited(0)]);
    h.run("eval 'e() { echo \"e:$1\"; }'; e one; export arr=(1 2); env")
        .unwrap();
    assert_eq!(h.output.text(), "e:one\n");
    let env = &h.commands.runs()[0].env;
    assert!(!env.iter().any(|(name, _)| name == "arr"), "{env:?}");
}

// Endless recursion at the default nesting limit ends in the limit's error, never a stack overflow: each call
// costs evaluator frames beyond the lists it nests (checked at the limit, in the unoptimised build).
#[test]
fn deep_function_recursion_fails_with_error_not_crash() {
    for script in [
        "f() { f; }; f",
        "f() { local x=$1; if (( x >= 0 )); then f $(( x + 1 )) | tool; fi; }; f 0",
        "f() { local -a a=(\"$@\"); { f \"${a[@]}\" x; } > out; }; f",
    ] {
        let mut h = Harness::new();
        h.on("tool", &[exited(0)]);
        assert!(
            matches!(h.run(script), Err(InterpError::DepthExceeded { .. })),
            "{script}"
        );
    }
}

// Review regression (KNSH-103): bash 5.2 expands an associative array's key-value words as assignment values
// (`assign_assoc_from_kvlist`): never split, never matched against file names; an empty key is refused.
#[test]
fn associative_key_value_words_are_not_split() {
    let mut h = Harness::new();
    h.fs.write(Path::new("/work/kfile"), b"", 0o644).unwrap();
    h.run("v='a b'; declare -A h=($v k*) g=([x]=$v); declare -p h g")
        .unwrap();
    assert_eq!(
        h.output.text(),
        "declare -A h=([\"a b\"]=\"k*\" )\ndeclare -A g=([x]=\"a b\" )\n"
    );
    let mut h = Harness::new();
    assert_eq!(refused(h.run("e=; declare -A h=($e v)")), Unsupported::Array);
}

// Review regression (KNSH-103): `declare -g` assigns the global variable but expands its list where the command
// is, with the function's locals visible, as bash does.
#[test]
fn declare_g_list_sees_the_functions_locals() {
    assert_eq!(
        output("f() { local v=1; declare -ga arr=($v x); }; f; declare -p arr"),
        "declare -a arr=([0]=\"1\" [1]=\"x\")\n"
    );
}

// Review regression (KNSH-103): a function named like a declaration builtin is given its words as bash writes
// them, which a list read apart from its word is not: refused rather than handed `x=` alone.
#[test]
fn a_list_given_to_a_function_named_declare_is_refused() {
    let mut h = Harness::new();
    assert_eq!(
        refused(h.run("declare() { echo \"$@\"; }; declare x=(1 2)")),
        Unsupported::Array
    );
}

// Review regression (KNSH-103): appending to an array keeps its elements without copying them, and a list that
// fails (a negative index before the first element) leaves the array as it was; `mapfile` and `a+=(x)` loops
// stay linear (each used to copy the whole array, so 30,000 lines took minutes).
#[test]
fn appending_lists_is_in_place_and_atomic() {
    assert_eq!(
        output("a=(x); a+=(y [-1]=z w); declare -p a; declare -A h=([a]=1); h+=([b]=2 [a]+=3); echo ${h[a]}${h[b]}"),
        "declare -a a=([0]=\"x\" [1]=\"z\" [2]=\"w\")\n132\n"
    );
    let mut h = Harness::new();
    assert_eq!(refused(h.run("a=(x y); a+=(p [-9]=q)")), Unsupported::Array);
    h.run("declare -p a").unwrap();
    assert_eq!(h.output.text(), "declare -a a=([0]=\"x\" [1]=\"y\")\n");
    let mut h = Harness::new();
    h.fs.write(Path::new("/work/in"), "l\n".repeat(30_000).as_bytes(), 0o644)
        .unwrap();
    h.run("mapfile -t m < in; i=0; while (( i < 10000 )); do a+=(x); i=$((i+1)); done; echo ${#m[@]} ${#a[@]}")
        .unwrap();
    assert_eq!(h.output.text(), "30000 10000\n");
}
