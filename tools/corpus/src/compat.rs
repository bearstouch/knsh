//! Detection of bash constructs that bash 3.2 lacks (NFR-COMPAT-05).
//!
//! macOS ships bash 3.2 as `/bin/bash`, and agent lines run with it unless the profile names another bash. Lines that
//! rely on bash 4 or 5 features fail or behave differently there, so the corpus tags them `b32-missing`. The importer
//! adds the tag automatically and the CI gate refuses an untagged line that [`missing_in_bash32`] flags.
//!
//! This is a textual scan, not a parse: it can flag a construct that only appears inside a quoted string. A false
//! positive costs one extra tag; a false negative only means the tag must be added by hand. Behaviour differences that
//! cannot be seen in the text (for example `set -u` with an empty array) are tagged `b32-differs` by hand.

/// The bash 4+ constructs `command` appears to use, by name, in a fixed order and without duplicates.
///
/// # Example
///
/// ```
/// assert_eq!(knsh_corpus::compat::missing_in_bash32("declare -A seen=()"), ["associative arrays"]);
/// assert!(knsh_corpus::compat::missing_in_bash32("for f in *.rs; do echo \"$f\"; done").is_empty());
/// ```
#[must_use]
pub fn missing_in_bash32(command: &str) -> Vec<&'static str> {
    let words = words(command);
    let mut found = Vec::new();
    let mut add = |name: &'static str| {
        if !found.contains(&name) {
            found.push(name);
        }
    };

    for (at, cmd) in words.iter().enumerate() {
        // Every option word of a declaration builtin counts (`declare -g -A h`), up to `--` or its first operand
        // (KNSH-103); `readonly` takes `-A` too.
        if !matches!(*cmd, "declare" | "local" | "typeset" | "readonly") {
            continue;
        }
        let options = words[at + 1..]
            .iter()
            .take_while(|flags| flags.len() > 1 && flags.starts_with(['-', '+']) && **flags != "--");
        for flags in options {
            if flags.contains('A') {
                add("associative arrays");
            }
            if flags.contains('n') && *cmd != "readonly" {
                add("namerefs");
            }
            if *cmd != "readonly" && (flags.contains('l') || flags.contains('u') || flags.contains('c')) {
                add("case-modifying attributes");
            }
        }
    }
    for pair in words.windows(2) {
        let (cmd, flags) = (pair[0], pair[1]);
        if cmd == "wait" && flags.starts_with('-') && flags.contains('n') {
            add("wait -n");
        }
        if cmd == "[[" && flags == "-v" {
            add("[[ -v ]]");
        }
    }
    for word in &words {
        match *word {
            "mapfile" | "readarray" => add("mapfile/readarray"),
            "coproc" => add("coproc"),
            _ => {}
        }
    }
    for (needle, name) in [
        ("|&", "|& pipe"),
        ("&>>", "&>> append"),
        (";;&", "case fall-through"),
        ("globstar", "globstar"),
        ("lastpipe", "lastpipe"),
        ("EPOCHSECONDS", "bash 5 variables"),
        ("EPOCHREALTIME", "bash 5 variables"),
        ("SRANDOM", "bash 5 variables"),
        ("BASHPID", "BASHPID"),
        ("%(", "printf %(…)T"),
    ] {
        if command.contains(needle) && (needle != "%(" || command.contains(")T")) {
            add(name);
        }
    }
    // `;&` on its own (not the tail of `;;&`) is also bash 4 fall-through.
    if command
        .match_indices(";&")
        .any(|(i, _)| i == 0 || command.as_bytes()[i - 1] != b';')
    {
        add("case fall-through");
    }
    for name in expansion_features(command) {
        add(name);
    }
    for name in brace_features(command) {
        add(name);
    }
    found
}

/// Splits on whitespace and on the separators that start a new simple command, so `x; mapfile` yields `mapfile`.
fn words(command: &str) -> Vec<&str> {
    command
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')' | '{' | '}' | '`'))
        .filter(|w| !w.is_empty())
        .collect()
}

/// Features inside `${…}`: case modification (`${x,,}`, `${x^}`), transformations (`${x@Q}`) and negative
/// subscripts (`${a[-1]}`).
fn expansion_features(command: &str) -> Vec<&'static str> {
    let bytes = command.as_bytes();
    let mut found = Vec::new();
    for (start, _) in command.match_indices("${") {
        let mut i = start + 2;
        // `${!x}` and `${#x}` prefixes do not change what follows the name.
        if matches!(bytes.get(i), Some(b'!' | b'#')) {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        if i == name_start {
            continue;
        }
        if bytes.get(i) == Some(&b'[') {
            if bytes.get(i + 1) == Some(&b'-') && bytes.get(i + 2).is_some_and(u8::is_ascii_digit) {
                found.push("negative array subscript");
            }
            while i < bytes.len() && bytes[i] != b']' {
                i += 1;
            }
            i += 1;
        }
        match bytes.get(i) {
            Some(b',' | b'^') => found.push("case-modification expansion"),
            Some(b'@')
                if bytes.get(i + 1).is_some_and(|b| b"QEPAaKkUuL".contains(b)) && bytes.get(i + 2) == Some(&b'}') =>
            {
                found.push("parameter transformation");
            }
            _ => {}
        }
    }
    found
}

/// Brace expansion forms added in bash 4: a step (`{1..10..2}`) and zero padding (`{01..10}`).
fn brace_features(command: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    for (start, _) in command.match_indices('{') {
        let rest = &command[start + 1..];
        let Some(end) = rest.find('}') else { continue };
        let parts: Vec<&str> = rest[..end].split("..").collect();
        let simple = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if parts.len() < 2 || parts.len() > 3 || !parts.iter().all(|p| simple(p)) {
            continue;
        }
        if parts.len() == 3 {
            found.push("brace expansion step");
        }
        let zero_padded = |p: &str| {
            let digits = p.trim_start_matches('-');
            digits.len() > 1 && digits.starts_with('0') && digits.bytes().all(|b| b.is_ascii_digit())
        };
        if zero_padded(parts[0]) || zero_padded(parts[1]) {
            found.push("zero-padded brace expansion");
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::missing_in_bash32;

    // NFR-COMPAT-05.
    #[test]
    fn flags_bash4_constructs() {
        for (line, construct) in [
            ("declare -A m=([a]=1)", "associative arrays"),
            ("local -n ref=$1", "namerefs"),
            ("declare -g -A cache", "associative arrays"),
            ("readonly -A table=([k]=v)", "associative arrays"),
            ("typeset +x -n r=x", "namerefs"),
            ("mapfile -t lines < f", "mapfile/readarray"),
            ("x=1; readarray a < f", "mapfile/readarray"),
            ("echo \"${name,,}\"", "case-modification expansion"),
            ("echo \"${arr[0]^^}\"", "case-modification expansion"),
            ("echo \"${v@Q}\"", "parameter transformation"),
            ("echo \"${a[-1]}\"", "negative array subscript"),
            ("make |& tee log", "|& pipe"),
            ("cmd &>> log", "&>> append"),
            ("case $x in a) echo;;& b) echo;; esac", "case fall-through"),
            ("case $x in a) echo;& b) echo;; esac", "case fall-through"),
            ("shopt -s globstar; ls **/*.rs", "globstar"),
            ("coproc cat", "coproc"),
            ("echo $EPOCHSECONDS", "bash 5 variables"),
            ("wait -n", "wait -n"),
            ("[[ -v HOME ]] && echo set", "[[ -v ]]"),
            ("echo {1..10..2}", "brace expansion step"),
            ("touch file{01..10}.txt", "zero-padded brace expansion"),
            ("printf '%(%F)T\\n' -1", "printf %(…)T"),
        ] {
            assert!(
                missing_in_bash32(line).contains(&construct),
                "{line:?} should flag {construct}"
            );
        }
    }

    #[test]
    fn keeps_bash32_constructs() {
        for line in [
            "declare -a arr=(1 2)",
            "local -r x=1",
            "echo \"${arr[@]}\" \"${#arr[@]}\" \"${!arr[@]}\"",
            "echo {1..10} {a..z} {foo,bar}",
            "x+=(y); echo ${x[1]} ${PATH//:/ } ${v:-d} ${v#*/}",
            "find . -name '*.rs' -exec grep -l foo {} +",
            "printf '%s\\n' \"$x\"",
            "a && b || c; d & wait",
        ] {
            assert_eq!(missing_in_bash32(line), Vec::<&str>::new(), "{line:?}");
        }
    }
}
