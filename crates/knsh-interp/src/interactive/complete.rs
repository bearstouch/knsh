//! Programmable completion's model and its pure parts (KNSH-107): the completion specifications `complete`
//! defines ([`CompSpec`]), the word being completed, how a match is quoted when inserted, the common prefix of the
//! matches and readline's column listing.
//!
//! What the matches are (files, commands, variables, a function's `COMPREPLY`) needs the shell, so it is generated
//! by the interpreter (`Interpreter::complete`, the `compgen` builtin).

use std::fmt::Write as _;

use super::width::str_width;

/// What a completion specification generates (`complete -A action` and its letters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CompAction {
    /// `-a`: aliases.
    Alias,
    /// `-b`: builtins.
    Builtin,
    /// `-c`: command names.
    Command,
    /// `-d`: directories.
    Directory,
    /// `-e`: exported variables.
    Export,
    /// `-f`: file names.
    File,
    /// `-j`: job names.
    Job,
    /// `-k`: reserved words.
    Keyword,
    /// `-v`: variables.
    Variable,
    /// `-A arrayvar`.
    ArrayVar,
    /// `-A disabled`: disabled builtins (there are none).
    Disabled,
    /// `-A enabled`: enabled builtins.
    Enabled,
    /// `-A function`.
    Function,
    /// `-A helptopic`: what `help` knows, the builtins.
    HelpTopic,
    /// `-A running`: running jobs.
    Running,
    /// `-A setopt`: `set -o` names.
    SetOpt,
    /// `-A shopt`: `shopt` names.
    Shopt,
    /// `-A signal`: signal names.
    Signal,
    /// `-A stopped`: stopped jobs.
    Stopped,
}

/// The actions with a letter of their own, in the order bash prints them, then those named with `-A`.
const ACTIONS: &[(CompAction, Option<char>, &str)] = &[
    (CompAction::Alias, Some('a'), "alias"),
    (CompAction::Builtin, Some('b'), "builtin"),
    (CompAction::Command, Some('c'), "command"),
    (CompAction::Directory, Some('d'), "directory"),
    (CompAction::Export, Some('e'), "export"),
    (CompAction::File, Some('f'), "file"),
    (CompAction::Job, Some('j'), "job"),
    (CompAction::Keyword, Some('k'), "keyword"),
    (CompAction::Variable, Some('v'), "variable"),
    (CompAction::ArrayVar, None, "arrayvar"),
    (CompAction::Disabled, None, "disabled"),
    (CompAction::Enabled, None, "enabled"),
    (CompAction::Function, None, "function"),
    (CompAction::HelpTopic, None, "helptopic"),
    (CompAction::Running, None, "running"),
    (CompAction::SetOpt, None, "setopt"),
    (CompAction::Shopt, None, "shopt"),
    (CompAction::Signal, None, "signal"),
    (CompAction::Stopped, None, "stopped"),
];

/// Actions bash has that are not supported here: the user, group, host and service databases and key bindings.
const UNSUPPORTED_ACTIONS: &[(Option<char>, &str)] = &[
    (Some('g'), "group"),
    (Some('s'), "service"),
    (Some('u'), "user"),
    (None, "binding"),
    (None, "hostname"),
];

/// `complete -o` options, in the order bash prints them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Bash's `COPT_*` bits.
pub struct CompOptions {
    /// `bashdefault`: the shell's default completions when nothing matches.
    pub bashdefault: bool,
    /// `default`: file names when nothing matches.
    pub default: bool,
    /// `dirnames`: directory names when nothing matches.
    pub dirnames: bool,
    /// `filenames`: the matches are file names (quoted, `/` after directories).
    pub filenames: bool,
    /// `noquote`: the matches are not quoted.
    pub noquote: bool,
    /// `nosort`: the matches are not sorted.
    pub nosort: bool,
    /// `nospace`: no space after a single match.
    pub nospace: bool,
    /// `plusdirs`: directory names are added to the matches.
    pub plusdirs: bool,
}

impl CompOptions {
    /// The option `name` set to `on`: `false` for a name bash does not have.
    pub fn set(&mut self, name: &str, on: bool) -> bool {
        let field = match name {
            "bashdefault" => &mut self.bashdefault,
            "default" => &mut self.default,
            "dirnames" => &mut self.dirnames,
            "filenames" => &mut self.filenames,
            "noquote" => &mut self.noquote,
            "nosort" => &mut self.nosort,
            "nospace" => &mut self.nospace,
            "plusdirs" => &mut self.plusdirs,
            _ => return false,
        };
        *field = on;
        true
    }

    /// The names of the options on, in bash's order.
    fn names(self) -> Vec<&'static str> {
        [
            (self.bashdefault, "bashdefault"),
            (self.default, "default"),
            (self.dirnames, "dirnames"),
            (self.filenames, "filenames"),
            (self.noquote, "noquote"),
            (self.nosort, "nosort"),
            (self.nospace, "nospace"),
            (self.plusdirs, "plusdirs"),
        ]
        .into_iter()
        .filter_map(|(on, name)| on.then_some(name))
        .collect()
    }
}

/// One completion specification (`complete … name`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompSpec {
    /// The actions, each once, in the order given.
    pub actions: Vec<CompAction>,
    /// `-o` options.
    pub options: CompOptions,
    /// `-W wordlist`, expanded when completing.
    pub wordlist: Option<String>,
    /// `-F function`.
    pub function: Option<String>,
    /// `-C command`: kept and listed, refused when completing.
    pub command: Option<String>,
    /// `-G globpat`: kept and listed, refused when completing.
    pub glob: Option<String>,
    /// `-X filterpat`.
    pub filter: Option<String>,
    /// `-P prefix`.
    pub prefix: Option<String>,
    /// `-S suffix`.
    pub suffix: Option<String>,
}

/// Every specification `complete` defined: by command name, and bash 5's `-D` (default), `-E` (empty line) and
/// `-I` (first word) ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompletionTable {
    /// By command name.
    pub by_command: std::collections::BTreeMap<String, CompSpec>,
    /// `complete -D`.
    pub default: Option<CompSpec>,
    /// `complete -E`.
    pub empty: Option<CompSpec>,
    /// `complete -I`.
    pub initial: Option<CompSpec>,
}

/// Why `complete` or `compgen` arguments were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecError {
    /// An option letter they do not take: bash's `-x: invalid option` and the usage line.
    InvalidOption(char),
    /// An option without its argument: `-W: option requires an argument`.
    MissingArgument(char),
    /// `-A name` with an action bash does not have: `name: invalid action name`.
    InvalidAction(String),
    /// `-o name` with an option bash does not have: `name: invalid option name`.
    InvalidOptionName(String),
    /// An action bash has that is not supported here.
    UnsupportedAction(String),
}

/// What `complete` or `compgen` was asked to do, besides the specification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Bash's `complete` flags.
pub struct SpecRequest {
    /// The specification the options describe.
    pub spec: CompSpec,
    /// `-p`: print.
    pub print: bool,
    /// `-r`: remove.
    pub remove: bool,
    /// `-D`: the default specification (commands without one of their own).
    pub default: bool,
    /// `-E`: the specification for an empty line.
    pub empty: bool,
    /// `-I`: the specification for the first word.
    pub initial: bool,
    /// The operands: command names for `complete`, the word for `compgen`.
    pub operands: Vec<String>,
}

/// Parses the options of `complete` (`compgen: false`) or `compgen`, as bash's `build_actions`.
///
/// # Errors
///
/// A [`SpecError`] as bash reports it.
pub fn parse_spec(args: &[String], compgen: bool) -> Result<SpecRequest, SpecError> {
    let mut request = SpecRequest::default();
    let mut index = 0;
    let push = |actions: &mut Vec<CompAction>, action: CompAction| {
        if !actions.contains(&action) {
            actions.push(action);
        }
    };
    while let Some(arg) = args.get(index) {
        if arg == "--" {
            index += 1;
            break;
        }
        if !arg.starts_with('-') || arg.len() < 2 {
            break;
        }
        index += 1;
        let letters: Vec<char> = arg.chars().skip(1).collect();
        for (at, &letter) in letters.iter().enumerate() {
            let takes_argument = matches!(letter, 'o' | 'A' | 'G' | 'W' | 'F' | 'C' | 'X' | 'P' | 'S');
            if takes_argument {
                let rest: String = letters[at + 1..].iter().collect();
                let value = if rest.is_empty() {
                    let value = args.get(index).cloned().ok_or(SpecError::MissingArgument(letter))?;
                    index += 1;
                    value
                } else {
                    rest
                };
                let spec = &mut request.spec;
                match letter {
                    'o' => {
                        if !spec.options.set(&value, true) {
                            return Err(SpecError::InvalidOptionName(value));
                        }
                    }
                    'A' => {
                        if let Some((action, _, _)) = ACTIONS.iter().find(|(_, _, name)| *name == value) {
                            push(&mut spec.actions, *action);
                        } else if UNSUPPORTED_ACTIONS.iter().any(|(_, name)| *name == value) {
                            return Err(SpecError::UnsupportedAction(value));
                        } else {
                            return Err(SpecError::InvalidAction(value));
                        }
                    }
                    'G' => spec.glob = Some(value),
                    'W' => spec.wordlist = Some(value),
                    'F' => spec.function = Some(value),
                    'C' => spec.command = Some(value),
                    'X' => spec.filter = Some(value),
                    'P' => spec.prefix = Some(value),
                    _ => spec.suffix = Some(value),
                }
                break;
            }
            match letter {
                'p' if !compgen => request.print = true,
                'r' if !compgen => request.remove = true,
                'D' if !compgen => request.default = true,
                'E' if !compgen => request.empty = true,
                'I' if !compgen => request.initial = true,
                _ => {
                    if let Some((action, _, _)) = ACTIONS.iter().find(|(_, short, _)| *short == Some(letter)) {
                        push(&mut request.spec.actions, *action);
                    } else if let Some((_, name)) = UNSUPPORTED_ACTIONS.iter().find(|(short, _)| *short == Some(letter))
                    {
                        return Err(SpecError::UnsupportedAction((*name).to_owned()));
                    } else {
                        return Err(SpecError::InvalidOption(letter));
                    }
                }
            }
        }
    }
    request.operands = args[index.min(args.len())..].to_vec();
    Ok(request)
}

/// `text` in single quotes, as bash's `sh_single_quote`.
fn single_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// `spec` for `name` as `complete -p` prints it, without the newline.
#[must_use]
pub fn print_spec(spec: &CompSpec, name: &str) -> String {
    let mut out = String::from("complete");
    for option in spec.options.names() {
        let _ = write!(out, " -o {option}");
    }
    for (action, short, long) in ACTIONS {
        if spec.actions.contains(action) {
            match short {
                Some(letter) => {
                    let _ = write!(out, " -{letter}");
                }
                None => {
                    let _ = write!(out, " -A {long}");
                }
            }
        }
    }
    let quoted = [
        ('G', &spec.glob),
        ('W', &spec.wordlist),
        ('P', &spec.prefix),
        ('S', &spec.suffix),
        ('X', &spec.filter),
    ];
    for (letter, value) in quoted {
        if let Some(value) = value {
            let _ = write!(out, " -{letter} {}", single_quote(value));
        }
    }
    if let Some(function) = &spec.function {
        let _ = write!(out, " -F {function}");
    }
    if let Some(command) = &spec.command {
        let _ = write!(out, " -C {}", single_quote(command));
    }
    if !name.is_empty() {
        let _ = write!(out, " {name}");
    }
    out
}

/// The word being completed: where it starts, its text with quoting removed, and the quote left open before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    /// Byte offset of the word's start in the line (after an opening quote, which is kept).
    pub start: usize,
    /// The word as typed, from `start` to the cursor.
    pub typed: String,
    /// The word with backslashes and quotes removed.
    pub text: String,
    /// The quote open at the cursor, if any.
    pub quote: Option<char>,
}

/// Characters that end a word for completion, as bash's default `COMP_WORDBREAKS` (`"'><=;|&(:` and blanks).
fn breaks_word(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '>' | '<' | '=' | ';' | '|' | '&' | '(' | ':')
}

/// The word before byte `cursor` of `line`.
#[must_use]
pub fn word_at(line: &str, cursor: usize) -> Word {
    let before = &line[..cursor];
    let mut start = 0;
    let mut quote: Option<char> = None;
    let mut chars = before.char_indices();
    while let Some((at, ch)) = chars.next() {
        match quote {
            Some(open) if ch == open => quote = None,
            Some('"') | None if ch == '\\' => {
                chars.next();
            }
            None if ch == '\'' || ch == '"' => {
                quote = Some(ch);
                // A quote opening a word starts it after the quote.
                if at == start || before[..at].ends_with(breaks_word) {
                    start = at + 1;
                }
            }
            None if breaks_word(ch) => start = at + ch.len_utf8(),
            Some(_) | None => {}
        }
    }
    let typed = before[start..].to_owned();
    Word {
        start,
        text: dequote(&typed, quote),
        typed,
        quote,
    }
}

/// `typed` with backslashes and quotes removed (`open`: inside that quote from the start).
fn dequote(typed: &str, open: Option<char>) -> String {
    let mut out = String::with_capacity(typed.len());
    let mut quote = open;
    let mut chars = typed.chars().peekable();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(q), _) if ch == q => quote = None,
            (Some('"'), '\\') if chars.peek().is_some_and(|next| matches!(next, '"' | '\\' | '$' | '`')) => {
                out.extend(chars.next());
            }
            (None, '\\') => out.extend(chars.next()),
            (None, '\'' | '"') => quote = Some(ch),
            (Some(_) | None, _) => out.push(ch),
        }
    }
    out
}

/// Characters readline quotes with a backslash in a file name (bash's `default_filename_quote_characters`).
fn needs_backslash(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '\\' | '"'
                | '\''
                | '@'
                | '<'
                | '>'
                | '='
                | ';'
                | '|'
                | '&'
                | '('
                | ')'
                | '#'
                | '$'
                | '`'
                | '?'
                | '*'
                | '['
                | '!'
                | ':'
                | '{'
        )
}

/// `text` quoted for insertion: inside `quote` only that quote is escaped; otherwise special characters get a
/// backslash.
#[must_use]
pub fn quote_match(text: &str, quote: Option<char>) -> String {
    let mut out = String::with_capacity(text.len() + 4);
    match quote {
        Some('\'') => {
            out.push_str(&text.replace('\'', "'\\''"));
        }
        Some(_) => {
            for ch in text.chars() {
                if matches!(ch, '"' | '\\' | '$' | '`') {
                    out.push('\\');
                }
                out.push(ch);
            }
        }
        None => {
            for ch in text.chars() {
                if needs_backslash(ch) {
                    out.push('\\');
                }
                out.push(ch);
            }
        }
    }
    out
}

/// The longest prefix every match shares (whole characters).
#[must_use]
pub fn common_prefix(matches: &[String]) -> String {
    let Some(first) = matches.first() else {
        return String::new();
    };
    let mut end = first.len();
    for other in &matches[1..] {
        end = first
            .char_indices()
            .zip(other.chars())
            .find(|((_, a), b)| a != b)
            .map_or(end.min(other.len()), |((at, _), _)| at.min(end));
    }
    first[..end].to_owned()
}

/// Readline's listing of `matches` in columns on a terminal `columns` wide: sorted down each column, each entry
/// padded to the widest plus two, one line per row (`\r\n`).
#[must_use]
pub fn columns_listing(matches: &[String], columns: usize) -> String {
    let widest = matches.iter().map(|entry| str_width(entry)).max().unwrap_or(0) + 2;
    let mut per_row = (columns / widest).max(1);
    // Readline leaves the last column free when the entries would fill the row exactly.
    if per_row > 1 && per_row * widest == columns {
        per_row -= 1;
    }
    let rows = matches.len().div_ceil(per_row);
    let mut out = String::new();
    for row in 0..rows {
        let mut index = row;
        while index < matches.len() {
            let entry = &matches[index];
            let next = index + rows;
            out.push_str(entry);
            if next < matches.len() {
                out.push_str(&" ".repeat(widest - str_width(entry)));
            }
            index = next;
        }
        out.push_str("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    // KNSH-107: `complete -p` prints a specification as bash does (checked against bash 3.2's output).
    #[test]
    fn specifications_print_like_bash() {
        let request = parse_spec(
            &strings(&[
                "-W", "a b", "-o", "nospace", "-o", "default", "-X", "!*.c", "-P", "pre", "-S", "suf", "-F", "fn",
                "-A", "function", "-d", "-c", "foo", "bar",
            ]),
            false,
        )
        .unwrap();
        assert_eq!(request.operands, ["foo", "bar"]);
        assert_eq!(
            print_spec(&request.spec, "foo"),
            "complete -o default -o nospace -c -d -A function -W 'a b' -P 'pre' -S 'suf' -X '!*.c' -F fn foo"
        );
        assert_eq!(parse_spec(&strings(&["-Q"]), false), Err(SpecError::InvalidOption('Q')));
        assert_eq!(
            parse_spec(&strings(&["-W"]), false),
            Err(SpecError::MissingArgument('W'))
        );
        assert_eq!(
            parse_spec(&strings(&["-A", "nope"]), false),
            Err(SpecError::InvalidAction("nope".into()))
        );
        assert_eq!(
            parse_spec(&strings(&["-u"]), true),
            Err(SpecError::UnsupportedAction("user".into()))
        );
        assert_eq!(parse_spec(&strings(&["-p"]), true), Err(SpecError::InvalidOption('p')));
        let request = parse_spec(&strings(&["-pr", "x"]), false).unwrap();
        assert!(request.print && request.remove);
    }

    #[test]
    fn words_end_at_breaks_and_open_quotes() {
        let word = word_at("ls /usr/lo", 10);
        assert_eq!((word.start, word.text.as_str(), word.quote), (3, "/usr/lo", None));
        let word = word_at("cat 'my fi", 10);
        assert_eq!((word.start, word.text.as_str(), word.quote), (5, "my fi", Some('\'')));
        let word = word_at("cat my\\ fi", 10);
        assert_eq!((word.start, word.text.as_str()), (4, "my fi"));
        let word = word_at("X=/tm", 5);
        assert_eq!((word.start, word.text.as_str()), (2, "/tm"));
        assert_eq!(word_at("echo ", 5).text, "");
    }

    #[test]
    fn matches_are_quoted_for_where_they_go() {
        assert_eq!(quote_match("my file(1)", None), "my\\ file\\(1\\)");
        assert_eq!(quote_match("~/a b", None), "~/a\\ b");
        assert_eq!(quote_match("it's", Some('\'')), "it'\\''s");
        assert_eq!(quote_match("a\"$b", Some('"')), "a\\\"\\$b");
    }

    // KNSH-107: the listing readline prints for ambiguous completions.
    #[test]
    fn listing_and_common_prefix() {
        let matches = strings(&["alpha", "alps", "also", "beta", "b"]);
        assert_eq!(common_prefix(&matches[..3]), "al");
        assert_eq!(common_prefix(&strings(&["日本", "日本語"])), "日本");
        assert_eq!(common_prefix(&[]), "");
        assert_eq!(columns_listing(&matches, 20), "alpha  beta\r\nalps   b\r\nalso\r\n");
        assert_eq!(columns_listing(&matches, 21), "alpha  beta\r\nalps   b\r\nalso\r\n");
        assert_eq!(columns_listing(&matches, 5), "alpha\r\nalps\r\nalso\r\nbeta\r\nb\r\n");
    }
}
