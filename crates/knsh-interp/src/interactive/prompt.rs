//! Decoding the backslash escapes of `PS1`, `PS2` and `PS4` as bash's `decode_prompt_string` (KNSH-107).
//!
//! | Escape | Meaning |
//! | --- | --- |
//! | `\a` `\e` `\n` `\r` `\\` | bell, escape, newline, carriage return, backslash |
//! | `\d` | the date, `Sat Nov 21` (`%a %b %d`) |
//! | `\D{format}` | `strftime(format)`; an empty format is the locale's time (`%X`) |
//! | `\t` `\T` `\@` `\A` | the time: `%H:%M:%S`, `%I:%M:%S`, `%I:%M %p`, `%H:%M` |
//! | `\h` `\H` | the host name up to its first `.`, and whole |
//! | `\u` | the user's login name |
//! | `\w` `\W` | the working directory (`$HOME` as `~`, cut to `PROMPT_DIRTRIM` components), and its base name |
//! | `\s` `\v` `\V` | the shell's name (base name of `$0`), version (`5.2`) and release (`5.2.0`) |
//! | `\j` `\l` | the number of jobs, the terminal's base name |
//! | `\!` `\#` | the history number and the command number of this command |
//! | `\$` | `#` for the superuser, `$` otherwise |
//! | `\nnn` | the byte with octal value `nnn` |
//! | `\[` `\]` | start and end of characters that take no column ([`IGNORE_START`], [`IGNORE_END`]) |
//!
//! Any other backslash is kept with the character after it. With `promptvars` (bash's default) the result is then
//! expanded as a here-document is (parameter, command and arithmetic substitution) by
//! [`Interpreter::expand_prompt`](crate::Interpreter::expand_prompt); so that what an escape produced is not
//! expanded again, `$`, `` ` `` and `\` in it are quoted with a backslash first, as bash quotes them.

use super::render::{IGNORE_END, IGNORE_START};

/// What the escapes of a prompt show, gathered by the session before each prompt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptInfo {
    /// The host's name (`\H`).
    pub host: String,
    /// The user's login name (`\u`).
    pub user: String,
    /// The terminal's base name (`\l`), `tty` when unknown, as bash.
    pub terminal: String,
    /// The shell's name, the base name of `$0` (`\s`).
    pub shell: String,
    /// The working directory (`\w`, `\W`), as `$PWD` shows it.
    pub cwd: String,
    /// `$HOME`, for `~` in `\w` and `\W`.
    pub home: Option<String>,
    /// `PROMPT_DIRTRIM`: how many trailing directories `\w` keeps.
    pub dirtrim: Option<usize>,
    /// The number of jobs (`\j`).
    pub jobs: usize,
    /// The history number of this command (`\!`).
    pub history_number: usize,
    /// The command number of this command (`\#`).
    pub command_number: usize,
    /// The shell runs as the superuser (`\$`).
    pub superuser: bool,
}

/// The parts of the time the time escapes need, formatted by the host's `strftime`.
pub trait PromptClock {
    /// `strftime(format)` of the current local time; empty when it cannot be formatted.
    fn format(&self, format: &str) -> String;
}

/// Bash's version as `\v` and `\V` show it, matching the bash 5.2 the interpreter follows.
const VERSION: &str = "5.2";

/// Bash's release as `\V` shows it.
const RELEASE: &str = "5.2.0";

/// `text` with `$`, `` ` `` and `\` quoted by a backslash (and `"` too: bash's
/// `sh_backslash_quote_for_double_quotes` leaves no character that the expansion would read differently).
fn quoted(text: &str, quote: bool) -> String {
    if !quote {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(ch, '$' | '`' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// `\w`: the working directory with `$HOME` as `~` and, with `PROMPT_DIRTRIM`, only the last components after
/// `...`.
fn working_directory(info: &PromptInfo) -> String {
    let cwd = info.cwd.as_str();
    let (prefix, rest) = match info.home.as_deref().filter(|home| !home.is_empty() && *home != "/") {
        Some(home) if cwd == home => return "~".to_owned(),
        Some(home) if cwd.starts_with(home) && cwd[home.len()..].starts_with('/') => ("~", &cwd[home.len()..]),
        _ => ("", cwd),
    };
    let Some(keep) = info.dirtrim.filter(|keep| *keep > 0) else {
        return format!("{prefix}{rest}");
    };
    let parts: Vec<&str> = rest.split('/').filter(|part| !part.is_empty()).collect();
    if parts.len() <= keep {
        return format!("{prefix}{rest}");
    }
    format!("{prefix}/.../{}", parts[parts.len() - keep..].join("/"))
}

/// `\W`: the base name of the working directory, `~` for `$HOME`.
fn base_directory(info: &PromptInfo) -> String {
    let cwd = info.cwd.as_str();
    if info.home.as_deref().is_some_and(|home| home == cwd && !home.is_empty()) {
        return "~".to_owned();
    }
    if cwd == "/" {
        return "/".to_owned();
    }
    cwd.trim_end_matches('/').rsplit('/').next().unwrap_or(cwd).to_owned()
}

/// `prompt` with its escapes decoded; with `promptvars` what they produced is quoted for the expansion that follows.
#[must_use]
pub fn decode(prompt: &str, info: &PromptInfo, clock: &dyn PromptClock, promptvars: bool) -> String {
    let mut out = String::with_capacity(prompt.len());
    let mut chars = prompt.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let Some(escape) = chars.next() else {
            out.push('\\');
            break;
        };
        let piece = |text: &str| quoted(text, promptvars);
        match escape {
            'a' => out.push('\u{7}'),
            'e' => out.push('\u{1b}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            '\\' => out.push_str(if promptvars { "\\\\" } else { "\\" }),
            '[' => out.push(IGNORE_START),
            ']' => out.push(IGNORE_END),
            'd' => out.push_str(&piece(&clock.format("%a %b %d"))),
            't' => out.push_str(&piece(&clock.format("%H:%M:%S"))),
            'T' => out.push_str(&piece(&clock.format("%I:%M:%S"))),
            '@' => out.push_str(&piece(&clock.format("%I:%M %p"))),
            'A' => out.push_str(&piece(&clock.format("%H:%M"))),
            'D' if chars.peek() == Some(&'{') => {
                chars.next();
                let mut format = String::new();
                let mut closed = false;
                for inner in chars.by_ref() {
                    if inner == '}' {
                        closed = true;
                        break;
                    }
                    format.push(inner);
                }
                if closed {
                    let format = if format.is_empty() { "%X".to_owned() } else { format };
                    out.push_str(&piece(&clock.format(&format)));
                } else {
                    // Bash keeps an unclosed `\D{` as written.
                    out.push_str("\\D{");
                    out.push_str(&format);
                }
            }
            'h' => out.push_str(&piece(info.host.split('.').next().unwrap_or(""))),
            'H' => out.push_str(&piece(&info.host)),
            'u' => out.push_str(&piece(&info.user)),
            'w' => out.push_str(&piece(&working_directory(info))),
            'W' => out.push_str(&piece(&base_directory(info))),
            's' => out.push_str(&piece(info.shell.rsplit('/').next().unwrap_or(&info.shell))),
            'v' => out.push_str(VERSION),
            'V' => out.push_str(RELEASE),
            'j' => out.push_str(&info.jobs.to_string()),
            'l' => out.push_str(&piece(&info.terminal)),
            '!' => out.push_str(&info.history_number.to_string()),
            '#' => out.push_str(&info.command_number.to_string()),
            '$' => out.push_str(match (info.superuser, promptvars) {
                (true, _) => "#",
                (false, true) => "\\$",
                (false, false) => "$",
            }),
            '0'..='7' => {
                let mut value = escape.to_digit(8).unwrap_or(0);
                for _ in 0..2 {
                    match chars.peek().and_then(|next| next.to_digit(8)) {
                        Some(digit) => {
                            value = value * 8 + digit;
                            chars.next();
                        }
                        None => break,
                    }
                }
                let byte = u8::try_from(value & 0xFF).unwrap_or(0);
                // A byte outside ASCII cannot stand alone in the prompt text; bash writes it raw.
                out.push(if byte.is_ascii() {
                    char::from(byte)
                } else {
                    char::REPLACEMENT_CHARACTER
                });
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedClock;

    impl PromptClock for FixedClock {
        fn format(&self, format: &str) -> String {
            match format {
                "%a %b %d" => "Sat Nov 21".into(),
                "%H:%M:%S" | "%X" => "22:04:44".into(),
                "%I:%M:%S" => "10:04:44".into(),
                "%I:%M %p" => "10:04 PM".into(),
                "%H:%M" => "22:04".into(),
                "%Y" => "2026".into(),
                other => format!("<{other}>"),
            }
        }
    }

    fn info() -> PromptInfo {
        PromptInfo {
            host: "mac.local".into(),
            user: "ana".into(),
            terminal: "ttys003".into(),
            shell: "/usr/local/bin/knsh".into(),
            cwd: "/Users/ana/src/knsh".into(),
            home: Some("/Users/ana".into()),
            dirtrim: None,
            jobs: 2,
            history_number: 41,
            command_number: 7,
            superuser: false,
        }
    }

    fn plain(prompt: &str) -> String {
        decode(prompt, &info(), &FixedClock, false)
    }

    // KNSH-107: every escape bash's `decode_prompt_string` knows, with bash's results (bash 5.2 manual, PROMPTING;
    // `\u \h \w \$` checked against bash 3.2's `${PS1@P}`-less `bash -i` prompt).
    #[test]
    fn ps1_escapes_expand_like_bash() {
        assert_eq!(plain("\\u@\\h:\\w\\$ "), "ana@mac:~/src/knsh$ ");
        assert_eq!(plain("\\H \\W \\s \\v \\V"), "mac.local knsh knsh 5.2 5.2.0");
        assert_eq!(
            plain("\\d|\\t|\\T|\\@|\\A|\\D{%Y}|\\D{}"),
            "Sat Nov 21|22:04:44|10:04:44|10:04 PM|22:04|2026|22:04:44"
        );
        assert_eq!(plain("\\j \\l \\! \\#"), "2 ttys003 41 7");
        assert_eq!(plain("\\a\\e\\n\\r\\\\"), "\u{7}\u{1b}\n\r\\");
        assert_eq!(plain("\\101\\0412"), "A!2");
        assert_eq!(plain("\\[\\e[1m\\]x"), "\u{1}\u{1b}[1m\u{2}x");
        assert_eq!(plain("\\q \\"), "\\q \\");
        assert_eq!(plain("\\D{%Y"), "\\D{%Y");
        let root = PromptInfo {
            superuser: true,
            ..info()
        };
        assert_eq!(decode("\\$", &root, &FixedClock, false), "#");
    }

    #[test]
    fn working_directory_follows_home_and_dirtrim() {
        let at = |cwd: &str, dirtrim: Option<usize>| {
            let info = PromptInfo {
                cwd: cwd.into(),
                dirtrim,
                ..info()
            };
            (working_directory(&info), base_directory(&info))
        };
        assert_eq!(at("/Users/ana", None), ("~".into(), "~".into()));
        assert_eq!(at("/Users/anabel", None), ("/Users/anabel".into(), "anabel".into()));
        assert_eq!(at("/", None), ("/".into(), "/".into()));
        assert_eq!(at("/Users/ana/a/b/c/d", Some(2)), ("~/.../c/d".into(), "d".into()));
        assert_eq!(
            at("/usr/local/share/man", Some(2)),
            ("/.../share/man".into(), "man".into())
        );
    }

    #[test]
    fn promptvars_quotes_what_escapes_produce() {
        let info = PromptInfo {
            cwd: "/tmp/$(rm -rf x)".into(),
            ..info()
        };
        assert_eq!(
            decode("\\w \\$ $X", &info, &FixedClock, true),
            "/tmp/\\$(rm -rf x) \\$ $X"
        );
    }
}
