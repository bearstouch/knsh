//! Command rule matching and precedence (KNSH-040; FR-POL-13 to FR-POL-17).
//!
//! [`evaluate_command`] decides one classified simple command against a resolved profile's `exec.allow`,
//! `exec.ask`, `exec.deny`, `exec.project_executables` and `exec.default`, and names the rule that decided it
//! ([`RuleId`]). It is pure: the same profile and command always give the same verdict.
//!
//! # Who rules can name
//!
//! Rules name programs (FR-POL-13), so what a command resolved to decides which settings apply:
//!
//! - **A binary in a trusted folder** ([`Program::Trusted`]) is matched against the rules. Its name is the base name
//!   of the resolved binary, or of the name as written (`/usr/bin/git` and `git` both read as `git`; `vi` linking to
//!   `/usr/bin/vim` reads as both `vi` and `vim`), so a deny rule cannot be stepped around through another spelling
//!   of a trusted binary. Only the resolved name allows, though: a name as written may be a symlink the agent made
//!   (`./git` linking to `/bin/rm` runs `rm`), so it counts for deny and ask rules only.
//! - **A bash builtin** (`cd`, `echo`, and `eval` or `source`, which the classifier leaves unresolved) is matched
//!   against the rules by its name: bash runs it itself, so it cannot be replaced by a file the agent wrote.
//! - **A binary anywhere else** ([`Program::ProjectExecutable`]) never matches a rule, however it is named; it gets
//!   `exec.project_executables` (FR-POL-14). So `./node_modules/.bin/git` is never allowed by `git`.
//! - **A function defined in the line, a name not found, or a name built from an expansion** matches no rule and gets
//!   `exec.default`. A function's body is decided command by command; a name not found fails with 127; dynamic code
//!   gets its limits from the line verdict (FR-POL-20, KNSH-041).
//!
//! # Patterns
//!
//! A pattern is a list of words separated by spaces. The first word names the program; each later word is matched
//! against the command's arguments, in order. The arguments are the normalised ones when the classifier normalised the
//! command (FR-POL-15: `git -c x=y push origin` reads as `git push origin`), and the arguments as written otherwise. A
//! rule matching either form matches, so a deny rule written against raw options (`git -c *`) still applies.
//!
//! Only `*` is special, and patterns are matched against the argument strings, never the filesystem:
//!
//! - In a word, `*` matches any run of characters within one argument (`*.txt`, `--force*`, and `*` in the name
//!   word).
//! - A word that is exactly `*`, after the name, matches any number of whole arguments, none included: `rm -rf *`
//!   matches `rm -rf`, `rm -rf /` and `rm -rf a b`; `git * --force` matches `git push origin --force`.
//! - A pattern without any `*` also matches the same command with more arguments (FR-POL-16): `git push` matches
//!   `git push origin main`, but not `git pushx`. A pattern with a `*` matches exactly, so `rm *.txt` does not match
//!   `rm a.txt b.txt`.
//!
//! There is no escape for a literal `*`, and `?` and `[` are ordinary characters.
//!
//! # Arguments that are not known
//!
//! An argument built from an expansion may become any number of words when it runs, and the command `xargs` runs
//! receives more arguments, or has any of them replaced, at run time ([`ClassifiedCommand::arguments_complete`]).
//! Matching such a command can therefore be certain or only possible. A deny or ask rule that **may** match counts as
//! matching; an allow rule counts only if it matches **whatever** the arguments turn out to be. So `rm $X` is denied by
//! `rm -rf *` and not allowed by `rm foo`, while `git` still allows `git $X`. Likewise, when a tool with subcommands
//! was not normalised because an option the table does not know, or an expansion, comes before the subcommand
//! (`git --unknown push`, `git -c $X push`), any leading arguments may be global options: a deny or ask rule may
//! match from any argument on, so `git push` still asks for both.
//!
//! # Precedence
//!
//! Across every matching rule, deny beats ask, which beats allow (FR-POL-17), and among rules of one list the first
//! wins, so the rule ID names the lowest index. No match gives `exec.default`.

use std::fmt;

use knsh_bash::{ClassifiedCommand, Normalisation, Program, RawReason, SUBCOMMAND_TABLE, normalise};

use super::model::{Profile, RuleAction};

/// The rule or setting that decided a command, as it appears in records, errors and `decision.requested`
/// (`specs/05-models/policy-profile.md#rule-ids`).
///
/// An index refers to the resolved profile's list. `extends` replaces a list whole and presets never add commands,
/// so the index is the entry's position in the nearest profile of the chain that sets that list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleId {
    /// `exec.allow[N]`.
    Allow(usize),
    /// `exec.ask[N]`.
    Ask(usize),
    /// `exec.deny[N]`.
    Deny(usize),
    /// `exec.project_executables`: a binary from an agent-writable place (FR-POL-14).
    ProjectExecutables,
    /// `exec.default`: no rule matched (FR-POL-17).
    Default,
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow(index) => write!(f, "exec.allow[{index}]"),
            Self::Ask(index) => write!(f, "exec.ask[{index}]"),
            Self::Deny(index) => write!(f, "exec.deny[{index}]"),
            Self::ProjectExecutables => f.write_str("exec.project_executables"),
            Self::Default => f.write_str("exec.default"),
        }
    }
}

/// The decision for one simple command: what to do and which rule or setting said so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommandVerdict {
    /// Run it, ask the authority, or refuse it.
    pub verdict: RuleAction,
    /// The rule or setting that decided it.
    pub rule_id: RuleId,
}

/// Decides one classified simple command against `profile`'s command rules (see the module documentation).
///
/// Pure and total. It decides a single command; combining the commands of a line, and the limits of dynamic code,
/// are the line verdict's (FR-POL-18, FR-POL-20).
#[must_use]
pub fn evaluate_command(profile: &Profile, command: &ClassifiedCommand) -> CommandVerdict {
    let exec = &profile.exec;
    let Some(subject) = Subject::of(command) else {
        // No rule may name this command: a project executable has its own setting (FR-POL-14), anything else falls
        // through to the default (module documentation, "Who rules can name").
        return match &command.program {
            Some(Program::ProjectExecutable(_)) => CommandVerdict {
                verdict: exec.project_executables,
                rule_id: RuleId::ProjectExecutables,
            },
            Some(Program::Trusted(_) | Program::Builtin | Program::Function | Program::NotFound) | None => {
                CommandVerdict {
                    verdict: exec.default,
                    rule_id: RuleId::Default,
                }
            }
        };
    };
    // Deny first, then ask, then allow: the first list with a match decides (FR-POL-17).
    for verdict in [RuleAction::Deny, RuleAction::Ask, RuleAction::Allow] {
        let (patterns, rule_id, needed): (&[String], fn(usize) -> RuleId, Match) = match verdict {
            RuleAction::Deny => (&exec.deny, RuleId::Deny, Match::Possible),
            RuleAction::Ask => (&exec.ask, RuleId::Ask, Match::Possible),
            // An allow must hold whatever unknown arguments become; a deny or ask applies if it might (module docs).
            RuleAction::Allow => (&exec.allow, RuleId::Allow, Match::Certain),
        };
        if let Some(index) = patterns.iter().position(|pattern| subject.matches(pattern) >= needed) {
            return CommandVerdict {
                verdict,
                rule_id: rule_id(index),
            };
        }
    }
    CommandVerdict {
        verdict: exec.default,
        rule_id: RuleId::Default,
    }
}

/// Whether `pattern` matches `command` whatever its unknown arguments turn out to be: the test an allow rule must
/// pass (module documentation). Used for grants of capability, such as a secret's `inject_for` (KNSH-041), where a
/// match that is only possible must not count. A command no rule may name (a project executable, a function, a name
/// not found or built from an expansion) never matches.
pub(crate) fn matches_certainly(pattern: &str, command: &ClassifiedCommand) -> bool {
    Subject::of(command).is_some_and(|subject| subject.matches(pattern) == Match::Certain)
}

/// How far a pattern matches a command whose arguments may not all be known. Ordered: `No < Possible < Certain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Match {
    /// Not for any value of the unknown arguments.
    No,
    /// For some values of the unknown arguments.
    Possible,
    /// For every value of the unknown arguments.
    Certain,
}

/// A command as rules see it: the names it answers to and its argument lists.
struct Subject<'a> {
    /// Base names the program answers to (module documentation), each with how surely it names what runs: the
    /// resolved binary's (or a builtin's) name is [`Match::Certain`]; a different name as written is only
    /// [`Match::Possible`], so it counts for deny and ask but never allows (an agent can write a symlink `./git` to
    /// `/bin/rm`). One or two entries.
    names: Vec<(&'a str, Match)>,
    /// The argument lists to match: the normalised arguments (after the tool's name) if the command was normalised,
    /// then the arguments as written. `None` is an argument built from an expansion.
    argument_lists: Vec<Vec<Option<&'a str>>>,
    /// `false` when arguments are appended or replaced at run time, so none of them is known.
    complete: bool,
    /// `true` when the program has subcommands but the classifier could not find where they start (an option it does
    /// not know, or an expansion, before the subcommand): any leading arguments may be global options, so a deny or
    /// ask rule may match from any argument on (module documentation, "Arguments that are not known").
    subcommand_unknown: bool,
}

impl<'a> Subject<'a> {
    /// The command as rules see it, or `None` if no rule may name it (module documentation).
    fn of(command: &'a ClassifiedCommand) -> Option<Self> {
        let written = command.name.as_deref()?;
        let written_base = base_name(written);
        let names = match &command.program {
            Some(Program::Trusted(path)) => {
                // A path that is not valid UTF-8 cannot equal any pattern word; the written name may still deny.
                match path.file_name().and_then(|name| name.to_str()) {
                    Some(resolved) if resolved == written_base => vec![(resolved, Match::Certain)],
                    Some(resolved) => vec![(resolved, Match::Certain), (written_base, Match::Possible)],
                    None => vec![(written_base, Match::Possible)],
                }
            }
            Some(Program::Builtin) => vec![(written_base, Match::Certain)],
            // `eval`, `source` and `.` are left unresolved by the classifier but are run by bash itself.
            None if knsh_bash::is_builtin(written) => vec![(written_base, Match::Certain)],
            Some(Program::ProjectExecutable(_) | Program::Function | Program::NotFound) | None => return None,
        };
        let raw: Vec<Option<&str>> = command.arguments.iter().map(|a| a.text.as_deref()).collect();
        let mut argument_lists = Vec::with_capacity(2);
        let mut subcommand_unknown = false;
        match normalise(command, SUBCOMMAND_TABLE) {
            Normalisation::Normalised(normalised) => {
                // The normalised argv is `[tool, …arguments from the subcommand on]`; `names` already covers the tool.
                argument_lists.push(raw.get(normalised.subcommand_index..).unwrap_or_default().to_vec());
            }
            // `git --unknown push` or `git -c $X push` may well run `git push`: never let that step around a deny or
            // ask rule written against the normalised form (FR-POL-15, fail closed).
            Normalisation::Raw(RawReason::UnknownOption { .. } | RawReason::ExpandedArgument { .. }) => {
                subcommand_unknown = true;
            }
            Normalisation::Raw(
                RawReason::Dynamic
                | RawReason::Wrapper
                | RawReason::NotTrusted
                | RawReason::NotInTable
                | RawReason::UnknownSubcommand { .. }
                | RawReason::InfoOption { .. }
                | RawReason::MissingValue { .. }
                | RawReason::NoSubcommand
                | RawReason::IncompleteArguments,
            ) => {}
        }
        argument_lists.push(raw);
        Some(Self {
            names,
            argument_lists,
            complete: command.arguments_complete,
            subcommand_unknown,
        })
    }

    /// How far `pattern` matches this command: the best of its names, capped by the best of its argument lists.
    fn matches(&self, pattern: &str) -> Match {
        let mut words = pattern.split(' ').filter(|word| !word.is_empty());
        let Some(name) = words.next() else {
            // The loader refuses a pattern without words; such a pattern would name nothing.
            return Match::No;
        };
        let name_match = self
            .names
            .iter()
            .filter(|(candidate, _)| glob(name, candidate))
            .map(|&(_, sure)| sure)
            .max()
            .unwrap_or(Match::No);
        if name_match == Match::No {
            return Match::No;
        }
        let mut words: Vec<Word<'_>> = words.map(Word::parse).collect();
        // FR-POL-16: a pattern without `*` also matches with more arguments.
        if !pattern.contains('*') {
            words.push(Word::Any);
        }
        let arguments_match = if self.complete {
            self.argument_lists
                .iter()
                .map(|arguments| match_arguments(&words, arguments, self.subcommand_unknown))
                .max()
                .unwrap_or(Match::No)
        } else if words.iter().all(|word| matches!(word, Word::Any)) {
            // Every argument may change at run time: only a tail of `*` words matches for certain.
            Match::Certain
        } else {
            Match::Possible
        };
        name_match.min(arguments_match)
    }
}

/// One pattern word after the name.
#[derive(Debug, Clone, Copy)]
enum Word<'a> {
    /// Exactly `*`: any number of whole arguments.
    Any,
    /// A glob over one argument.
    One(&'a str),
}

impl<'a> Word<'a> {
    /// Reads one non-empty pattern word: only a word that is exactly `*` spans arguments.
    fn parse(word: &'a str) -> Self {
        if word == "*" { Self::Any } else { Self::One(word) }
    }
}

/// The last `/`-separated component of a command name as written (`./bin/x` → `x`).
fn base_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// How far `words` match `arguments`, where `None` is an argument built from an expansion that may become any number
/// of words.
///
/// Certain if the words match when each unknown argument can only be absorbed by `*` words (then any expansion
/// matches); possible if they match when an unknown argument may stand for any words at all, or, with
/// `any_start`, from any argument on (leading arguments that may be global options); otherwise no.
fn match_arguments(words: &[Word<'_>], arguments: &[Option<&str>], any_start: bool) -> Match {
    if sequence_matches(words, arguments, false, false) {
        Match::Certain
    } else if (any_start || arguments.iter().any(Option::is_none))
        && sequence_matches(words, arguments, true, any_start)
    {
        Match::Possible
    } else {
        Match::No
    }
}

/// Whether `words` match `arguments` as a whole, or with `any_start` some suffix of them. `unknown_is_wildcard`
/// decides how a `None` argument reads: as any sequence of words (`true`), or as something only a `*` word may absorb
/// (`false`).
///
/// Dynamic programming over suffixes, one row at a time, so time is `words × arguments` glob checks and memory one
/// row: both inputs can be large (a long agent line, a long rule list), so no backtracking.
fn sequence_matches(
    words: &[Word<'_>],
    arguments: &[Option<&str>],
    unknown_is_wildcard: bool,
    any_start: bool,
) -> bool {
    let count = arguments.len();
    // `next[j]`: whether `words[i + 1..]` match `arguments[j..]`; starts as the empty pattern's row.
    let mut next: Vec<bool> = (0..=count).map(|j| j == count).collect();
    // A run of unknown arguments may also become no words at all, before the pattern is exhausted too.
    if unknown_is_wildcard {
        for j in (0..count).rev() {
            next[j] = arguments[j].is_none() && next[j + 1];
        }
    }
    for word in words.iter().rev() {
        let mut row = vec![false; count + 1];
        row[count] = match word {
            Word::Any => next[count],
            Word::One(_) => false,
        };
        for j in (0..count).rev() {
            row[j] = match (word, arguments[j]) {
                // `*` absorbs nothing more, or this argument (known or not) and maybe more.
                (Word::Any, _) => next[j] || row[j + 1],
                // The cheap check first: the glob only matters if the rest can match.
                (Word::One(glob_word), Some(text)) => next[j + 1] && glob(glob_word, text),
                // An unknown argument may become no word, one word matching this one, or that word and more.
                (Word::One(_), None) if unknown_is_wildcard => row[j + 1] || next[j + 1] || next[j],
                (Word::One(_), None) => false,
            };
        }
        next = row;
    }
    if any_start { next.contains(&true) } else { next[0] }
}

/// Whether `text` matches `pattern`, where each `*` matches any run of bytes and everything else matches itself.
///
/// Greedy with backtracking to the last `*` only, which is exact for this one-wildcard grammar and takes at most
/// `pattern × text` steps.
fn glob(pattern: &str, text: &str) -> bool {
    let (pattern, text) = (pattern.as_bytes(), text.as_bytes());
    let (mut p, mut t) = (0, 0);
    // Where to resume after the last `*`: the pattern index after it, and the text index it matched up to.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p + 1, t));
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((after, matched)) = star {
            // Let the last `*` take one more byte and retry from there.
            p = after;
            t = matched + 1;
            star = Some((after, matched + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use knsh_bash::{Interpreters, Lookup, Resolver, SourceFile, classify, parse_line};

    use super::*;
    use crate::policy::paths::testing::FakeFs;
    use crate::policy::{LookupError, PathContext, ProfileSource, load_profile_text};
    use crate::session::ProfileName;

    /// No parents: every test profile stands alone.
    struct NoParents;

    impl ProfileSource for NoParents {
        fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
            Err(LookupError::NotFound)
        }
    }

    /// A session whose `PATH` finds names in `/usr/bin`, except those starting with `./` or naming `node_modules`,
    /// which are project executables, and `missing`, which is not found.
    struct Session;

    impl Resolver for Session {
        fn resolve(&self, name: &str, _lookup: Lookup) -> Program {
            if knsh_bash::is_builtin(name) {
                Program::Builtin
            } else if name == "missing" {
                Program::NotFound
            } else if name == "./git" {
                // An agent-written symlink to a trusted binary: it resolves to, and runs, `/bin/rm`.
                Program::Trusted(PathBuf::from("/bin/rm"))
            } else if name.starts_with("./") || name.contains("node_modules") {
                Program::ProjectExecutable(PathBuf::from("/Users/u/app").join(name))
            } else if name == "vi" {
                Program::Trusted(PathBuf::from("/usr/bin/vim"))
            } else if name.starts_with('/') {
                Program::Trusted(PathBuf::from(name))
            } else {
                Program::Trusted(PathBuf::from("/usr/bin").join(name))
            }
        }

        fn source_file(&self, _path: &str) -> SourceFile {
            SourceFile::Unresolved
        }
    }

    /// A profile with the given rules, read through the real loader so rule lists are what a profile file gives.
    fn profile(text: &str) -> Profile {
        let mut fs = FakeFs::new();
        fs.add("/Users/u/app").add("/tmp").add("/bin/bash");
        let context = PathContext {
            home: PathBuf::from("/Users/u"),
            tmpdir: PathBuf::from("/tmp"),
            start_dir: PathBuf::from("/Users/u/app"),
        };
        let text = format!("name = \"t\"\n[exec]\n{text}");
        load_profile_text(text.as_bytes(), &NoParents, &context, &fs).unwrap()
    }

    /// The verdicts of every simple command of `line`, in source order.
    fn verdicts(profile: &Profile, line: &str) -> Vec<CommandVerdict> {
        let classification = classify(&parse_line(line), line, &Session, &Interpreters::defaults());
        classification
            .commands()
            .iter()
            .map(|command| evaluate_command(profile, command))
            .collect()
    }

    /// The verdict of the last simple command of `line` (the command a wrapper runs, if any).
    fn verdict(profile: &Profile, line: &str) -> CommandVerdict {
        *verdicts(profile, line).last().unwrap()
    }

    fn decided(verdict: RuleAction, rule_id: RuleId) -> CommandVerdict {
        CommandVerdict { verdict, rule_id }
    }

    // FR-POL-13, FR-POL-14: `git` names the trusted binary only, never a project-local `git`.
    #[test]
    fn name_rule_matches_only_trusted_binary() {
        let p = profile("allow = [\"git\"]\ndefault = \"deny\"\nproject_executables = \"ask\"");
        assert_eq!(verdict(&p, "git status"), decided(RuleAction::Allow, RuleId::Allow(0)));
        assert_eq!(
            verdict(&p, "/usr/bin/git status"),
            decided(RuleAction::Allow, RuleId::Allow(0))
        );
        assert_eq!(
            verdict(&p, "./node_modules/.bin/git status"),
            decided(RuleAction::Ask, RuleId::ProjectExecutables)
        );
    }

    // FR-POL-14: a project executable gets `exec.project_executables`, even when a deny rule names it.
    #[test]
    fn project_executable_uses_project_executables_setting() {
        for (setting, action) in [
            ("allow", RuleAction::Allow),
            ("ask", RuleAction::Ask),
            ("deny", RuleAction::Deny),
        ] {
            let p = profile(&format!(
                "allow = [\"git\"]\ndeny = [\"x\"]\nproject_executables = \"{setting}\"\ndefault = \"ask\""
            ));
            assert_eq!(verdict(&p, "./x --flag"), decided(action, RuleId::ProjectExecutables));
            assert_eq!(
                verdict(&p, "./scripts/git push"),
                decided(action, RuleId::ProjectExecutables)
            );
        }
    }

    // FR-POL-16: a pattern without `*` also matches with more arguments, on word boundaries only.
    #[test]
    fn pattern_without_star_matches_with_extra_args() {
        let p = profile("ask = [\"git push\"]\nallow = [\"git\"]");
        assert_eq!(verdict(&p, "git push"), decided(RuleAction::Ask, RuleId::Ask(0)));
        assert_eq!(
            verdict(&p, "git push origin main"),
            decided(RuleAction::Ask, RuleId::Ask(0))
        );
        // `pushx` is another argument, not `push` with more text.
        assert_eq!(verdict(&p, "git pushx"), decided(RuleAction::Allow, RuleId::Allow(0)));
        // A pattern with `*` matches exactly.
        let p = profile("ask = [\"rm *.txt\"]\ndefault = \"allow\"");
        assert_eq!(verdict(&p, "rm a.txt"), decided(RuleAction::Ask, RuleId::Ask(0)));
        assert_eq!(
            verdict(&p, "rm a.txt b.txt"),
            decided(RuleAction::Allow, RuleId::Default)
        );
    }

    // FR-POL-15: options before the subcommand are normalised away, so `git push` matches them.
    #[test]
    fn normalised_git_push_matches_ask_rule() {
        let p = profile("ask = [\"git push\"]\nallow = [\"git\"]");
        for line in [
            "git -c x=y push",
            "git -c x=y push origin main",
            "git --no-pager -C /tmp push",
            "/usr/bin/git -c a=b push --force",
        ] {
            assert_eq!(verdict(&p, line), decided(RuleAction::Ask, RuleId::Ask(0)), "{line}");
        }
        // A deny written against the raw options still applies: either argument form may match.
        let p = profile("deny = [\"git -c *\"]\nallow = [\"git push\"]");
        assert_eq!(
            verdict(&p, "git -c x=y push"),
            decided(RuleAction::Deny, RuleId::Deny(0))
        );
        // A wrapper's command is decided as itself (FR-LC-04).
        let p = profile("ask = [\"git push\"]\nallow = [\"git\", \"env\"]");
        assert_eq!(
            verdicts(&p, "env FOO=1 git -c x=y push"),
            [
                decided(RuleAction::Allow, RuleId::Allow(1)),
                decided(RuleAction::Ask, RuleId::Ask(0))
            ]
        );
    }

    // FR-POL-17: across every matching rule, deny beats ask beats allow, whatever the list order in the file.
    #[test]
    fn deny_beats_ask_beats_allow() {
        let p = profile("allow = [\"rm\"]\nask = [\"rm -r *\"]\ndeny = [\"rm -r /*\"]");
        assert_eq!(verdict(&p, "rm a"), decided(RuleAction::Allow, RuleId::Allow(0)));
        assert_eq!(verdict(&p, "rm -r build"), decided(RuleAction::Ask, RuleId::Ask(0)));
        assert_eq!(verdict(&p, "rm -r /etc"), decided(RuleAction::Deny, RuleId::Deny(0)));
        let p = profile("deny = [\"git\"]\nask = [\"git\"]\nallow = [\"git\"]");
        assert_eq!(verdict(&p, "git log"), decided(RuleAction::Deny, RuleId::Deny(0)));
    }

    // FR-POL-17: no match uses `exec.default`, as do commands no rule can name.
    #[test]
    fn no_match_uses_default() {
        for (setting, action) in [
            ("allow", RuleAction::Allow),
            ("ask", RuleAction::Ask),
            ("deny", RuleAction::Deny),
        ] {
            let p = profile(&format!("allow = [\"git\"]\ndefault = \"{setting}\""));
            assert_eq!(verdict(&p, "curl x"), decided(action, RuleId::Default));
            assert_eq!(verdict(&p, "missing"), decided(action, RuleId::Default));
            assert_eq!(verdict(&p, "\"$X\" push"), decided(action, RuleId::Default));
        }
        // Unset, the default is `ask`.
        assert_eq!(verdict(&profile(""), "ls"), decided(RuleAction::Ask, RuleId::Default));
        // A function defined in the line matches no rule, even one naming it.
        let p = profile("allow = [\"git\"]\ndefault = \"deny\"");
        assert_eq!(
            verdicts(&p, "git() { :; }; git")[1],
            decided(RuleAction::Deny, RuleId::Default)
        );
    }

    // The rule ID names the list and index of the first matching rule.
    #[test]
    fn rule_id_points_at_matching_rule() {
        let p = profile("allow = [\"ls\", \"git status\", \"git\"]\nask = [\"npm\", \"git push\"]");
        assert_eq!(verdict(&p, "git status -s").rule_id, RuleId::Allow(1));
        assert_eq!(verdict(&p, "git log").rule_id, RuleId::Allow(2));
        assert_eq!(verdict(&p, "git push").rule_id, RuleId::Ask(1));
        assert_eq!(RuleId::Allow(1).to_string(), "exec.allow[1]");
        assert_eq!(RuleId::Ask(0).to_string(), "exec.ask[0]");
        assert_eq!(RuleId::Deny(12).to_string(), "exec.deny[12]");
        assert_eq!(RuleId::ProjectExecutables.to_string(), "exec.project_executables");
        assert_eq!(RuleId::Default.to_string(), "exec.default");
    }

    // `*` is matched against the argument strings, never expanded against the filesystem.
    #[test]
    fn glob_matches_arguments_not_files() {
        let p = profile("ask = [\"rm -rf *\"]\ndefault = \"allow\"");
        // A `*` word matches any number of whole arguments, none included.
        for line in ["rm -rf", "rm -rf /", "rm -rf a b c", "rm -rf 'a b'", "rm -rf '*'"] {
            assert_eq!(verdict(&p, line), decided(RuleAction::Ask, RuleId::Ask(0)), "{line}");
        }
        // The literal words must still match.
        assert_eq!(verdict(&p, "rm -r x"), decided(RuleAction::Allow, RuleId::Default));
        assert_eq!(verdict(&p, "rm x -rf"), decided(RuleAction::Allow, RuleId::Default));
        // `*` inside a word stays inside one argument; `?` and `[` are ordinary characters.
        let p = profile("deny = [\"git push --force*\", \"cat a?[b]\"]\ndefault = \"allow\"");
        assert_eq!(verdict(&p, "git push --force-with-lease").verdict, RuleAction::Deny);
        assert_eq!(verdict(&p, "git push --forc").verdict, RuleAction::Allow);
        assert_eq!(verdict(&p, "cat 'a?[b]'").verdict, RuleAction::Deny);
        assert_eq!(verdict(&p, "cat 'ax[b]'").verdict, RuleAction::Allow);
        // Unquoted, bash expands `ax[b]` against the filesystem, so the argument is unknown and the deny may apply.
        assert_eq!(verdict(&p, "cat ax[b]").verdict, RuleAction::Deny);
        // A `*` word in the middle spans arguments.
        let p = profile("deny = [\"git * --force\"]\ndefault = \"allow\"");
        assert_eq!(verdict(&p, "git push origin --force").verdict, RuleAction::Deny);
        assert_eq!(verdict(&p, "git --force").verdict, RuleAction::Deny);
        assert_eq!(verdict(&p, "git push --force x").verdict, RuleAction::Allow);
    }

    // Unknown arguments: a deny or ask applies if it might match, an allow only if it surely does.
    #[test]
    fn unknown_arguments_fail_closed() {
        let p = profile("allow = [\"rm foo\", \"git\"]\nask = [\"git push\"]\ndeny = [\"rm -rf *\"]");
        assert_eq!(verdict(&p, "rm $X").verdict, RuleAction::Deny);
        assert_eq!(verdict(&p, "rm foo $X").verdict, RuleAction::Allow);
        assert_eq!(verdict(&p, "git $X").verdict, RuleAction::Ask);
        assert_eq!(verdict(&p, "git status $X").verdict, RuleAction::Allow);
        // `xargs` appends and replaces arguments at run time: only the name is known.
        let p = profile("allow = [\"git status\", \"xargs\"]\nask = [\"git push\"]\ndefault = \"deny\"");
        assert_eq!(verdict(&p, "xargs git status").verdict, RuleAction::Ask);
        let p = profile("allow = [\"git\", \"xargs\"]\ndefault = \"deny\"");
        assert_eq!(verdict(&p, "xargs git status").verdict, RuleAction::Allow);
        let p = profile("allow = [\"git status\", \"xargs\"]\ndefault = \"deny\"");
        assert_eq!(verdict(&p, "xargs git status").verdict, RuleAction::Deny);
        // Where the subcommand starts is unknown (an expansion or an unknown option before it): a deny or ask written
        // against the normalised form still applies, and an allow of another subcommand does not.
        let p = profile("allow = [\"git\", \"git status\"]\nask = [\"git push\"]\ndeny = [\"git push --force\"]");
        // `$X` may become `x=y push --force`, which runs `git push --force`.
        assert_eq!(verdict(&p, "git -c $X push").verdict, RuleAction::Deny);
        assert_eq!(verdict(&p, "git --frobnicate push origin").verdict, RuleAction::Ask);
        assert_eq!(verdict(&p, "git --frobnicate push --force").verdict, RuleAction::Deny);
        assert_eq!(verdict(&p, "git --frobnicate status").verdict, RuleAction::Allow);
        assert_eq!(verdict(&p, "git --frobnicate status").rule_id, RuleId::Allow(0));
        let p = profile("allow = [\"git\"]\nask = [\"git push\"]");
        assert_eq!(verdict(&p, "git -c $X push").verdict, RuleAction::Ask);
        assert_eq!(verdict(&p, "git -c $X status").verdict, RuleAction::Ask);
        assert_eq!(verdict(&p, "git --frobnicate status").verdict, RuleAction::Allow);
    }

    // Builtins are named by rules; a trusted binary answers to its resolved and its written base name.
    #[test]
    fn builtins_and_binary_aliases_match_by_name() {
        let p = profile("allow = [\"cd\", \"echo\"]\ndeny = [\"eval\", \"vim\"]\ndefault = \"ask\"");
        assert_eq!(verdict(&p, "cd /tmp").verdict, RuleAction::Allow);
        assert_eq!(verdict(&p, "echo hi").verdict, RuleAction::Allow);
        assert_eq!(verdict(&p, "eval x").verdict, RuleAction::Deny);
        assert_eq!(verdict(&p, "vi file").verdict, RuleAction::Deny);
        // The name as written may deny or ask, but only the resolved name allows: `./git` linking to `/bin/rm` is `rm`.
        let p = profile("allow = [\"vi\", \"git\"]\ndefault = \"deny\"");
        assert_eq!(verdict(&p, "vi file").verdict, RuleAction::Deny);
        assert_eq!(verdict(&p, "./git -rf /").verdict, RuleAction::Deny);
        let p = profile("allow = [\"rm\"]\nask = [\"git\"]");
        assert_eq!(verdict(&p, "./git -rf /").verdict, RuleAction::Ask);
        let p = profile("allow = [\"g*\"]\ndefault = \"deny\"");
        assert_eq!(verdict(&p, "git").verdict, RuleAction::Allow);
    }

    #[test]
    fn glob_handles_stars_and_literals() {
        assert!(glob("*", ""));
        assert!(glob("a*", "a"));
        assert!(glob("*b*", "abc"));
        assert!(glob("a*b*c", "aXbYbZc"));
        assert!(!glob("a*b", "aXbY"));
        assert!(!glob("abc", "ab"));
        assert!(glob("**", "x"));
    }
}
