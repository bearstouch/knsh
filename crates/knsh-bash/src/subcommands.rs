//! Subcommand normalisation and network-intent classes (KNSH-037; FR-POL-15, FR-LC-06, FR-NET-03).
//!
//! Tools with subcommands accept global options before the subcommand: `git -c x=y push`, `kubectl -n prod apply`,
//! `docker --context prod push`. Policy patterns are globs over *normalised* arguments (FR-POL-15), so
//! [`normalise`] reads those options with the tool's grammar from [`SUBCOMMAND_TABLE`](crate::SUBCOMMAND_TABLE) and
//! gives `[tool, subcommand, …remaining arguments]`, recording each option it skipped ([`SkippedOption`]). The same
//! table gives each subcommand its network-intent classes ([`NetworkClass`]), which host rules use later to decide
//! whether a command may reach `network.approval_hosts` (FR-NET-03, KNSH-060), and the normalised form is what
//! irreversible-action matching reads (KNSH-093).
//!
//! # How the arguments are read
//!
//! From the left, until the first operand, which must be a subcommand the table lists (by name or alias):
//!
//! - an argument equal to one of [`flag_options`](SubcommandTool::flag_options) is skipped;
//! - one equal to a [`value_options`](SubcommandTool::value_options) entry is skipped with the next argument; it is
//!   also skipped alone when its value is attached with `=` (`--git-dir=/x`, `-chdir=dir`; a short option `-n=x` only
//!   when [`attached_short_values`](SubcommandTool::attached_short_values) is set), or directly (`-nprod`) when that
//!   flag is set;
//! - a short cluster (`-vv`) is skipped when [`short_clusters`](SubcommandTool::short_clusters) is set and every letter
//!   is a short flag option;
//! - the first argument may start with a [`prefix_flags`](SubcommandTool::prefix_flags) entry (`cargo +nightly`).
//!
//! # Never guess
//!
//! The subcommand is only ever the one the tool itself would read. Anything else gives [`Normalisation::Raw`] with a
//! [`RawReason`] and **no** network classes, and rules match on the raw argv: an option the table does not know (it
//! could take a value that shifts the subcommand), an argument built from an expansion before the subcommand (an
//! unquoted one may split into several words), a first operand that is not a listed subcommand (`git co` may be an
//! alias, `npm --global false install` reads `false` as a value), an option that runs nothing (`--version`,
//! `--help`), a value option whose next argument looks like an option (`pnpm --filter -C x install` reads `-C x`, so
//! the subcommand is not `install`), arguments that run out before the subcommand, a command whose arguments are
//! incomplete (`xargs` appends to them and `xargs -I fetch git fetch` replaces any word at run time), and every command
//! that is not a trusted binary.
//!
//! Classes are given only to a binary resolved in a trusted folder ([`Program::Trusted`]) whose resolved base name is
//! in the table. The name as written is never used: a project-local `./git` linking to `curl` must not gain
//! `network:fetch`. Dynamic code never inherits classes (FR-POL-20). As every classifier result, this is an intent
//! filter, never a security boundary: the proxy enforces what each class may reach.

use std::ops::Range;

use crate::classify::{ClassifiedCommand, CommandClass, Program};

/// A network-intent class: what a command may do on the network (FR-LC-06, FR-NET-03).
///
/// A command's classes list everything it may do, so a host rule must allow **every** class of a command for the
/// command to reach a host on the strength of its classes (KNSH-060). A command with no classes (not in the table, or
/// not normalised) never reaches `network.approval_hosts` without an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkClass {
    /// Works locally: `git status`, `npm run`, `cargo new`.
    None,
    /// Downloads from, or reads the state of, a remote: `git fetch`, `npm install`, `docker pull`, `kubectl get`.
    Fetch,
    /// Uploads to, or changes the state of, a remote: `git push`, `npm publish`, `docker push`, `kubectl apply`.
    Publish,
}

impl NetworkClass {
    /// The class's name in policy and records: `network:none`, `network:fetch` or `network:publish`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::None => "network:none",
            Self::Fetch => "network:fetch",
            Self::Publish => "network:publish",
        }
    }
}

/// One subcommand of a tool and its network-intent classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subcommand {
    /// The subcommand's canonical name (`install`).
    pub name: &'static str,
    /// Other spellings the tool accepts for it (`i`, `add` for `npm install`).
    pub aliases: &'static [&'static str],
    /// Everything it may do on the network. Never empty in the default table; a group (`gh pr`, `docker image`) has
    /// the union of its members' classes.
    pub classes: &'static [NetworkClass],
}

/// One tool with subcommands: its global option grammar, just far enough to find the subcommand, and its
/// subcommands. See the module documentation for how arguments are read with it.
///
/// Options are written as on the command line (`-c`, `--git-dir`, `-chdir`). Every list is exact: an option not
/// listed makes the command fall back to its raw argv.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubcommandTool {
    /// Resolved base names that run this tool; the first is the name used in the normalised argv.
    pub names: &'static [&'static str],
    /// Global options that take no value (`--no-pager`, `-q`).
    pub flag_options: &'static [&'static str],
    /// Global options that take a value, as the next argument or attached (`-c x=y`, `--git-dir=/x`).
    pub value_options: &'static [&'static str],
    /// Global options that make the tool run no subcommand (`--version`, `--help`).
    pub info_options: &'static [&'static str],
    /// Prefixes of a first argument that is a flag rather than the subcommand (`+` for `cargo +nightly build`).
    pub prefix_flags: &'static [&'static str],
    /// Whether a short value option takes an attached value (`kubectl -nprod`, `-n=prod`).
    pub attached_short_values: bool,
    /// Whether short flag options cluster (`cargo -vv`).
    pub short_clusters: bool,
    /// The subcommands the tool runs.
    pub subcommands: &'static [Subcommand],
}

impl SubcommandTool {
    /// The tool's name in the normalised argv: the first of [`names`](Self::names).
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self.names {
            [first, ..] => first,
            [] => "",
        }
    }

    /// The subcommand `word` names, by canonical name or alias.
    #[must_use]
    pub fn subcommand(&self, word: &str) -> Option<&'static Subcommand> {
        self.subcommands
            .iter()
            .find(|entry| entry.name == word || entry.aliases.contains(&word))
    }

    /// How one argument before the subcommand reads. `index` is its position among the command's arguments.
    fn read(&self, text: &str, index: usize) -> Read {
        if !text.starts_with('-') {
            // The rustup proxy only reads `+toolchain` as the very first argument.
            let prefixed = index == 0
                && self
                    .prefix_flags
                    .iter()
                    .any(|prefix| text.len() > prefix.len() && text.starts_with(prefix));
            return if prefixed {
                Read::Flag(text.to_owned())
            } else {
                Read::Operand
            };
        }
        if self.flag_options.contains(&text) {
            return Read::Flag(text.to_owned());
        }
        if self.info_options.contains(&text) {
            return Read::Info;
        }
        if self.value_options.contains(&text) {
            return Read::Value(text.to_owned());
        }
        if let Some((name, _)) = text.split_once('=') {
            // `--name=value` and `-chdir=dir`; a short `-n=value` only where the tool reads attached short values.
            let short = !name.starts_with("--") && name.len() == 2;
            if self.value_options.contains(&name) && (!short || self.attached_short_values) {
                return Read::AttachedValue(name.to_owned());
            }
            return Read::Unknown;
        }
        if text.starts_with("--") {
            return Read::Unknown;
        }
        let letters = &text[1..];
        // `-nprod`: the value is attached directly to a short value option, read only by tools that accept it.
        if self.attached_short_values
            && let Some(letter) = letters.chars().next()
        {
            let option = format!("-{letter}");
            if self.value_options.contains(&option.as_str()) {
                return Read::AttachedValue(option);
            }
        }
        // `-vv`: a single letter was already checked against `flag_options` above, so a cluster needs two or more.
        if self.short_clusters
            && letters.len() > 1
            && letters
                .chars()
                .all(|letter| self.flag_options.contains(&format!("-{letter}").as_str()))
        {
            return Read::Flag(text.to_owned());
        }
        Read::Unknown
    }
}

/// How one argument before the subcommand reads.
enum Read {
    /// Not an option: the subcommand, if the table lists it.
    Operand,
    /// A flag (or a cluster of them, or a prefix flag), with the option as written.
    Flag(String),
    /// A value option whose value is the next argument.
    Value(String),
    /// A value option with its value attached; carries the option without its value.
    AttachedValue(String),
    /// An option that runs no subcommand.
    Info,
    /// Anything else.
    Unknown,
}

/// A global option skipped before the subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedOption {
    /// The option without its value (`-c`, `--git-dir`, `-vv`, `+nightly`), so a value such as `--token` never
    /// appears here; read values through [`arguments`](Self::arguments) from the command's own arguments.
    pub option: String,
    /// The indices (in [`ClassifiedCommand::arguments`]) of the option and its separate value, if any.
    pub arguments: Range<usize>,
}

/// A command normalised to `[tool, subcommand, …remaining arguments]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalised {
    /// The tool's table name (`git`, whatever path ran it).
    pub tool: &'static str,
    /// The subcommand's canonical name (`install` for `npm i`).
    pub subcommand: &'static str,
    /// The index (in [`ClassifiedCommand::arguments`]) of the subcommand.
    pub subcommand_index: usize,
    /// `[tool, subcommand as written, …remaining arguments]`; `None` for an argument built from an expansion.
    pub argv: Vec<Option<String>>,
    /// Every global option skipped before the subcommand, in order.
    pub skipped: Vec<SkippedOption>,
    /// The subcommand's network-intent classes.
    pub classes: &'static [NetworkClass],
}

/// Why a command keeps its raw argv. Rules match on the raw argv, and the command has no network classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RawReason {
    /// Dynamic code: never normalised, never given classes (FR-POL-20).
    Dynamic,
    /// A wrapper; the command it runs has its own entry.
    Wrapper,
    /// Not a binary from a trusted folder (a project executable, a builtin, a function, a name not found).
    NotTrusted,
    /// The resolved binary's base name is not in the table.
    NotInTable,
    /// An option before the subcommand the table does not know, at this argument index.
    UnknownOption {
        /// The argument's index.
        index: usize,
    },
    /// An argument before the subcommand built from an expansion, at this argument index.
    ExpandedArgument {
        /// The argument's index.
        index: usize,
    },
    /// The first operand, at this argument index, is not a subcommand the table lists.
    UnknownSubcommand {
        /// The argument's index.
        index: usize,
    },
    /// An option that runs no subcommand (`--version`), at this argument index.
    InfoOption {
        /// The argument's index.
        index: usize,
    },
    /// A value option at this argument index is the last argument.
    MissingValue {
        /// The argument's index.
        index: usize,
    },
    /// No subcommand: only global options.
    NoSubcommand,
    /// More arguments arrive at run time, or words are replaced (`xargs`, `xargs -I`): the arguments are unknown.
    IncompleteArguments,
}

/// The result of [`normalise`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Normalisation {
    /// Normalised to `[tool, subcommand, …]`.
    Normalised(Normalised),
    /// Kept as written, with no network classes.
    Raw(RawReason),
}

impl Normalisation {
    /// The command's network-intent classes: the subcommand's, or none when not normalised.
    #[must_use]
    pub const fn classes(&self) -> &'static [NetworkClass] {
        match self {
            Self::Normalised(normalised) => normalised.classes,
            Self::Raw(_) => &[],
        }
    }

    /// The normalised command, if any.
    #[must_use]
    pub const fn normalised(&self) -> Option<&Normalised> {
        match self {
            Self::Normalised(normalised) => Some(normalised),
            Self::Raw(_) => None,
        }
    }
}

/// Normalises one classified command with `table` (usually [`SUBCOMMAND_TABLE`](crate::SUBCOMMAND_TABLE)) and gives
/// its network-intent classes. See the module documentation.
///
/// Pure and total: anything it cannot read with certainty is [`Normalisation::Raw`].
///
/// # Example
///
/// ```
/// use std::path::PathBuf;
/// use knsh_bash::{
///     classify, normalise, parse_line, Interpreters, Lookup, NetworkClass, Program, Resolver, SourceFile,
///     SUBCOMMAND_TABLE,
/// };
///
/// struct Session;
/// impl Resolver for Session {
///     fn resolve(&self, name: &str, _lookup: Lookup) -> Program {
///         Program::Trusted(PathBuf::from("/usr/bin").join(name))
///     }
///     fn source_file(&self, _path: &str) -> SourceFile {
///         SourceFile::Unresolved
///     }
/// }
///
/// let line = "git -c x=y push origin main";
/// let classes = classify(&parse_line(line), line, &Session, &Interpreters::defaults());
/// let result = normalise(&classes.commands()[0], SUBCOMMAND_TABLE);
/// let normalised = result.normalised().unwrap();
/// let argv: Vec<_> = normalised.argv.iter().map(|a| a.as_deref().unwrap()).collect();
/// assert_eq!(argv, ["git", "push", "origin", "main"]);
/// assert_eq!(result.classes(), [NetworkClass::Publish]);
/// ```
#[must_use]
pub fn normalise(command: &ClassifiedCommand, table: &[SubcommandTool]) -> Normalisation {
    match command.class {
        CommandClass::Dynamic { .. } => return Normalisation::Raw(RawReason::Dynamic),
        CommandClass::Wrapper => return Normalisation::Raw(RawReason::Wrapper),
        CommandClass::ProjectExecutable => return Normalisation::Raw(RawReason::NotTrusted),
        CommandClass::Static => {}
    }
    // Only the resolved binary decides the tool, never the name as written (see the module documentation).
    let Some(Program::Trusted(path)) = &command.program else {
        return Normalisation::Raw(RawReason::NotTrusted);
    };
    let base_name = path.file_name().and_then(|name| name.to_str());
    let Some(tool) = base_name.and_then(|base| table.iter().find(|tool| tool.names.contains(&base))) else {
        return Normalisation::Raw(RawReason::NotInTable);
    };
    // `xargs` appends arguments, and with `-I` replaces any word holding its placeholder, even one before or at the
    // subcommand (`xargs -I fetch git fetch` runs `git push` for the input `push`): the arguments are unknown.
    if !command.arguments_complete {
        return Normalisation::Raw(RawReason::IncompleteArguments);
    }
    let arguments: Vec<Option<&str>> = command.arguments.iter().map(|a| a.text.as_deref()).collect();
    normalise_arguments(tool, &arguments)
}

/// Reads `arguments` (after the tool's name; `None` for one built from an expansion) with `tool`'s grammar.
fn normalise_arguments(tool: &SubcommandTool, arguments: &[Option<&str>]) -> Normalisation {
    let mut skipped = Vec::new();
    let mut index = 0;
    while let Some(&argument) = arguments.get(index) {
        let Some(text) = argument else {
            return Normalisation::Raw(RawReason::ExpandedArgument { index });
        };
        match tool.read(text, index) {
            Read::Operand => {
                let Some(subcommand) = tool.subcommand(text) else {
                    return Normalisation::Raw(RawReason::UnknownSubcommand { index });
                };
                let mut argv = Vec::with_capacity(arguments.len() + 1 - index);
                argv.push(Some(tool.name().to_owned()));
                argv.extend(arguments[index..].iter().map(|a| a.map(str::to_owned)));
                return Normalisation::Normalised(Normalised {
                    tool: tool.name(),
                    subcommand: subcommand.name,
                    subcommand_index: index,
                    argv,
                    skipped,
                    classes: subcommand.classes,
                });
            }
            Read::Flag(option) | Read::AttachedValue(option) => {
                skipped.push(SkippedOption {
                    option,
                    arguments: index..index + 1,
                });
                index += 1;
            }
            Read::Value(option) => match arguments.get(index + 1) {
                // nopt (npm, pnpm) leaves a word that looks like an option unread and gives the value option an empty
                // value; other parsers take it or fail. Which one applies is not known here, so never guess.
                Some(Some(value)) if value.starts_with('-') => {
                    return Normalisation::Raw(RawReason::UnknownOption { index: index + 1 });
                }
                Some(Some(_)) => {
                    skipped.push(SkippedOption {
                        option,
                        arguments: index..index + 2,
                    });
                    index += 2;
                }
                // The value is a separate word: an expansion there could split and shift the subcommand.
                Some(None) => return Normalisation::Raw(RawReason::ExpandedArgument { index: index + 1 }),
                None => return Normalisation::Raw(RawReason::MissingValue { index }),
            },
            Read::Info => return Normalisation::Raw(RawReason::InfoOption { index }),
            Read::Unknown => return Normalisation::Raw(RawReason::UnknownOption { index }),
        }
    }
    Normalisation::Raw(RawReason::NoSubcommand)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::PathBuf;

    use super::*;
    use crate::classify::{Lookup, Resolver, SourceFile, classify};
    use crate::interpreter_table::Interpreters;
    use crate::outcome::parse_line;
    use crate::subcommand_table::SUBCOMMAND_TABLE;

    /// Every name resolves in `/usr/bin`, except names starting with `./`, which are project executables.
    struct Session;

    impl Resolver for Session {
        fn resolve(&self, name: &str, _lookup: Lookup) -> Program {
            if let Some(local) = name.strip_prefix("./") {
                Program::ProjectExecutable(PathBuf::from("/Users/a/project").join(local))
            } else {
                Program::Trusted(PathBuf::from("/usr/bin").join(name))
            }
        }

        fn source_file(&self, _path: &str) -> SourceFile {
            SourceFile::Unresolved
        }
    }

    /// The normalisation of every entry of `line`.
    fn all(line: &str) -> Vec<Normalisation> {
        let classes = classify(&parse_line(line), line, &Session, &Interpreters::defaults());
        classes
            .commands()
            .iter()
            .map(|command| normalise(command, SUBCOMMAND_TABLE))
            .collect()
    }

    /// The normalisation of the last entry of `line`.
    fn last(line: &str) -> Normalisation {
        all(line).pop().expect("the line has a command")
    }

    /// The normalised argv of the last entry, which must be normalised.
    fn argv(line: &str) -> Vec<String> {
        let result = last(line);
        let normalised = result.normalised().expect("normalised");
        normalised
            .argv
            .iter()
            .map(|a| a.clone().expect("static argument"))
            .collect()
    }

    fn skipped(line: &str) -> Vec<(String, Range<usize>)> {
        let result = last(line);
        let normalised = result.normalised().expect("normalised");
        normalised
            .skipped
            .iter()
            .map(|s| (s.option.clone(), s.arguments.clone()))
            .collect()
    }

    // FR-POL-15: `git -c x=y push` matches `git push`.
    #[test]
    fn git_dash_c_before_push_normalises_to_git_push() {
        assert_eq!(argv("git -c x=y push origin main"), ["git", "push", "origin", "main"]);
        assert_eq!(skipped("git -c x=y push"), [("-c".to_owned(), 0..2)]);
        assert_eq!(last("git -c x=y push").classes(), [NetworkClass::Publish]);
        // The path it ran from does not matter; the table name is used.
        assert_eq!(argv("/usr/bin/git -c a=b -c c=d push"), ["git", "push"]);
    }

    // FR-POL-15
    #[test]
    fn git_dash_capital_c_path_option_is_skipped() {
        assert_eq!(argv("git -C /repo --no-pager log -1"), ["git", "log", "-1"]);
        assert_eq!(
            skipped("git -C /repo --no-pager log"),
            [("-C".to_owned(), 0..2), ("--no-pager".to_owned(), 2..3)]
        );
        assert_eq!(argv("git --git-dir=/r/.git --work-tree /r status"), ["git", "status"]);
        // git reads no attached short values, so `-C/repo` is unknown.
        assert_eq!(
            last("git -C/repo log"),
            Normalisation::Raw(RawReason::UnknownOption { index: 0 })
        );
        assert_eq!(last("git -C /repo log").classes(), [NetworkClass::None]);
    }

    // FR-POL-15
    #[test]
    fn npm_global_flags_before_run() {
        assert_eq!(argv("npm --prefix ./web --silent run build"), ["npm", "run", "build"]);
        assert_eq!(argv("npm -w pkg -s run test"), ["npm", "run", "test"]);
        assert_eq!(argv("npm --loglevel=warn run lint"), ["npm", "run", "lint"]);
        // An alias keeps its spelling in the argv; the canonical name and classes come from the table.
        let result = last("npm --silent i left-pad");
        let normalised = result.normalised().expect("normalised");
        assert_eq!(normalised.subcommand, "install");
        assert_eq!(normalised.argv[1].as_deref(), Some("i"));
        assert_eq!(result.classes(), [NetworkClass::Fetch]);
        // npm reads `--global false` as a value: `false` is not a subcommand, so nothing is guessed.
        assert_eq!(
            last("npm --global false install"),
            Normalisation::Raw(RawReason::UnknownSubcommand { index: 1 })
        );
    }

    // FR-POL-15
    #[test]
    fn docker_context_option_before_push() {
        assert_eq!(argv("docker --context prod push img:1"), ["docker", "push", "img:1"]);
        assert_eq!(argv("docker -c prod push img"), ["docker", "push", "img"]);
        assert_eq!(argv("docker --context=prod -D push img"), ["docker", "push", "img"]);
        assert_eq!(
            argv("docker -H tcp://h:2376 --tlsverify push img"),
            ["docker", "push", "img"]
        );
        assert_eq!(
            last("docker --context prod push img").classes(),
            [NetworkClass::Publish]
        );
        assert_eq!(last("docker pull img").classes(), [NetworkClass::Fetch]);
    }

    // FR-POL-15
    #[test]
    fn kubectl_namespace_option_before_apply() {
        assert_eq!(
            argv("kubectl -n prod apply -f x.yaml"),
            ["kubectl", "apply", "-f", "x.yaml"]
        );
        assert_eq!(
            argv("kubectl --namespace=prod apply -f x.yaml"),
            ["kubectl", "apply", "-f", "x.yaml"]
        );
        assert_eq!(
            argv("kubectl -nprod --context c apply -k ."),
            ["kubectl", "apply", "-k", "."]
        );
        assert_eq!(skipped("kubectl -nprod apply"), [("-n".to_owned(), 0..1)]);
        assert_eq!(last("kubectl -n prod apply -f x").classes(), [NetworkClass::Publish]);
        assert_eq!(last("kubectl -n prod get pods").classes(), [NetworkClass::Fetch]);
    }

    // FR-POL-15: never guess the subcommand.
    #[test]
    fn unknown_global_option_falls_back_to_raw_argv() {
        let result = last("git --frobnicate push");
        assert_eq!(result, Normalisation::Raw(RawReason::UnknownOption { index: 0 }));
        assert_eq!(result.classes(), []);
        assert_eq!(
            last("kubectl --mystery x apply"),
            Normalisation::Raw(RawReason::UnknownOption { index: 0 })
        );
        // `--` and a flag given a value are unknown too.
        assert_eq!(
            last("git -- push"),
            Normalisation::Raw(RawReason::UnknownOption { index: 0 })
        );
        assert_eq!(
            last("git --bare=x push"),
            Normalisation::Raw(RawReason::UnknownOption { index: 0 })
        );
    }

    // FR-NET-03, FR-LC-06
    #[test]
    fn git_fetch_gets_fetch_network_class() {
        assert_eq!(last("git fetch origin").classes(), [NetworkClass::Fetch]);
        assert_eq!(last("git -C repo fetch --all").classes(), [NetworkClass::Fetch]);
        assert_eq!(NetworkClass::Fetch.code(), "network:fetch");
        assert_eq!(NetworkClass::Publish.code(), "network:publish");
        assert_eq!(NetworkClass::None.code(), "network:none");
    }

    // An expansion before the subcommand may split into several words; never guess.
    #[test]
    fn expansion_before_subcommand_falls_back_to_raw() {
        assert_eq!(
            last("git $FLAGS push"),
            Normalisation::Raw(RawReason::ExpandedArgument { index: 0 })
        );
        assert_eq!(
            last("git -c \"$x\" push"),
            Normalisation::Raw(RawReason::ExpandedArgument { index: 1 })
        );
        // After the subcommand an expansion is kept, as unknown text.
        let result = last("git push \"$remote\"");
        assert_eq!(result.normalised().expect("normalised").argv[2], None);
    }

    #[test]
    fn unknown_subcommand_info_option_and_missing_subcommand_are_raw() {
        assert_eq!(
            last("git -c alias.p=push p"),
            Normalisation::Raw(RawReason::UnknownSubcommand { index: 2 })
        );
        assert_eq!(
            last("git --version"),
            Normalisation::Raw(RawReason::InfoOption { index: 0 })
        );
        assert_eq!(
            last("git --help push"),
            Normalisation::Raw(RawReason::InfoOption { index: 0 })
        );
        assert_eq!(last("git --no-pager"), Normalisation::Raw(RawReason::NoSubcommand));
        assert_eq!(last("git -C"), Normalisation::Raw(RawReason::MissingValue { index: 0 }));
        assert_eq!(last("ls -la"), Normalisation::Raw(RawReason::NotInTable));
    }

    // FR-POL-14, FR-POL-20: only trusted binaries gain classes; dynamic code never does.
    #[test]
    fn untrusted_wrapper_and_dynamic_commands_get_no_classes() {
        assert_eq!(last("./git fetch"), Normalisation::Raw(RawReason::NotTrusted));
        assert_eq!(last("$tool fetch"), Normalisation::Raw(RawReason::Dynamic));
        let through_wrapper = all("env FOO=1 git -c x=y push");
        assert_eq!(through_wrapper[0], Normalisation::Raw(RawReason::Wrapper));
        assert_eq!(through_wrapper[1].classes(), [NetworkClass::Publish]);
    }

    // `xargs` appends arguments, and with `-I` replaces any word holding its placeholder: the arguments are unknown,
    // so never normalised (`xargs -I fetch git fetch` runs `git push` for the input `push`).
    #[test]
    fn commands_run_by_xargs_are_never_normalised() {
        assert_eq!(
            last("xargs git push"),
            Normalisation::Raw(RawReason::IncompleteArguments)
        );
        assert_eq!(
            last("xargs -I fetch git fetch origin"),
            Normalisation::Raw(RawReason::IncompleteArguments)
        );
        assert_eq!(last("xargs -I fetch git fetch").classes(), []);
        assert_eq!(last("xargs git -C"), Normalisation::Raw(RawReason::IncompleteArguments));
        assert_eq!(
            last("xargs git --no-pager"),
            Normalisation::Raw(RawReason::IncompleteArguments)
        );
    }

    #[test]
    fn cargo_toolchain_and_clustered_flags_terraform_single_dash_value() {
        assert_eq!(
            argv("cargo +nightly -vv --locked build --release"),
            ["cargo", "build", "--release"]
        );
        assert_eq!(skipped("cargo +nightly -vv build")[0], ("+nightly".to_owned(), 0..1));
        // `+toolchain` is only read first.
        assert_eq!(
            last("cargo -q +nightly build"),
            Normalisation::Raw(RawReason::UnknownSubcommand { index: 1 })
        );
        assert_eq!(
            last("cargo -Zunstable-options publish").classes(),
            [NetworkClass::Publish]
        );
        assert_eq!(argv("terraform -chdir=infra apply"), ["terraform", "apply"]);
        assert_eq!(
            last("terraform -chdir=infra apply").classes(),
            [NetworkClass::Fetch, NetworkClass::Publish]
        );
    }

    // A value that looks like an option may be left unread by the tool (nopt: `pnpm --filter -C install publish`
    // publishes from the directory `install`), so the subcommand is not guessed.
    #[test]
    fn value_that_looks_like_an_option_falls_back_to_raw() {
        assert_eq!(
            last("pnpm --filter -C install publish"),
            Normalisation::Raw(RawReason::UnknownOption { index: 1 })
        );
        assert_eq!(
            last("git -c -x push"),
            Normalisation::Raw(RawReason::UnknownOption { index: 1 })
        );
        // pnpm's `--color` takes an enum value, so `pnpm --color install publish` publishes: not a known flag.
        assert_eq!(
            last("pnpm --color install publish"),
            Normalisation::Raw(RawReason::UnknownOption { index: 0 })
        );
    }

    // Subcommands that can upload carry `network:publish`, so a preset that lets `network:fetch` reach a host never
    // lets them through (FR-NET-03).
    #[test]
    fn subcommands_that_can_upload_carry_publish() {
        for line in [
            "git submodule foreach git push",
            "docker build --push -t img .",
            "docker plugin push p",
            "kubectl proxy",
            "kubectl port-forward pod/p 8080",
            "kubectl attach -i pod/p",
            "kubectl auth reconcile -f rbac.yaml",
            "gh extension exec ext",
            "terraform plan",
            "terraform init -migrate-state",
        ] {
            assert!(last(line).classes().contains(&NetworkClass::Publish), "{line}");
        }
        // A project `[alias]` overrides cargo's built-in aliases (`b = "publish"`): never read as `build`.
        for line in ["cargo b", "cargo t", "cargo r", "cargo rm x"] {
            assert_eq!(last(line).classes(), [], "{line}");
        }
    }

    // The skipped option never carries its value, which may be a secret (`kubectl --token`).
    #[test]
    fn skipped_options_never_carry_values() {
        assert_eq!(
            skipped("kubectl --token=s3cr3t --as admin get pods"),
            [("--token".to_owned(), 0..1), ("--as".to_owned(), 1..3)]
        );
    }

    // The table is data: check it is well formed, so an entry added without care cannot change how others read.
    #[test]
    fn default_table_is_well_formed() {
        let mut names = HashSet::new();
        for tool in SUBCOMMAND_TABLE {
            assert_ne!(tool.name(), "");
            for name in tool.names {
                assert!(names.insert(*name), "{name} is in the table twice");
            }
            let options: Vec<&str> = tool
                .flag_options
                .iter()
                .chain(tool.value_options)
                .chain(tool.info_options)
                .copied()
                .collect();
            let mut seen = HashSet::new();
            for option in &options {
                assert!(
                    option.starts_with('-') && option.len() >= 2 && *option != "--",
                    "{option}"
                );
                assert!(!option.contains('='), "{option}");
                assert!(seen.insert(*option), "{} lists {option} twice", tool.name());
            }
            for prefix in tool.prefix_flags {
                assert!(!prefix.is_empty() && !prefix.starts_with('-'));
            }
            let mut words = HashSet::new();
            for subcommand in tool.subcommands {
                assert!(!subcommand.classes.is_empty(), "{} {}", tool.name(), subcommand.name);
                for word in std::iter::once(&subcommand.name).chain(subcommand.aliases) {
                    assert!(!word.starts_with('-') && !word.is_empty());
                    assert!(words.insert(*word), "{} lists {word} twice", tool.name());
                }
            }
        }
        for tool in ["git", "npm", "cargo", "docker", "kubectl"] {
            assert!(names.contains(tool), "{tool} must be in the table (FR-POL-15)");
        }
    }
}
