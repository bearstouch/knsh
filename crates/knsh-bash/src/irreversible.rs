//! Irreversible actions before running: the built-in list and the argument readers it needs (KNSH-093; FR-IRR-01,
//! FR-IRR-02).
//!
//! Checkpoints restore files; they cannot take back a push, a deploy, a remote write or a sent request. Commands that
//! do such things are flagged before they run, so policy can ask about them (FR-IRR-05). This module holds the data
//! and the per-tool readers; matching a command against a pattern is policy's (`knsh-core`), which reads
//! [`BUILTIN_IRREVERSIBLE`] with the same rule matcher as `exec.ask`, normalised subcommands included (FR-POL-15), so
//! `git -c x=y push` is `git push`.
//!
//! # What is flagged
//!
//! - Every pattern of [`BUILTIN_IRREVERSIBLE`]: at least the FR-IRR-02 list (`git push`, `npm publish`, `docker push`,
//!   `kubectl apply`, `terraform apply`, `gh pr merge`, `ssh`, `scp`), plus a few commands of the same kind.
//! - `curl` sending anything but a read ([`curl_reason`]): an explicit `-X`/`--request` with a method other than
//!   `GET`, `HEAD`, `OPTIONS` or `TRACE`; otherwise `-T`/`--upload-file` (`PUT`), or a data or form option without
//!   `-G`/`--get` (`POST`). Plain `curl URL` is a `GET` and is not flagged. Each request of a line (`-:`/`--next`
//!   starts another) is read on its own, and `--expand-<option>` (curl 8.3+) is read as `--<option>`. A reason names
//!   only fixed words: a method outside `POST`, `PUT`, `PATCH`, `DELETE` and `CONNECT` is `curl (other method)`, so
//!   no text of the line (which could hold a secret) reaches a record or the authority through it.
//! - `rsync` with an operand on a remote host ([`rsync_reason`]): `host:path`, `user@host:path`, `host::module` or
//!   `rsync://…`. Only local paths are not flagged; as in rsync itself, a colon after a `/` (`./a:b`) is local.
//!
//! # Unknown arguments
//!
//! An argument built from an expansion may become anything when it runs (`-XPOST`, `host:path`), and a command whose
//! arguments are incomplete (`xargs`) receives more at run time. Like an ask rule that may match, such a command is
//! flagged (fail closed), with a reason saying the arguments were not known. A config file (`curl -K`) is read the
//! same way: what it sets is not known from the line.
//!
//! As every classifier result, this is an intent filter, never a security boundary: the proxy enforces what a line
//! may reach, and what it did reach is marked after it runs (FR-IRR-03).

/// Patterns flagged irreversible whatever the profile says (FR-IRR-02). Read like `exec.ask` patterns: the first
/// word names the program, later words its normalised arguments, and a command with more arguments matches too
/// (FR-POL-16). A profile's `approvals.irreversible_commands` adds to this list (FR-IRR-01), never removes from it.
pub const BUILTIN_IRREVERSIBLE: &[&str] = &[
    "git push",
    "npm publish",
    "pnpm publish",
    "yarn publish",
    "cargo publish",
    "docker push",
    "kubectl apply",
    "kubectl create",
    "kubectl delete",
    "kubectl replace",
    "kubectl patch",
    "terraform apply",
    "terraform destroy",
    "tofu apply",
    "tofu destroy",
    "gh pr merge",
    "gh release create",
    "ssh",
    "scp",
    "sftp",
];

/// The reason given when a command's arguments are not all known from the line.
const UNKNOWN_ARGUMENTS: &str = "arguments not known";

/// `curl` short options that take a value (as the rest of their cluster, or the next argument). The ones this
/// module reads (`X`, `d`, `F`, `T`, `K`) are among them.
const CURL_SHORT_VALUES: &str = "AbcCdDeEFHKmoPQrtTuUwxXyYz";

/// `curl` long options that take the next argument as their value, other than the ones read explicitly below.
/// Skipping a value keeps a value such as `-d` (a header named so) from being read as an option.
const CURL_LONG_VALUES: &[&str] = &[
    "--header",
    "--output",
    "--user",
    "--user-agent",
    "--url",
    "--cookie",
    "--cookie-jar",
    "--referer",
    "--max-time",
    "--connect-timeout",
    "--proxy",
    "--proxy-user",
    "--resolve",
    "--connect-to",
    "--cacert",
    "--capath",
    "--cert",
    "--key",
    "--range",
    "--retry",
    "--write-out",
    "--output-dir",
    "--dump-header",
    "--oauth2-bearer",
    "--interface",
    "--limit-rate",
    "--max-filesize",
    "--trace",
    "--trace-ascii",
    "--url-query",
];

/// Methods that only read: a `curl` sending one of these is not flagged.
const READ_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "TRACE"];

/// Write methods a reason names (`curl POST`). Any other method is reported as `curl (other method)`: the method is
/// text from the agent's line, and a reason must never carry such text (it could hold a secret, and upper-casing it
/// would hide it from the redactor), only fixed words.
const NAMED_WRITE_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE", "CONNECT"];

/// An explicit `curl` method (`-X`, `--request`, `-I`).
enum Method {
    /// The method, upper-cased.
    Named(String),
    /// Its value is built from an expansion, or missing.
    Unknown,
}

impl Method {
    /// The method `value` names, or [`Method::Unknown`] without one.
    fn of(value: Option<&str>) -> Self {
        value.map_or(Self::Unknown, |value| Self::Named(value.to_ascii_uppercase()))
    }
}

/// A body option that implies a method when no `-X` is given. Ordered: an upload (`PUT`) wins over data (`POST`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Body {
    /// A data or form option: a `POST` unless `-G` says otherwise.
    Data,
    /// `-T`/`--upload-file`: a `PUT`.
    Upload,
}

/// What the arguments of one `curl` set, as far as the method goes.
#[derive(Default)]
struct CurlState {
    /// The last explicit method of the current request (since the last `-:`/`--next`).
    method: Option<Method>,
    /// The strongest body option of the current request.
    body: Option<Body>,
    /// `-G`/`--get` in the current request: data goes into the query string of a `GET`.
    get: bool,
    /// Something whose effect is not known from the line (an expansion, a config file).
    unknown: bool,
    /// The reason of the first earlier request that writes.
    written: Option<String>,
}

impl CurlState {
    fn body(&mut self, body: Body) {
        self.body = self.body.max(Some(body));
    }

    /// Ends the current request (`-:`/`--next`, or the end of the arguments): keeps its reason if it is the first to
    /// write, and starts the next one afresh, as curl does (a `-G` of one request never makes another a read).
    fn next_request(&mut self) {
        let reason = match self.method.take() {
            Some(Method::Named(method)) => method_reason(&method),
            Some(Method::Unknown) => Some(format!("curl ({UNKNOWN_ARGUMENTS})")),
            None => match self.body {
                Some(Body::Upload) => method_reason("PUT"),
                Some(Body::Data) if !self.get => method_reason("POST"),
                Some(Body::Data) | None => None,
            },
        };
        if self.written.is_none() {
            self.written = reason;
        }
        self.body = None;
        self.get = false;
    }
}

/// The reason for an upper-cased `method`, or `None` for a read (module documentation).
fn method_reason(method: &str) -> Option<String> {
    if READ_METHODS.contains(&method) {
        None
    } else if NAMED_WRITE_METHODS.contains(&method) {
        Some(format!("curl {method}"))
    } else {
        Some("curl (other method)".to_owned())
    }
}

/// Why a `curl` command with `arguments` (after its name; `None` for one built from an expansion) is irreversible,
/// or `None` if it only reads (module documentation). `complete` is `false` when more arguments come at run time.
/// Each request of the line (`-:`/`--next` starts another) is read on its own; the first that writes gives the
/// reason.
///
/// The reason is `curl <METHOD>` (`curl POST`), `curl (other method)`, or `curl (arguments not known)`.
#[must_use]
pub fn curl_reason(arguments: &[Option<&str>], complete: bool) -> Option<String> {
    let mut state = CurlState {
        unknown: !complete,
        ..CurlState::default()
    };
    let mut index = 0;
    let mut operands_only = false;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        let Some(text) = argument else {
            // An expansion may be any option, `-XPOST` included.
            state.unknown = true;
            continue;
        };
        if operands_only || !text.starts_with('-') || *text == "-" {
            continue;
        }
        if *text == "--" {
            operands_only = true;
            continue;
        }
        // The argument after the option, if it exists and is not built from an expansion.
        let next = arguments.get(index).copied().flatten();
        if let Some(long) = text.strip_prefix("--") {
            index += curl_long(long, next, &mut state);
        } else {
            index += curl_short(&text[1..], next, &mut state);
        }
    }
    state.next_request();
    match state.written {
        Some(reason) => Some(reason),
        None if state.unknown => Some(format!("curl ({UNKNOWN_ARGUMENTS})")),
        None => None,
    }
}

/// Reads one long `curl` option (without its `--`), with `next` the argument after it; returns how many arguments
/// after it were consumed as its value (0 or 1).
fn curl_long(name: &str, next: Option<&str>, state: &mut CurlState) -> usize {
    // curl 8.3+: `--expand-<option>` is `--<option>` with `{{variables}}` expanded in its value (`--expand-data`).
    let name = name.strip_prefix("expand-").unwrap_or(name);
    match name {
        "request" => {
            state.method = Some(Method::of(next));
            1
        }
        "upload-file" => {
            state.body(Body::Upload);
            1
        }
        "get" => {
            state.get = true;
            0
        }
        "head" => {
            state.method = Some(Method::Named("HEAD".to_owned()));
            0
        }
        "next" => {
            state.next_request();
            0
        }
        "config" => {
            state.unknown = true;
            1
        }
        _ if name == "json" || name.starts_with("data") || name.starts_with("form") => {
            state.body(Body::Data);
            1
        }
        _ if CURL_LONG_VALUES.contains(&format!("--{name}").as_str()) => 1,
        _ => 0,
    }
}

/// Reads one short `curl` option cluster (without its `-`), with `next` the argument after it; returns how many
/// arguments after it were consumed as a value (0 or 1).
fn curl_short(letters: &str, next: Option<&str>, state: &mut CurlState) -> usize {
    for (offset, letter) in letters.char_indices() {
        if !CURL_SHORT_VALUES.contains(letter) {
            match letter {
                'G' => state.get = true,
                'I' => state.method = Some(Method::Named("HEAD".to_owned())),
                ':' => state.next_request(),
                _ => {}
            }
            continue;
        }
        // The rest of the cluster is the value; or, when nothing follows the letter, the next argument.
        let attached = &letters[offset + letter.len_utf8()..];
        let (value, consumed) = if attached.is_empty() {
            (next, 1)
        } else {
            (Some(attached), 0)
        };
        match letter {
            'X' => state.method = Some(Method::of(value)),
            'T' => state.body(Body::Upload),
            'd' | 'F' => state.body(Body::Data),
            'K' => state.unknown = true,
            _ => {}
        }
        return consumed;
    }
    0
}

/// `rsync` short options that take the next argument as their value.
const RSYNC_SHORT_VALUES: &str = "eBfMT";

/// `rsync` long options that take the next argument as their value (when not attached with `=`).
const RSYNC_LONG_VALUES: &[&str] = &[
    "--rsh",
    "--rsync-path",
    "--filter",
    "--exclude",
    "--exclude-from",
    "--include",
    "--include-from",
    "--files-from",
    "--temp-dir",
    "--partial-dir",
    "--compare-dest",
    "--copy-dest",
    "--link-dest",
    "--backup-dir",
    "--suffix",
    "--chmod",
    "--chown",
    "--usermap",
    "--groupmap",
    "--log-file",
    "--log-file-format",
    "--out-format",
    "--password-file",
    "--port",
    "--block-size",
    "--max-size",
    "--min-size",
    "--max-delete",
    "--timeout",
    "--contimeout",
    "--bwlimit",
    "--remote-option",
    "--sockopts",
    "--address",
    "--compress-choice",
    "--checksum-choice",
    "--iconv",
];

/// Why an `rsync` command with `arguments` (after its name; `None` for one built from an expansion) is irreversible,
/// or `None` if every operand is a local path (module documentation). `complete` is `false` when more arguments come
/// at run time.
///
/// The reason is `rsync to a remote host`, or `rsync (arguments not known)`.
#[must_use]
pub fn rsync_reason(arguments: &[Option<&str>], complete: bool) -> Option<String> {
    let mut unknown = !complete;
    let mut index = 0;
    let mut operands_only = false;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        let Some(text) = argument else {
            unknown = true;
            continue;
        };
        if !operands_only && text.starts_with('-') && *text != "-" {
            if *text == "--" {
                operands_only = true;
            } else if let Some(long) = text.strip_prefix("--") {
                if !long.contains('=') && RSYNC_LONG_VALUES.contains(text) {
                    index += 1;
                }
            } else {
                // The value is the rest of the cluster, or the next argument when the letter ends it.
                let letters = &text[1..];
                let valued = letters
                    .char_indices()
                    .find(|(_, letter)| RSYNC_SHORT_VALUES.contains(*letter));
                if valued.is_some_and(|(offset, letter)| offset + letter.len_utf8() == letters.len()) {
                    index += 1;
                }
            }
            continue;
        }
        if is_remote(text) {
            return Some("rsync to a remote host".to_owned());
        }
    }
    unknown.then(|| format!("rsync ({UNKNOWN_ARGUMENTS})"))
}

/// Whether an rsync operand names a remote host: `rsync://…`, or a `:` before any `/` (`host:path`,
/// `user@host:path`, `host::module`).
fn is_remote(operand: &str) -> bool {
    if operand.starts_with("rsync://") {
        return true;
    }
    match (operand.find(':'), operand.find('/')) {
        (Some(colon), Some(slash)) => colon < slash,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args<'a>(words: &[&'a str]) -> Vec<Option<&'a str>> {
        words.iter().map(|word| (*word != "$X").then_some(*word)).collect()
    }

    fn curl(words: &[&str]) -> Option<String> {
        curl_reason(&args(words), true)
    }

    fn rsync(words: &[&str]) -> Option<String> {
        rsync_reason(&args(words), true)
    }

    // FR-IRR-02: `curl` with POST, PUT, PATCH or DELETE is irreversible; a plain GET is not.
    #[test]
    fn curl_write_methods_are_flagged() {
        assert_eq!(curl(&["-X", "POST", "https://x"]), Some("curl POST".to_owned()));
        assert_eq!(curl(&["-XPUT", "https://x"]), Some("curl PUT".to_owned()));
        assert_eq!(
            curl(&["--request", "patch", "https://x"]),
            Some("curl PATCH".to_owned())
        );
        assert_eq!(curl(&["-sSX", "DELETE", "https://x"]), Some("curl DELETE".to_owned()));
        assert_eq!(curl(&["-d", "a=1", "https://x"]), Some("curl POST".to_owned()));
        assert_eq!(
            curl(&["--data-binary", "@f", "https://x"]),
            Some("curl POST".to_owned())
        );
        assert_eq!(curl(&["-F", "f=@a", "https://x"]), Some("curl POST".to_owned()));
        assert_eq!(curl(&["--json", "{}", "https://x"]), Some("curl POST".to_owned()));
        assert_eq!(curl(&["-T", "a.txt", "https://x"]), Some("curl PUT".to_owned()));
    }

    // FR-IRR-02: reads are not flagged.
    #[test]
    fn curl_reads_are_not_flagged() {
        assert_eq!(curl(&["https://x"]), None);
        assert_eq!(curl(&["-sSL", "-o", "out", "https://x"]), None);
        assert_eq!(curl(&["-X", "GET", "https://x"]), None);
        assert_eq!(curl(&["-I", "https://x"]), None);
        assert_eq!(curl(&["-G", "-d", "q=1", "https://x"]), None);
        // A header value that looks like an option is the header's value.
        assert_eq!(curl(&["-H", "-d", "https://x"]), None);
        assert_eq!(curl(&["--header", "-XPOST", "https://x"]), None);
        assert_eq!(curl(&["--", "-d"]), None);
    }

    // A reason never carries text from the line: a method outside the fixed names is reported as "other".
    #[test]
    fn curl_reason_never_carries_line_text() {
        assert_eq!(
            curl(&["-X", "sk-live-secret", "https://x"]),
            Some("curl (other method)".to_owned())
        );
        assert_eq!(curl(&["-XPURGE", "https://x"]), Some("curl (other method)".to_owned()));
    }

    // curl 8.3+ `--expand-<option>` is the option itself: `--expand-data` posts.
    #[test]
    fn curl_expand_options_are_read_as_the_option() {
        assert_eq!(
            curl(&["--expand-data", "{{v}}", "https://x"]),
            Some("curl POST".to_owned())
        );
        assert_eq!(
            curl(&["--expand-request", "DELETE", "https://x"]),
            Some("curl DELETE".to_owned())
        );
    }

    // Each request of `-:`/`--next` is read on its own: a later `-G` does not make an earlier POST a read.
    #[test]
    fn curl_next_request_is_read_on_its_own() {
        assert_eq!(
            curl(&["-d", "a=1", "https://x", "--next", "-G", "https://y"]),
            Some("curl POST".to_owned())
        );
        assert_eq!(
            curl(&["https://x", "-:", "-d", "a=1", "https://y"]),
            Some("curl POST".to_owned())
        );
        assert_eq!(
            curl(&["-X", "POST", "https://x", "--next", "https://y"]),
            Some("curl POST".to_owned())
        );
        assert_eq!(curl(&["-G", "https://x", "--next", "https://y"]), None);
    }

    // Unknown arguments may become any option: flagged, fail closed.
    #[test]
    fn curl_with_unknown_arguments_is_flagged() {
        let unknown = Some("curl (arguments not known)".to_owned());
        assert_eq!(curl(&["$X"]), unknown);
        assert_eq!(curl(&["-X", "$X", "https://x"]), unknown);
        assert_eq!(curl(&["-K", "conf", "https://x"]), unknown);
        assert_eq!(curl_reason(&args(&["https://x"]), false), unknown);
        // A known write method still names itself.
        assert_eq!(curl(&["-X", "POST", "$X"]), Some("curl POST".to_owned()));
    }

    // FR-IRR-02: `rsync` to a remote host is flagged; with only local paths it is not.
    #[test]
    fn rsync_remote_operands_are_flagged() {
        let remote = Some("rsync to a remote host".to_owned());
        assert_eq!(rsync(&["-av", "src/", "host:dst/"]), remote);
        assert_eq!(rsync(&["-av", "user@host:/dst", "."]), remote);
        assert_eq!(rsync(&["src", "host::module"]), remote);
        assert_eq!(rsync(&["src", "rsync://host/module"]), remote);
        assert_eq!(rsync(&["-e", "ssh -p 22", "src", "h:dst"]), remote);
    }

    #[test]
    fn rsync_local_only_is_not_flagged() {
        assert_eq!(rsync(&["-av", "src/", "dst/"]), None);
        assert_eq!(rsync(&["-a", "./a:b", "/tmp/x"]), None);
        // An option's value is not an operand.
        assert_eq!(rsync(&["--exclude", "h:x", "src", "dst"]), None);
        assert_eq!(rsync(&["-e", "h:x", "src", "dst"]), None);
        assert_eq!(rsync(&["--exclude=h:x", "src", "dst"]), None);
        assert_eq!(
            rsync(&["-av", "$X", "dst"]),
            Some("rsync (arguments not known)".to_owned())
        );
    }

    #[test]
    fn builtin_list_covers_fr_irr_02() {
        for pattern in [
            "git push",
            "npm publish",
            "docker push",
            "kubectl apply",
            "terraform apply",
            "gh pr merge",
            "ssh",
            "scp",
        ] {
            assert!(BUILTIN_IRREVERSIBLE.contains(&pattern), "{pattern}");
        }
    }
}
