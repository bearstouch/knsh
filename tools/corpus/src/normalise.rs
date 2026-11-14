//! The normaliser: replaces personal and secret-like values in a command line with stable placeholders.
//!
//! Decision 7 and NFR-PRIV-08: every corpus line is normalised before it is stored. Paths, user names, hosts and
//! anything secret-like become placeholders, so the corpus can be published with the repository.
//!
//! The normaliser is a pure function made of passes that each rewrite one kind of value. It is **idempotent**: a
//! placeholder never matches any pass, and the passes are repeated until the line stops changing, so
//! `normalise(normalise(x)) == normalise(x)`. The CI gate relies on this: a
//! corpus line that changes when normalised again still holds a raw value ([`crate::check`]).
//!
//! Placeholders are upper-case words wrapped in double underscores. They contain no shell metacharacters, so a
//! normalised line has the same shell structure as the original (a word stays one word).
//!
//! The rules are heuristics tuned to keep shell structure readable; they prefer replacing too much over too little
//! for secrets, and keep values that are not personal (loopback addresses, `git@` remotes, commit IDs, UUIDs).

use std::net::{Ipv4Addr, Ipv6Addr};

/// Placeholder for a user name (in home paths, `~name`, URL user info, `user@<IPv4>`, `-u user:password` and names
/// given to the importer with `--user`).
pub const USER: &str = "__USER__";
/// Placeholder for a private or given host name.
pub const HOST: &str = "__HOST__";
/// Placeholder for an IPv4 or IPv6 address other than loopback or unspecified.
pub const IP: &str = "__IP__";
/// Placeholder for an e-mail address.
pub const EMAIL: &str = "__EMAIL__";
/// Placeholder for a secret-like value: a known token, a high-entropy string or the value of a secret-named variable.
pub const SECRET: &str = "__SECRET__";
/// Placeholder for the per-user part of the macOS temporary directory (`/var/folders/xx/yyyy`).
pub const TMP: &str = "__TMP__";

/// Known values to scrub from one trace, besides the pattern-based rules.
///
/// A CI trace knows its runner's user and host name; passing them here removes them wherever they appear, including
/// places the patterns cannot recognise (`ssh deploy@build01`).
#[derive(Debug, Clone, Default)]
pub struct Scrub {
    /// User names, replaced by [`USER`].
    pub users: Vec<String>,
    /// Host names, replaced by [`HOST`].
    pub hosts: Vec<String>,
}

/// Returns `command` with every personal or secret-like value replaced by a placeholder.
///
/// Idempotent for any `scrub`: normalising the output again with the same `scrub` returns it unchanged.
///
/// # Example
///
/// ```
/// use knsh_corpus::{Scrub, normalise};
/// let line = "cd /Users/alice/src && GITHUB_TOKEN=s3cr3t-value gh pr list";
/// assert_eq!(
///     normalise(line, &Scrub::default()),
///     "cd /Users/__USER__/src && GITHUB_TOKEN=__SECRET__ gh pr list"
/// );
/// ```
#[must_use]
pub fn normalise(command: &str, scrub: &Scrub) -> String {
    // One round of passes is not always a fixpoint: a pass can create a new match for an earlier one (an `IP`
    // placeholder glued to `sk-` forms a token; a replaced value puts a scheme such as `Bearer ` at a word boundary).
    // Repeating the round until nothing changes makes the result idempotent. Every change turns raw bytes into
    // placeholders, so the loop settles in a round or two; the bound only guards against a pass bug, and a line that
    // still changes is then refused by the gate's fixpoint check ([`crate::check`]).
    let mut out = normalise_once(command, scrub);
    for _ in 0..MAX_ROUNDS {
        let next = normalise_once(&out, scrub);
        if next == out {
            break;
        }
        out = next;
    }
    out
}

/// Upper bound on extra rounds of passes in [`normalise`].
const MAX_ROUNDS: usize = 16;

/// One round of every pass, in order.
fn normalise_once(command: &str, scrub: &Scrub) -> String {
    // Order matters: secrets go first so a token is never split by a later pass (a token inside a URL or an
    // e-mail-like string is replaced whole), and the entropy rule goes last as the catch-all.
    let mut out = scrub_known(command, scrub);
    out = jwt_tokens(&out);
    out = prefixed_tokens(&out);
    out = secret_assignments_and_flags(&out);
    out = authorization_values(&out);
    out = user_flag_credentials(&out);
    out = url_userinfo(&out);
    out = emails(&out);
    out = home_paths(&out);
    out = tilde_users(&out);
    out = macos_temp_dirs(&out);
    out = private_hosts(&out);
    out = ipv4_addresses(&out);
    out = ipv6_addresses(&out);
    high_entropy_strings(&out)
}

// ---------------------------------------------------------------------------------------------------------------
// Character classes and helpers. Every pattern is ASCII, so the passes scan bytes and only ever cut the string at an
// ASCII byte: slicing at those indices is always on a UTF-8 boundary, and non-ASCII text is copied through as is.
// ---------------------------------------------------------------------------------------------------------------

/// Characters of a token: what a secret, identifier or base64url string is made of.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Characters of an identifier (variable names, word boundaries for known values).
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Characters that end a shell word or a path segment. Anything else (including non-ASCII) stays inside it.
fn is_word_delimiter(b: u8) -> bool {
    b.is_ascii_whitespace() || b"/'\"`;|&()<>:,=\\".contains(&b)
}

/// True for a placeholder this module writes, so passes never rewrite their own output (idempotence).
fn is_placeholder(s: &str) -> bool {
    [USER, HOST, IP, EMAIL, SECRET, TMP].contains(&s)
}

/// Rewrites every maximal run of bytes matching `is_run`. `f` gets the run and the bytes before and after it and
/// returns the replacement, or `None` to keep the run.
fn map_runs(s: &str, is_run: impl Fn(u8) -> bool, mut f: impl FnMut(&str, &[u8], &[u8]) -> Option<String>) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut copied = 0;
    while i < bytes.len() {
        if !is_run(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_run(bytes[i]) {
            i += 1;
        }
        if let Some(replacement) = f(&s[start..i], &bytes[..start], &bytes[i..]) {
            out.push_str(&s[copied..start]);
            out.push_str(&replacement);
            copied = i;
        }
    }
    out.push_str(&s[copied..]);
    out
}

/// The first index at or after `from` whose byte does not satisfy `keep` (or `bytes.len()`).
fn scan_while(bytes: &[u8], from: usize, keep: impl Fn(u8) -> bool) -> usize {
    bytes
        .iter()
        .skip(from)
        .position(|&b| !keep(b))
        .map_or(bytes.len(), |offset| from + offset)
}

/// A pass's decision for the text after one occurrence of its marker: how far it scanned, and optionally the end of
/// the span to replace (the span starts right after the marker) with its replacement.
type MarkerEdit = (usize, Option<(usize, String)>);

/// Rewrites the text that follows each occurrence of `marker`. `f` gets the index just past the marker.
///
/// The search resumes after the scanned text, never inside it, so a pass does not re-read what it just rewrote and
/// every later occurrence lies after the last replaced span.
fn rewrite_after_marker(s: &str, marker: &str, mut f: impl FnMut(usize) -> MarkerEdit) -> String {
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let mut from = 0;
    while let Some(pos) = s[from..].find(marker).map(|p| p + from) {
        let start = pos + marker.len();
        let (scanned_end, edit) = f(start);
        if let Some((end, replacement)) = edit {
            out.push_str(&s[copied..start]);
            out.push_str(&replacement);
            copied = end;
        }
        from = scanned_end.max(start);
    }
    out.push_str(&s[copied..]);
    out
}

/// Shannon entropy of `s` in bits per byte.
fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[usize::from(b)] += 1;
    }
    // Lengths are bounded by the entry limit, far below f64's exact-integer range.
    #[allow(clippy::cast_precision_loss)]
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

// ---------------------------------------------------------------------------------------------------------------
// Passes.
// ---------------------------------------------------------------------------------------------------------------

/// Replaces the user and host names given for this trace, at identifier boundaries.
fn scrub_known(s: &str, scrub: &Scrub) -> String {
    let mut out = s.to_owned();
    for (values, placeholder) in [(&scrub.users, USER), (&scrub.hosts, HOST)] {
        for value in values {
            // Very short values would match inside unrelated words; such names must be scrubbed by pattern rules.
            if value.len() < 3 || is_placeholder(value) {
                continue;
            }
            out = replace_bounded(&out, value, placeholder);
        }
    }
    out
}

/// Replaces `needle` where it is not part of a longer identifier.
fn replace_bounded(s: &str, needle: &str, replacement: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let mut from = 0;
    while let Some(pos) = s[from..].find(needle).map(|p| p + from) {
        let end = pos + needle.len();
        let before_ok = pos == 0 || !is_ident_byte(bytes[pos - 1]);
        let after_ok = end == bytes.len() || !is_ident_byte(bytes[end]);
        if before_ok && after_ok {
            out.push_str(&s[copied..pos]);
            out.push_str(replacement);
            copied = end;
            // Resume after the replaced text: a self-overlapping value (`box.box` in `box.box.box`) must not match
            // again inside what was already copied.
            from = end;
            continue;
        }
        // Advance past the first character of the match; `find` returns char boundaries, so this stays on one.
        from = pos + s[pos..].chars().next().map_or(1, char::len_utf8);
    }
    out.push_str(&s[copied..]);
    out
}

/// JSON Web Tokens: `eyJ…` header, `.`, `eyJ…` payload, `.`, signature.
fn jwt_tokens(s: &str) -> String {
    map_runs(
        s,
        |b| is_token_byte(b) || b == b'.',
        |run, _, _| {
            let mut parts = run.split('.');
            let header = parts.next()?;
            let payload = parts.next()?;
            (header.starts_with("eyJ") && payload.starts_with("eyJ") && header.len() >= 10 && payload.len() >= 10)
                .then(|| SECRET.to_owned())
        },
    )
}

/// The alphabet allowed after a token prefix.
#[derive(Clone, Copy)]
enum Alphabet {
    /// Letters and digits only.
    Alnum,
    /// Letters, digits, `_` and `-`.
    Token,
}

/// Known token prefixes, the minimum length of what follows, and its alphabet. Minimum lengths sit below the real
/// token lengths so truncated tokens are still caught, and above the length of ordinary words with the same prefix.
const TOKEN_PREFIXES: &[(&str, usize, Alphabet)] = &[
    ("github_pat_", 20, Alphabet::Token),
    ("ghp_", 20, Alphabet::Alnum),
    ("gho_", 20, Alphabet::Alnum),
    ("ghu_", 20, Alphabet::Alnum),
    ("ghs_", 20, Alphabet::Alnum),
    ("ghr_", 20, Alphabet::Alnum),
    ("sk-", 16, Alphabet::Token),
    ("sk_live_", 16, Alphabet::Alnum),
    ("sk_test_", 16, Alphabet::Alnum),
    ("rk_live_", 16, Alphabet::Alnum),
    ("rk_test_", 16, Alphabet::Alnum),
    ("xoxa-", 10, Alphabet::Token),
    ("xoxb-", 10, Alphabet::Token),
    ("xoxe-", 10, Alphabet::Token),
    ("xoxp-", 10, Alphabet::Token),
    ("xoxs-", 10, Alphabet::Token),
    ("glpat-", 16, Alphabet::Token),
    ("npm_", 20, Alphabet::Alnum),
    ("pypi-", 32, Alphabet::Token),
    ("hf_", 20, Alphabet::Alnum),
    ("AKIA", 16, Alphabet::Alnum),
    ("ASIA", 16, Alphabet::Alnum),
    ("AIza", 30, Alphabet::Token),
    ("shpat_", 20, Alphabet::Alnum),
    ("dop_v1_", 32, Alphabet::Alnum),
];

/// The known prefix `run` starts with, if what follows it has the prefix's alphabet and minimum length.
#[must_use]
pub(crate) fn known_token_prefix(run: &str) -> Option<&'static str> {
    TOKEN_PREFIXES.iter().find_map(|&(prefix, min, alphabet)| {
        let rest = run.strip_prefix(prefix)?;
        let ok = rest.len() >= min
            && rest.bytes().all(|b| match alphabet {
                Alphabet::Alnum => b.is_ascii_alphanumeric(),
                Alphabet::Token => is_token_byte(b),
            });
        ok.then_some(prefix)
    })
}

/// Tokens with a known vendor prefix (`ghp_…`, `sk-…`, `AKIA…`), replaced whole.
fn prefixed_tokens(s: &str) -> String {
    map_runs(s, is_token_byte, |run, _, _| {
        known_token_prefix(run).map(|_| SECRET.to_owned())
    })
}

/// Suffix components that make a secret-looking name a reference to a secret rather than the secret itself.
const NON_SECRET_SUFFIXES: &[&str] = &["FILE", "PATH", "DIR", "NAME", "ID", "ENV", "VAR", "STDIN", "URL", "CMD"];

/// True for a variable or flag name whose value is a secret, such as `GITHUB_TOKEN`, `PGPASSWORD`, `OPENAI_API_KEY`
/// or `--client-secret`. `name` is upper-cased with `-` mapped to `_` by the caller.
fn is_secret_name(name: &str) -> bool {
    let parts: Vec<&str> = name.split('_').filter(|p| !p.is_empty()).collect();
    let Some(&last) = parts.last() else { return false };
    if NON_SECRET_SUFFIXES.contains(&last) {
        return false;
    }
    // `TOKENIZERS_PARALLELISM` must not match, so `TOKEN` has to end a component.
    if last.ends_with("TOKEN") || last == "PAT" {
        return true;
    }
    if parts.len() >= 2 && last == "KEY" {
        let before = parts[parts.len() - 2];
        if [
            "API",
            "ACCESS",
            "PRIVATE",
            "AUTH",
            "SIGNING",
            "ENCRYPTION",
            "SECRET",
            "MASTER",
            "LICENSE",
        ]
        .contains(&before)
        {
            return true;
        }
    }
    parts.iter().any(|p| {
        [
            "PASSWORD",
            "PASSWD",
            "PASSPHRASE",
            "SECRET",
            "APIKEY",
            "CREDENTIAL",
            "CREDENTIALS",
        ]
        .iter()
        .any(|k| p.contains(k))
    })
}

/// The value of an assignment or flag starting at `start`: its end and its replacement, or `None` to keep it.
///
/// Values that reference a secret instead of holding one (`$TOKEN`, `"$(cat key)"`), empty values and placeholders
/// are kept. Quoting is preserved so the shell structure does not change.
fn redact_value(s: &str, start: usize) -> Option<(usize, String)> {
    let bytes = s.as_bytes();
    let first = *bytes.get(start)?;
    match first {
        b'"' | b'\'' => {
            // Find the closing quote; inside double quotes a backslash escapes the next byte.
            let mut i = start + 1;
            while i < bytes.len() && bytes[i] != first {
                i += if first == b'"' && bytes[i] == b'\\' { 2 } else { 1 };
            }
            let close = i.min(bytes.len());
            let inner = &s[start + 1..close];
            if inner.is_empty() || inner.starts_with('$') || inner == SECRET {
                return None;
            }
            // An unterminated quote stays unterminated: the normaliser never repairs shell syntax.
            let quote = char::from(first);
            let end = if close < bytes.len() { close + 1 } else { close };
            let tail = if close < bytes.len() {
                quote.to_string()
            } else {
                String::new()
            };
            Some((end, format!("{quote}{SECRET}{tail}")))
        }
        b'$' | b'-' => None,
        _ => {
            let end = scan_while(bytes, start, |b| {
                !b.is_ascii_whitespace() && !b";|&()<>'\"`".contains(&b)
            });
            let word = &s[start..end];
            (!word.is_empty() && word != SECRET).then(|| (end, SECRET.to_owned()))
        }
    }
}

/// Values of secret-named assignments (`GITHUB_TOKEN=…`, `export PGPASSWORD=…`) and long flags (`--password …`,
/// `--api-key=…`).
fn secret_assignments_and_flags(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        let at_boundary = i == 0 || !is_ident_byte(bytes[i - 1]) && bytes[i - 1] != b'-';
        // `NAME=value`: an identifier at a word boundary followed by `=` (and not `==`).
        if at_boundary && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            let start = i;
            i = scan_while(bytes, start, is_ident_byte);
            let name = s[start..i].to_ascii_uppercase();
            if bytes.get(i) == Some(&b'=')
                && bytes.get(i + 1) != Some(&b'=')
                && is_secret_name(&name)
                && let Some((end, replacement)) = redact_value(s, i + 1)
            {
                out.push_str(&s[copied..=i]);
                out.push_str(&replacement);
                copied = end;
                i = end;
            }
            continue;
        }
        // `--name=value` or `--name value`.
        if at_boundary && bytes[i..].starts_with(b"--") {
            let start = i + 2;
            let j = scan_while(bytes, start, |b| is_ident_byte(b) || b == b'-');
            let name = s[start..j].to_ascii_uppercase().replace('-', "_");
            // The value follows `=` or a single space.
            if matches!(bytes.get(j), Some(b'=' | b' '))
                && is_secret_name(&name)
                && let Some((end, replacement)) = redact_value(s, j + 1)
            {
                out.push_str(&s[copied..=j]);
                out.push_str(&replacement);
                copied = end;
                i = end;
                continue;
            }
            i = j.max(i + 1);
            continue;
        }
        i += 1;
    }
    out.push_str(&s[copied..]);
    out
}

/// Credentials in HTTP authorisation values: `Bearer …`, `Basic …` and GitHub's `Authorization: token …`.
fn authorization_values(s: &str) -> String {
    let mut out = s.to_owned();
    for scheme in [
        "Bearer ",
        "bearer ",
        "Basic ",
        "basic ",
        "Authorization: token ",
        "authorization: token ",
    ] {
        let bytes = out.as_bytes();
        out = rewrite_after_marker(&out, scheme, |value_start| {
            let pos = value_start - scheme.len();
            // `XBearer abc` is not a scheme: the marker must start a word.
            let boundary = pos == 0 || !is_ident_byte(bytes[pos - 1]);
            let end = scan_while(bytes, value_start, |b| {
                !b.is_ascii_whitespace() && !b"'\"`;|&()<>".contains(&b)
            });
            let value = &out[value_start..end];
            let redact = boundary && !value.is_empty() && !value.starts_with('$') && value != SECRET;
            (end, redact.then(|| (end, SECRET.to_owned())))
        });
    }
    out
}

/// Credentials given as `user:password` after `-u` or `--user` (`curl -u alice:pw`, `--user=alice:pw`) become
/// `__USER__:__SECRET__`. Only the colon form is touched: `-u` alone means many things (`git push -u origin`,
/// `sudo -u postgres`), and all-numeric pairs (`docker run -u 1000:1000`) are IDs, not credentials.
fn user_flag_credentials(s: &str) -> String {
    let mut out = s.to_owned();
    for flag in ["-u ", "--user ", "--user="] {
        let bytes = out.as_bytes();
        out = rewrite_after_marker(&out, flag, |value_start| {
            let pos = value_start - flag.len();
            let boundary = pos == 0 || bytes[pos - 1].is_ascii_whitespace();
            // An optional quote around the value is kept as is.
            let quote = bytes.get(value_start).copied().filter(|b| matches!(b, b'\'' | b'"'));
            let inner_start = value_start + usize::from(quote.is_some());
            let end = match quote {
                // A quoted value may hold spaces: it runs to the closing quote (or the end of an unterminated one).
                Some(q) => scan_while(bytes, inner_start, |b| b != q),
                None => scan_while(bytes, inner_start, |b| {
                    !b.is_ascii_whitespace() && !b"'\"`;|&()<>".contains(&b)
                }),
            };
            let value = &out[inner_start..end];
            let Some((user, password)) = value.split_once(':') else {
                return (end, None);
            };
            let numeric = |v: &str| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit());
            if !boundary || (numeric(user) && numeric(password)) {
                return (end, None);
            }
            let keep = |v: &str| v.is_empty() || v.starts_with('$') || is_placeholder(v);
            let new_user = if keep(user) || numeric(user) || GENERIC_USERS.contains(&user) {
                user
            } else {
                USER
            };
            let new_password = if keep(password) { password } else { SECRET };
            let replacement = format!("{new_user}:{new_password}");
            let edit =
                (replacement != value).then(|| (end, format!("{}{replacement}", &out[value_start..inner_start])));
            (end, edit)
        });
    }
    out
}

/// User names that identify a protocol role, not a person, and are kept in URLs and `git@host` remotes.
const GENERIC_USERS: &[&str] = &["git", "x-access-token", "oauth2", "anonymous", "ftp"];

/// User info in URLs: `scheme://user:password@host` becomes `scheme://__USER__:__SECRET__@host`.
fn url_userinfo(s: &str) -> String {
    let bytes = s.as_bytes();
    rewrite_after_marker(s, "://", |authority_start| {
        let end = scan_while(bytes, authority_start, |b| {
            !b.is_ascii_whitespace() && !b"/?#'\"`;|&()<>".contains(&b)
        });
        // The last `@` ends the user info (a password may itself contain `@` only percent-encoded, but be safe).
        let Some(at) = s[authority_start..end].rfind('@').map(|p| p + authority_start) else {
            return (end, None);
        };
        let userinfo = &s[authority_start..at];
        let (user, password) = match userinfo.split_once(':') {
            Some((user, password)) => (user, Some(password)),
            None => (userinfo, None),
        };
        let keep_user =
            user.is_empty() || user.starts_with('$') || is_placeholder(user) || GENERIC_USERS.contains(&user);
        let new_user = if keep_user { user } else { USER };
        let new_password = password.map(|p| if p.is_empty() || p.starts_with('$') { p } else { SECRET });
        let replacement = match new_password {
            Some(p) => format!("{new_user}:{p}"),
            None => new_user.to_owned(),
        };
        // Only the user info is replaced; the host after `@` is left to the host and address passes.
        let edit = (replacement != userinfo).then_some((at, replacement));
        (end, edit)
    })
}

/// E-mail addresses (`local@domain.tld`), except `git@` remotes and user info already handled as part of a URL. The
/// user name of `user@<IPv4>` becomes [`USER`].
fn emails(s: &str) -> String {
    let bytes = s.as_bytes();
    let is_local = |b: u8| b.is_ascii_alphanumeric() || b"._%+-".contains(&b);
    let is_domain = |b: u8| b.is_ascii_alphanumeric() || b == b'.' || b == b'-';
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'@' || i < copied {
            i += 1;
            continue;
        }
        let mut start = i;
        while start > copied && is_local(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = scan_while(bytes, i + 1, is_domain);
        // A trailing `.` or `-` ends a sentence or a flag, not the domain.
        while end > i + 1 && matches!(bytes[end - 1], b'.' | b'-') {
            end -= 1;
        }
        let local = &s[start..i];
        let domain = &s[i + 1..end];
        let tld_ok = domain.rsplit_once('.').is_some_and(|(name, tld)| {
            !name.is_empty() && tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
        });
        let in_url = start > 0 && matches!(bytes[start - 1], b':' | b'/');
        // `_` is in the local-part class, so a placeholder before `@` (`__USER__@host`, or `__EMAIL__@x.de` left by
        // an earlier match on `a@b.co@x.de`) must be kept explicitly, or a second run would rewrite it (idempotence).
        let keep_local = local.is_empty() || in_url || is_placeholder(local) || GENERIC_USERS.contains(&local);
        if !keep_local && tld_ok {
            out.push_str(&s[copied..start]);
            out.push_str(EMAIL);
            copied = end;
            i = end;
            continue;
        }
        // `user@10.0.0.5` (ssh, scp): the address is left to the IPv4 pass, but the user name is personal.
        if !keep_local && domain.parse::<Ipv4Addr>().is_ok() {
            out.push_str(&s[copied..start]);
            out.push_str(USER);
            copied = i;
        }
        i += 1;
    }
    out.push_str(&s[copied..]);
    out
}

/// Home directory names that are not a person's.
const SHARED_HOMES: &[&str] = &["Shared", "Guest", "runner"];

/// `/Users/<name>` and `/home/<name>` become `/Users/__USER__` and `/home/__USER__`.
fn home_paths(s: &str) -> String {
    let mut out = s.to_owned();
    for root in ["/Users/", "/home/"] {
        let bytes = out.as_bytes();
        out = rewrite_after_marker(&out, root, |seg_start| {
            let seg_end = scan_while(bytes, seg_start, |b| !is_word_delimiter(b));
            let name = &out[seg_start..seg_end];
            // Variables and globs (`/Users/$USER`, `/home/*`) are not names.
            let keep = name.is_empty()
                || is_placeholder(name)
                || SHARED_HOMES.contains(&name)
                || name.starts_with('$')
                || name.contains(['*', '?', '[', '{']);
            (seg_end, (!keep).then(|| (seg_end, USER.to_owned())))
        });
    }
    out
}

/// `~name` at the start of a word becomes `~__USER__` (`~`, `~/`, `~+` and `~-` are kept).
fn tilde_users(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'~' || i < copied {
            continue;
        }
        let word_start = i == 0 || bytes[i - 1].is_ascii_whitespace() || b"=:'\"(".contains(&bytes[i - 1]);
        let name_start = i + 1;
        let end = scan_while(bytes, name_start, |b| is_ident_byte(b) || b == b'-' || b == b'.');
        let name = &s[name_start..end];
        let ends_word = end == bytes.len() || bytes[end] == b'/' || is_word_delimiter(bytes[end]);
        let starts_like_name = name
            .bytes()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_');
        if word_start && ends_word && starts_like_name && !is_placeholder(name) {
            out.push_str(&s[copied..name_start]);
            out.push_str(USER);
            copied = end;
        }
    }
    out.push_str(&s[copied..]);
    out
}

/// `/var/folders/<xx>/<random>` (the per-user macOS temporary directory) becomes `/var/folders/__TMP__`.
fn macos_temp_dirs(s: &str) -> String {
    const ROOT: &str = "/var/folders/";
    let bytes = s.as_bytes();
    let segment_end = |from: usize| scan_while(bytes, from, |b| !is_word_delimiter(b));
    rewrite_after_marker(s, ROOT, |start| {
        let first_end = segment_end(start);
        let mut end = first_end;
        // Consume the second segment too: both are derived from the user's ID. An empty one (`xx//`) is not consumed.
        if bytes.get(first_end) == Some(&b'/') {
            let second_end = segment_end(first_end + 1);
            if second_end > first_end + 1 {
                end = second_end;
            }
        }
        let first = &s[start..first_end];
        let replace = !first.is_empty() && !is_placeholder(first) && !first.starts_with('$');
        (end, replace.then(|| (end, TMP.to_owned())))
    })
}

/// Domain suffixes that only name private machines; such host names are personal and always replaced.
const PRIVATE_SUFFIXES: &[&str] = &[".internal", ".lan", ".corp", ".intranet", ".home.arpa", ".localdomain"];

/// Host names under private suffixes. `.local` (mDNS) is replaced only after `://` or `@`, because file names such as
/// `.env.local` share the suffix.
fn private_hosts(s: &str) -> String {
    map_runs(
        s,
        |b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-',
        |run, before, _| {
            let lower = run.to_ascii_lowercase();
            let host_context = before.ends_with(b"://") || before.ends_with(b"@");
            let private = PRIVATE_SUFFIXES
                .iter()
                .chain(host_context.then_some(&".local"))
                .any(|suffix| lower.len() > suffix.len() && lower.ends_with(suffix) && !lower.starts_with('.'));
            private.then(|| HOST.to_owned())
        },
    )
}

/// IPv4 addresses other than loopback (`127.0.0.0/8`) and `0.0.0.0`, which are kept because they say where a
/// command connects without naming a machine.
fn ipv4_addresses(s: &str) -> String {
    map_runs(
        s,
        |b| b.is_ascii_digit() || b == b'.',
        |run, before, after| {
            // A run glued to letters is part of a version or identifier (`v1.2.3.4`, `1.2.3.4a`).
            if before.last().is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                || after.first().is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
            {
                return None;
            }
            let trimmed = run.trim_end_matches('.');
            let address: Ipv4Addr = trimmed.parse().ok()?;
            if address.is_loopback() || address.is_unspecified() {
                return None;
            }
            Some(format!("{IP}{}", &run[trimmed.len()..]))
        },
    )
}

/// IPv6 addresses other than `::1` and `::`.
fn ipv6_addresses(s: &str) -> String {
    map_runs(
        s,
        |b| b.is_ascii_hexdigit() || b == b':' || b == b'.',
        |run, before, after| {
            if run.matches(':').count() < 2
                || before.last().is_some_and(|b| is_ident_byte(*b))
                || after.first().is_some_and(|b| is_ident_byte(*b))
            {
                return None;
            }
            let address: Ipv6Addr = run.parse().ok()?;
            (!address.is_loopback() && !address.is_unspecified()).then(|| IP.to_owned())
        },
    )
}

/// Minimum length of a string the entropy rule considers.
const ENTROPY_MIN_LEN: usize = 32;
/// Minimum Shannon entropy, in bits per byte, of a secret-like string. Random base62 or base64 strings of 32 bytes
/// or more score about 4.4 or higher; identifiers and words score well below 4.
const ENTROPY_MIN_BITS: f64 = 4.0;
/// Hex strings up to this length are kept: they are commit IDs (40) or shorter hashes, which commands name often.
const HEX_KEEP_MAX_LEN: usize = 40;

/// Long strings that look random: hex longer than a commit ID, or mixed-case alphanumeric (base64) strings of at
/// least 32 bytes with high entropy.
fn high_entropy_strings(s: &str) -> String {
    map_runs(
        s,
        |b| is_token_byte(b) || b == b'+' || b == b'=',
        |run, _, _| is_high_entropy(run).then(|| SECRET.to_owned()),
    )
}

/// True if `run` looks like a random secret rather than a word, identifier, UUID or commit ID.
pub(crate) fn is_high_entropy(run: &str) -> bool {
    // Trailing `=` is base64 padding. An `=` left inside joins two words (`--flag=value`, `NAME=value`): only the
    // value is judged.
    let body = run.trim_end_matches('=');
    if let Some((_, value)) = body.split_once('=').filter(|(name, _)| !name.is_empty()) {
        return is_high_entropy(value);
    }
    if body.len() < ENTROPY_MIN_LEN {
        return false;
    }
    if body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return body.len() > HEX_KEEP_MAX_LEN;
    }
    let has_lower = body.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = body.bytes().any(|b| b.is_ascii_uppercase());
    let digits = body.bytes().filter(u8::is_ascii_digit).count();
    has_lower && has_upper && digits >= 2 && entropy(body) >= ENTROPY_MIN_BITS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> String {
        normalise(s, &Scrub::default())
    }

    // KNSH-033, NFR-PRIV-08.
    #[test]
    fn normalises_home_paths_to_placeholder() {
        assert_eq!(n("cd /Users/alice/src/app"), "cd /Users/__USER__/src/app");
        assert_eq!(n("cat /home/bob/.bashrc"), "cat /home/__USER__/.bashrc");
        assert_eq!(n("ls '/Users/josé.luis/Documents'"), "ls '/Users/__USER__/Documents'");
        assert_eq!(n("cp a /Users/carol"), "cp a /Users/__USER__");
        assert_eq!(n("ls ~dave/bin ~ ~/x ~+ ~-"), "ls ~__USER__/bin ~ ~/x ~+ ~-");
        assert_eq!(
            n("ls /private/var/folders/x7/abc123_def/T/tmp.1"),
            "ls /private/var/folders/__TMP__/T/tmp.1"
        );
    }

    #[test]
    fn keeps_home_paths_that_are_not_names() {
        for line in [
            "ls /Users/Shared",
            "ls /Users/$USER/x",
            "ls /home/*/x",
            "ls /Users/",
            "echo $HOME/x",
        ] {
            assert_eq!(n(line), line);
        }
    }

    // KNSH-033: known prefixes and long base64.
    #[test]
    fn normalises_secret_like_tokens() {
        assert_eq!(
            n("gh auth login --with-token ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
            "gh auth login --with-token __SECRET__"
        );
        assert_eq!(
            n("curl -H 'x-api-key: sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv' https://api.example.com"),
            "curl -H 'x-api-key: __SECRET__' https://api.example.com"
        );
        assert_eq!(
            n("export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrst"),
            "export OPENAI_API_KEY=__SECRET__"
        );
        assert_eq!(
            n("aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE"),
            "aws configure set aws_access_key_id __SECRET__"
        );
        assert_eq!(
            n("echo dGhpcyBpcyBhIHZlcnkgc2VjcmV0IHZhbHVlIDEyMzQ1Njc4OTA= | base64 -d"),
            "echo __SECRET__ | base64 -d"
        );
        assert_eq!(
            n("npm config set //registry.npmjs.org/:_authToken=npm_abcdefghijABCDEFGHIJ0123456789"),
            "npm config set //registry.npmjs.org/:_authToken=__SECRET__"
        );
        assert_eq!(
            n("curl -H \"Authorization: Bearer abc.def-123\" https://x.example.com"),
            "curl -H \"Authorization: Bearer __SECRET__\" https://x.example.com"
        );
        assert_eq!(
            n("TOKEN=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc ./run"),
            "TOKEN=__SECRET__ ./run"
        );
        assert_eq!(
            n("hexkey 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
            "hexkey __SECRET__"
        );
    }

    #[test]
    fn redacts_secret_named_assignments_and_flags() {
        assert_eq!(n("GITHUB_TOKEN=abc gh pr list"), "GITHUB_TOKEN=__SECRET__ gh pr list");
        assert_eq!(
            n("export PGPASSWORD='hunter2'; psql"),
            "export PGPASSWORD='__SECRET__'; psql"
        );
        assert_eq!(n("mysql --password=\"p w\" db"), "mysql --password=\"__SECRET__\" db");
        assert_eq!(n("tool --client-secret s3 --x"), "tool --client-secret __SECRET__ --x");
        // References to secrets are kept: they reveal nothing and matter to the classifier.
        for line in [
            "GITHUB_TOKEN=$GH_TOKEN gh pr list",
            "export API_KEY=\"$(cat key)\"",
            "docker login --password-stdin -u x",
            "TOKENIZERS_PARALLELISM=false python t.py",
            "GITHUB_TOKEN_FILE=/run/secret ./x",
            "[ \"$a\" == b ]",
        ] {
            assert_eq!(n(line), line);
        }
    }

    #[test]
    fn normalises_users_hosts_and_ips() {
        assert_eq!(
            n("git clone https://alice:pa55@git.corp.internal/x.git"),
            "git clone https://__USER__:__SECRET__@__HOST__/x.git"
        );
        assert_eq!(
            n("git config user.email alice@example.com"),
            "git config user.email __EMAIL__"
        );
        assert_eq!(
            n("git clone git@github.com:org/repo.git"),
            "git clone git@github.com:org/repo.git"
        );
        // `user@host.tld` reads as an e-mail address; either way neither part survives.
        assert_eq!(n("ssh dev@mac-mini.local uptime"), "ssh __EMAIL__ uptime");
        assert_eq!(n("curl http://mac-mini.local:8080/"), "curl http://__HOST__:8080/");
        assert_eq!(n("cp .env.example .env.local"), "cp .env.example .env.local");
        assert_eq!(n("curl http://192.168.1.20:8080/x"), "curl http://__IP__:8080/x");
        assert_eq!(n("ping -c1 10.0.0.1."), "ping -c1 __IP__.");
        assert_eq!(
            n("curl http://127.0.0.1:3000 http://0.0.0.0:80"),
            "curl http://127.0.0.1:3000 http://0.0.0.0:80"
        );
        assert_eq!(
            n("curl -g http://[fe80::1ff:fe23:4567:890a]/"),
            "curl -g http://[__IP__]/"
        );
        assert_eq!(n("curl http://[::1]:8000/"), "curl http://[::1]:8000/");
        assert_eq!(
            n("pip install foo==1.2.3 && ver v1.2.3.4"),
            "pip install foo==1.2.3 && ver v1.2.3.4"
        );
        assert_eq!(n("cargo test knsh::parse::tests"), "cargo test knsh::parse::tests");
    }

    // KNSH-033 review: user names before an IPv4 address and `-u user:password` credentials were left raw.
    #[test]
    fn normalises_user_at_ip_and_user_flag_credentials() {
        assert_eq!(n("ssh alice@10.0.0.5 uptime"), "ssh __USER__@__IP__ uptime");
        assert_eq!(n("scp f bob@192.168.1.2:/tmp"), "scp f __USER__@__IP__:/tmp");
        assert_eq!(n("ssh git@10.0.0.5"), "ssh git@__IP__");
        assert_eq!(n("npm i lodash@4.17.21"), "npm i lodash@4.17.21");
        assert_eq!(
            n("curl -u alice:hunter2 https://example.com"),
            "curl -u __USER__:__SECRET__ https://example.com"
        );
        assert_eq!(n("curl --user=alice:pw x"), "curl --user=__USER__:__SECRET__ x");
        assert_eq!(n("curl --user 'alice:p w' x"), "curl --user '__USER__:__SECRET__' x");
        assert_eq!(n("curl -u \"$U:$P\" x"), "curl -u \"$U:$P\" x");
        for line in [
            "docker run -u 1000:1000 img",
            "git push -u origin main",
            "sudo -u postgres psql",
            "diff -u a b",
        ] {
            assert_eq!(n(line), line);
        }
    }

    #[test]
    fn scrubs_known_users_and_hosts() {
        let scrub = Scrub {
            users: vec!["deploy".into()],
            hosts: vec!["build01".into()],
        };
        assert_eq!(
            normalise("ssh deploy@build01 'ls'", &scrub),
            "ssh __USER__@__HOST__ 'ls'"
        );
        // A self-overlapping value is replaced without re-matching inside the replacement.
        let overlapping = Scrub {
            users: vec![],
            hosts: vec!["box.box".into()],
        };
        assert_eq!(normalise("ssh box.box.box", &overlapping), "ssh __HOST__.box");
        // Not inside longer identifiers.
        assert_eq!(normalise("./deployment build01x", &scrub), "./deployment build01x");
    }

    #[test]
    fn keeps_ordinary_agent_commands() {
        for line in [
            "git checkout 3f2a9c1d8e7b6a5f4e3d2c1b0a9f8e7d6c5b4a39",
            "docker run --rm 550e8400-e29b-41d4-a716-446655440000",
            "cargo test -p knsh-bash normalises_home_paths_to_placeholder_and_more",
            "rg -n 'fn main' src/ | head -20",
            "npm install react@18 @types/node",
            "python -m pytest tests/test_models.py::TestUserModel::test_create -x",
            "sed -i '' 's/foo/bar/g' README.md",
            "printf '%s\\n' \"${PATH//:/ }\"",
        ] {
            assert_eq!(n(line), line);
        }
    }

    // KNSH-033: idempotence is what the CI fixpoint check relies on.
    #[test]
    fn normalisation_is_idempotent() {
        let scrub = Scrub {
            users: vec!["alice".into()],
            hosts: vec!["box".into()],
        };
        for line in [
            "cd /Users/alice/src && GITHUB_TOKEN=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8 gh pr list",
            "git clone https://alice:pa55@git.corp.internal/x.git",
            "git clone https://ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8@github.com/o/r",
            "curl -u alice:pw https://alice@box.lan:8443 -H 'Authorization: token abc'",
            "echo alice@example.com 10.1.2.3 fe80::1 ~alice/x /var/folders/ab/cd/T",
            "export SECRET=\"unterminated",
            "PASSWORD= ./x; API_KEY='' ./y",
            "echo QWxhZGRpbjpvcGVuIHNlc2FtZQ0KQWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            // Review regressions: a second `@` after a replaced address, and placeholders before `@`.
            "echo a@b.co@c.de __USER__@example.com",
            "ssh alice@10.0.0.5; curl -u alice:pw --user 'bob:p w' x",
            // Review regressions: one round of passes creating a match for an earlier pass.
            "sk-10.0.0.1--password",
            "Basic eyJhbGciOiJIUzI1Bearer Bearer A1b2C3d4E5f6G7h8I9j0K =.lan",
            "xAuthorization: token Authorization: token abc",
        ] {
            let once = normalise(line, &scrub);
            assert_eq!(normalise(&once, &scrub), once, "not idempotent for {line:?}");
        }
    }
}
