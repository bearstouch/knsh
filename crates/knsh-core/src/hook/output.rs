//! A hook's answer: its stdout and how it exited, read as a verdict (`specs/05-models/hook.md#output`, FR-HOOK-02,
//! FR-HOOK-03).
//!
//! The output is untrusted (a hook may echo agent text back): its size is checked before it is parsed, the JSON
//! reader bounds depth, and anything outside the documented object is refused rather than guessed at. [`judge`]
//! returning `None` is an error, which the chain turns into a deny (FR-HOOK-04).

use knsh_json::{Fields, Value};

/// Most bytes of stdout a hook may print. Large enough for a `rewrite` of a line at the
/// [`MAX_LINE_LEN`](crate::MAX_LINE_LEN) limit with escapes; more is an error.
pub const MAX_HOOK_OUTPUT: usize = 256 * 1024;

/// Longest `reason`, in bytes.
pub const MAX_HOOK_REASON_LEN: usize = 1024;

/// Most labels one `annotate` may carry.
pub const MAX_HOOK_LABELS: usize = 16;

/// Longest label, in bytes.
pub const MAX_HOOK_LABEL_LEN: usize = 64;

/// How a hook's process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookExit {
    /// It exited with this code.
    Exited(i32),
    /// A signal ended it.
    Signalled,
}

/// One hook's verdict (`specs/03-functional-requirements/hooks.md#verdicts`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookReply {
    /// No objection.
    Allow,
    /// Refuse the line.
    Deny {
        /// Shown to the agent.
        reason: Option<String>,
    },
    /// Escalate to the authority.
    Ask {
        /// Why, if the hook said.
        reason: Option<String>,
    },
    /// Replace the line.
    Rewrite {
        /// The new line.
        command: String,
    },
    /// Add labels to the record; decides nothing.
    Annotate {
        /// The labels, each checked against the label charset.
        labels: Vec<String>,
    },
}

/// Reads a hook's verdict from its `stdout` and `exit` (`specs/05-models/hook.md#output`). `None` is an error: the
/// output is too long, not one valid object, or the exit was not clean.
#[must_use]
pub fn judge(stdout: &[u8], exit: HookExit) -> Option<HookReply> {
    if stdout.len() > MAX_HOOK_OUTPUT {
        return None;
    }
    // FR-HOOK-03: a hook that prints nothing (or only whitespace, such as a bare `echo`) is judged by its exit code.
    if stdout.iter().all(u8::is_ascii_whitespace) {
        return match exit {
            HookExit::Exited(0) => Some(HookReply::Allow),
            HookExit::Exited(2) => Some(HookReply::Deny { reason: None }),
            HookExit::Exited(_) | HookExit::Signalled => None,
        };
    }
    // A verdict from a hook that then failed is not trusted: it may have been cut short.
    if exit != HookExit::Exited(0) {
        return None;
    }
    let value = knsh_json::parse(stdout, MAX_HOOK_OUTPUT).ok()?;
    parse_reply(&value)
}

/// `{verdict, reason?, command?, labels?}`, nothing else, with each member allowed only where it means something.
fn parse_reply(value: &Value) -> Option<HookReply> {
    let mut fields = Fields::new(value).ok()?;
    let verdict: String = fields.required("verdict").ok()?;
    let reason: Option<String> = fields.optional("reason").ok()?;
    let command: Option<String> = fields.optional("command").ok()?;
    let labels: Option<Vec<String>> = fields.optional("labels").ok()?;
    fields.finish_closed().ok()?;
    if reason.as_deref().is_some_and(|reason| !is_reason(reason)) {
        return None;
    }
    match (verdict.as_str(), command, labels) {
        ("allow", None, None) => Some(HookReply::Allow),
        ("deny", None, None) => Some(HookReply::Deny { reason }),
        ("ask", None, None) => Some(HookReply::Ask { reason }),
        // The pipeline checks the new line's length and content when it accepts the rewrite (FR-AUTH-32).
        ("rewrite", Some(command), None) if !command.is_empty() => Some(HookReply::Rewrite { command }),
        ("annotate", None, Some(labels))
            if (1..=MAX_HOOK_LABELS).contains(&labels.len()) && labels.iter().all(|label| is_label(label)) =>
        {
            Some(HookReply::Annotate { labels })
        }
        _ => None,
    }
}

/// A reason shown to the agent: bounded, and without control characters that could drive its terminal.
fn is_reason(reason: &str) -> bool {
    reason.len() <= MAX_HOOK_REASON_LEN && !reason.chars().any(char::is_control)
}

/// A label: 1 to [`MAX_HOOK_LABEL_LEN`] bytes of `A-Z a-z 0-9 . _ : -`, so a label cannot carry line text.
fn is_label(label: &str) -> bool {
    (1..=MAX_HOOK_LABEL_LEN).contains(&label.len())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}
