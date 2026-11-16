//! A user-presence prompt whose answers the test scripts.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use super::lock;
use crate::presence::{Authenticated, NotAuthenticated, PromptReason, UserPresence};

/// One prompt the fake was asked to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    /// The reason text, exactly as the dialog would show it.
    pub reason: String,
    /// How long the caller was prepared to wait.
    pub timeout: Duration,
}

/// Answers each prompt with the next scripted answer, in order, and records every prompt. With nothing scripted it
/// refuses with [`NotAuthenticated::TimedOut`], as the real backend does when nobody is at the screen: a forgotten
/// script fails closed.
#[derive(Debug, Default)]
pub struct ScriptedPresence {
    answers: Mutex<VecDeque<Result<(), NotAuthenticated>>>,
    prompts: Mutex<Vec<Prompt>>,
}

impl ScriptedPresence {
    /// A prompt nobody answers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The next prompt succeeds.
    pub fn approve_next(&self) {
        lock(&self.answers).push_back(Ok(()));
    }

    /// The next prompt is refused with `refusal`.
    pub fn refuse_next(&self, refusal: NotAuthenticated) {
        lock(&self.answers).push_back(Err(refusal));
    }

    /// Every prompt shown so far, in order.
    #[must_use]
    pub fn prompts(&self) -> Vec<Prompt> {
        lock(&self.prompts).clone()
    }
}

impl UserPresence for ScriptedPresence {
    fn authenticate(&self, reason: &PromptReason, timeout: Duration) -> Result<Authenticated, NotAuthenticated> {
        lock(&self.prompts).push(Prompt {
            reason: reason.as_str().to_owned(),
            timeout,
        });
        let answer = lock(&self.answers)
            .pop_front()
            .unwrap_or(Err(NotAuthenticated::TimedOut));
        answer.map(|()| Authenticated::new())
    }
}
