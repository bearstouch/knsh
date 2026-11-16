//! A code-signing service whose answer the test sets (KNSH-067).

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::lock;
use crate::control::{CodeSigning, SignatureFacts};
use crate::error::PlatformError;

/// Reports the same scripted facts (or failure) for the sender of every message, whatever the message is, and counts
/// the questions: a test can show a refused peer was never inspected, or that every message was.
#[derive(Debug)]
pub struct FakeCodeSigning {
    answer: Mutex<Result<SignatureFacts, PlatformError>>,
    calls: AtomicUsize,
}

impl FakeCodeSigning {
    /// A service that answers `answer` until [`FakeCodeSigning::set`] changes it.
    #[must_use]
    pub fn answering(answer: Result<SignatureFacts, PlatformError>) -> Self {
        Self {
            answer: Mutex::new(answer),
            calls: AtomicUsize::new(0),
        }
    }

    /// From now on answers `answer`: the peer changed identity (for example it exec'd another binary).
    pub fn set(&self, answer: Result<SignatureFacts, PlatformError>) {
        *lock(&self.answer) = answer;
    }

    /// How many senders were inspected.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl<M: ?Sized> CodeSigning<M> for FakeCodeSigning {
    fn inspect(&self, _message: &M) -> Result<SignatureFacts, PlatformError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.answer).clone()
    }
}
