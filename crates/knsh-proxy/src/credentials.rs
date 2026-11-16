//! Per-command proxy credentials (FR-NET-01, decision 14).
//!
//! Every envelope and every spawned line gets its own credentials, issued here and carried as the user and password
//! of its proxy URL (`http://knsh-<id>:<token>@127.0.0.1:<port>`). The proxy maps them back to an [`Owner`], the
//! session and (for a line) the record, so every connection is tied to one command and session.
//!
//! - **Id:** a decimal counter, unique for the life of the table, so a revoked id is never issued again and a late
//!   connection with an old id is unknown rather than someone else's.
//! - **Token:** [`TOKEN_LEN`] letters and digits from the injected random source (about 190 bits). Letters and digits
//!   only, so no tool has to percent-decode them (decision 14). Compared in constant time.
//! - **Revocation:** by line when it ends, by session when its envelope ends (which also revokes its lines). A revoked
//!   credential is unknown at once: the next request with it is refused with `407`.
//!
//! The table holds at most [`MAX_CREDENTIALS`] live credentials; beyond that, issuing fails and the command does not
//! start (fail closed), rather than letting the table grow without bound.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{RecordId, Redacted, SessionId};
use knsh_platform::Random;

use crate::error::ProxyError;

/// Letters and digits in a token: 62 symbols, so about 5.95 bits each.
pub const TOKEN_LEN: usize = 32;

/// Live credentials the table holds at most.
pub const MAX_CREDENTIALS: usize = 65_536;

/// The prefix of every proxy user name: `knsh-<id>` (decision 14).
pub const USER_PREFIX: &str = "knsh-";

/// The token alphabet: letters and digits only (decision 14).
const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The largest multiple of 62 that fits a byte: random bytes at or above it are drawn again, so every symbol is
/// equally likely.
const UNBIASED_LIMIT: u8 = 248;

/// Who a connection belongs to: a session, and the line (its record) when the credentials were a line's. Envelope
/// credentials have no line: their connections are attributed to the session alone (FR-NET-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Owner {
    /// The session.
    pub session: SessionId,
    /// The line's record, or `None` for the envelope.
    pub line: Option<RecordId>,
}

/// Credentials just issued: the id and token of the user name `knsh-<id>` and the password.
pub struct Issued {
    id: String,
    token: Redacted<String>,
}

impl Issued {
    /// The id, `<id>` in `knsh-<id>`: decimal digits.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The token, the password: [`TOKEN_LEN`] letters and digits.
    #[must_use]
    pub fn token(&self) -> &Redacted<String> {
        &self.token
    }
}

impl fmt::Debug for Issued {
    /// The id only: the token never reaches a log or a test failure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issued").field("id", &self.id).finish_non_exhaustive()
    }
}

/// One live credential.
struct Entry {
    token: [u8; TOKEN_LEN],
    owner: Owner,
}

/// The table's state, behind one lock.
struct State {
    /// The next id to issue. Never reused.
    next_id: u64,
    entries: HashMap<u64, Entry>,
}

/// The credential table (module documentation). `Send + Sync`: issued and revoked by the supervisor, read by every
/// connection thread.
pub struct Credentials {
    random: Arc<dyn Random>,
    state: Mutex<State>,
}

impl Credentials {
    /// An empty table that draws tokens from `random`, which must be a secure source in production.
    #[must_use]
    pub fn new(random: Arc<dyn Random>) -> Self {
        Self {
            random,
            state: Mutex::new(State {
                next_id: 1,
                entries: HashMap::new(),
            }),
        }
    }

    /// Takes the lock even if a thread panicked while holding it: every update is a single map operation that a
    /// panic cannot leave half done.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Issues new, unique credentials for `owner`.
    ///
    /// # Errors
    ///
    /// [`ProxyError::Random`] if the random source fails, [`ProxyError::TooManyCredentials`] if the table is full.
    /// Either way nothing is issued, and the caller must not start the command.
    pub fn issue(&self, owner: Owner) -> Result<Issued, ProxyError> {
        let token = self.token()?;
        let mut state = self.lock();
        if state.entries.len() >= MAX_CREDENTIALS {
            return Err(ProxyError::TooManyCredentials);
        }
        let id = state.next_id;
        state.next_id = id.checked_add(1).ok_or(ProxyError::TooManyCredentials)?;
        state.entries.insert(id, Entry { token, owner });
        let token = token.iter().map(|&byte| char::from(byte)).collect();
        Ok(Issued {
            id: id.to_string(),
            token: Redacted::new(token),
        })
    }

    /// A fresh token: unbiased letters and digits from the random source.
    fn token(&self) -> Result<[u8; TOKEN_LEN], ProxyError> {
        let mut token = [0; TOKEN_LEN];
        let mut filled = 0;
        let mut bytes = [0; TOKEN_LEN];
        while filled < TOKEN_LEN {
            self.random.fill(&mut bytes).map_err(|_| ProxyError::Random)?;
            for &byte in bytes.iter().filter(|&&byte| byte < UNBIASED_LIMIT) {
                if filled == TOKEN_LEN {
                    break;
                }
                token[filled] = ALPHABET[usize::from(byte % 62)];
                filled += 1;
            }
        }
        Ok(token)
    }

    /// The owner of the credentials `user` and `password`, or `None` if they are not live credentials: unknown user
    /// form, unknown or revoked id, or a wrong token.
    #[must_use]
    pub fn authenticate(&self, user: &[u8], password: &[u8]) -> Option<Owner> {
        let id = parse_user(user)?;
        let state = self.lock();
        let entry = state.entries.get(&id)?;
        constant_time_eq(&entry.token, password).then_some(entry.owner)
    }

    /// Revokes the credentials of the line `record`. Revoking credentials that are already gone does nothing.
    pub fn revoke_line(&self, record: RecordId) {
        self.lock().entries.retain(|_, entry| entry.owner.line != Some(record));
    }

    /// Revokes every credential of `session`: its envelope's and its lines'.
    pub fn revoke_session(&self, session: SessionId) {
        self.lock().entries.retain(|_, entry| entry.owner.session != session);
    }

    /// How many credentials are live.
    #[must_use]
    pub fn live(&self) -> usize {
        self.lock().entries.len()
    }
}

/// The id of a user name `knsh-<id>`: 1 to 20 decimal digits without a leading zero. `None` otherwise.
fn parse_user(user: &[u8]) -> Option<u64> {
    let digits = user.strip_prefix(USER_PREFIX.as_bytes())?;
    if digits.is_empty() || digits.len() > 20 || digits[0] == b'0' || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// Compares a token with a password without an early exit, so the time taken does not tell how many leading
/// characters matched. The length is not secret: every token has [`TOKEN_LEN`] characters.
fn constant_time_eq(token: &[u8; TOKEN_LEN], password: &[u8]) -> bool {
    if password.len() != TOKEN_LEN {
        return false;
    }
    token.iter().zip(password).fold(0, |diff, (a, b)| diff | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use knsh_core::Ulid;
    use knsh_platform::testing::SeededRandom;

    use super::*;

    fn table() -> Credentials {
        Credentials::new(Arc::new(SeededRandom::new(7)))
    }

    fn session(n: u128) -> SessionId {
        SessionId::from_ulid(Ulid::from_u128(n))
    }

    fn record(n: u128) -> RecordId {
        RecordId::from_ulid(Ulid::from_u128(n))
    }

    fn login(table: &Credentials, issued: &Issued) -> Option<Owner> {
        let user = format!("{USER_PREFIX}{}", issued.id());
        table.authenticate(user.as_bytes(), issued.token().expose().as_bytes())
    }

    // FR-NET-01: each line and envelope has its own credentials, mapped to its command and session.
    #[test]
    fn maps_credentials_to_command_and_session() {
        let table = table();
        let envelope = Owner {
            session: session(1),
            line: None,
        };
        let line = Owner {
            session: session(1),
            line: Some(record(10)),
        };
        let other = Owner {
            session: session(2),
            line: Some(record(20)),
        };
        let issued: Vec<Issued> = [envelope, line, other].map(|owner| table.issue(owner).unwrap()).into();
        assert_eq!(login(&table, &issued[0]), Some(envelope));
        assert_eq!(login(&table, &issued[1]), Some(line));
        assert_eq!(login(&table, &issued[2]), Some(other));
        // Unique ids and tokens, letters and digits only (decision 14).
        assert_ne!(issued[0].id(), issued[1].id());
        assert_ne!(issued[0].token().expose(), issued[1].token().expose());
        for credential in &issued {
            let token = credential.token().expose();
            assert_eq!(token.len(), TOKEN_LEN);
            assert!(token.bytes().all(|byte| byte.is_ascii_alphanumeric()));
            assert!(!format!("{credential:?}").contains(token.as_str()));
        }
    }

    // FR-NET-01: unknown ids, wrong tokens and other user forms map to nobody.
    #[test]
    fn refuses_unknown_credentials() {
        let table = table();
        let issued = table
            .issue(Owner {
                session: session(1),
                line: None,
            })
            .unwrap();
        let token = issued.token().expose().as_bytes();
        let mut wrong = token.to_vec();
        wrong[TOKEN_LEN - 1] ^= 1;
        for (user, password) in [
            (format!("{USER_PREFIX}99"), token.to_vec()),
            (format!("{USER_PREFIX}{}", issued.id()), wrong),
            (format!("{USER_PREFIX}{}", issued.id()), token[..TOKEN_LEN - 1].to_vec()),
            (format!("{USER_PREFIX}{}", issued.id()), Vec::new()),
            (format!("{USER_PREFIX}0{}", issued.id()), token.to_vec()),
            (format!("KNSH-{}", issued.id()), token.to_vec()),
            (issued.id().to_owned(), token.to_vec()),
            (USER_PREFIX.to_owned(), token.to_vec()),
        ] {
            assert_eq!(table.authenticate(user.as_bytes(), &password), None, "{user}");
        }
    }

    // FR-NET-01: a line's credentials die with the line; its envelope's stay until the session ends.
    #[test]
    fn revokes_credentials_when_line_ends() {
        let table = table();
        let envelope = table
            .issue(Owner {
                session: session(1),
                line: None,
            })
            .unwrap();
        let line = table
            .issue(Owner {
                session: session(1),
                line: Some(record(10)),
            })
            .unwrap();
        let other_session = table
            .issue(Owner {
                session: session(2),
                line: None,
            })
            .unwrap();
        table.revoke_line(record(10));
        assert_eq!(login(&table, &line), None);
        assert!(login(&table, &envelope).is_some());
        // Revoking again is harmless; a session's end takes the rest of its credentials only.
        table.revoke_line(record(10));
        let second_line = table
            .issue(Owner {
                session: session(1),
                line: Some(record(11)),
            })
            .unwrap();
        table.revoke_session(session(1));
        assert_eq!(login(&table, &envelope), None);
        assert_eq!(login(&table, &second_line), None);
        assert!(login(&table, &other_session).is_some());
        assert_eq!(table.live(), 1);
        // A revoked id is never issued again.
        let next = table
            .issue(Owner {
                session: session(3),
                line: None,
            })
            .unwrap();
        assert!(![envelope.id(), line.id(), second_line.id()].contains(&next.id()));
    }

    // Fail closed: a random source that fails issues nothing.
    #[test]
    fn issues_nothing_when_random_fails() {
        struct Broken;
        impl Random for Broken {
            fn fill(&self, _buf: &mut [u8]) -> Result<(), knsh_platform::PlatformError> {
                Err(knsh_platform::PlatformError::Os {
                    operation: knsh_platform::Operation::Random,
                    errno: 5,
                })
            }
        }
        let table = Credentials::new(Arc::new(Broken));
        let owner = Owner {
            session: session(1),
            line: None,
        };
        assert!(matches!(table.issue(owner), Err(ProxyError::Random)));
        assert_eq!(table.live(), 0);
    }
}
