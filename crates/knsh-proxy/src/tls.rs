//! The TLS server-name reader: the name a client puts in its `ClientHello`, read without decrypting (KNSH-061;
//! FR-NET-06, NFR-SEC-05, NFR-SEC-07).
//!
//! After a tunnel is granted, the first bytes a TLS client sends are its `ClientHello`, in clear. Its `server_name`
//! extension (RFC 6066, section 3) names the host the client means to talk to, and a server that hosts several names
//! (a CDN, a shared front end) routes by it. A command allowed to reach `github.com` could otherwise ask for
//! `CONNECT github.com:443` and then name another host served from the same front end (domain fronting). The proxy
//! therefore reads the `ClientHello` before it lets any byte through, and [`check_server_name`] opens the tunnel only
//! if the name matches the host that was checked.
//!
//! # What is read ([`read_client_hello`])
//!
//! - **Records** (RFC 8446, section 5.1): only `handshake` records (type 22), record version `3.0` to `3.3`, each
//!   1 to 2^14 bytes. The `ClientHello` may be split across several records; they are joined. A record of any other
//!   type before the `ClientHello` is complete, or handshake bytes after it in its last record, are refused.
//! - **The `ClientHello`** (RFC 8446, section 4.1.2; RFC 5246, section 7.4.1.2): the first handshake message, of type
//!   1, at most [`MAX_CLIENT_HELLO`] bytes. Every length field must fit inside its parent exactly, extension types
//!   must not repeat, and the `server_name` extension must hold exactly one `host_name` entry, a valid DNS name
//!   (normalised: ASCII lower case, no trailing dot) and not an IP literal (RFC 6066 forbids them).
//! - **Encrypted Client Hello** (extension `0xfe0d`): the real name is encrypted and the clear one is the
//!   provider's public name, so the hello is treated as naming no server ([`ServerName::Encrypted`]).
//!
//! Nothing is repaired: a malformed hello, or bytes that are not TLS, are refused ([`HelloError`]). The reader is a
//! pure function of its input; it can be called again as more bytes arrive and never reads past
//! [`MAX_HELLO_BYTES`].
//!
//! # Allocation
//!
//! While the hello is incomplete the reader only walks record headers. Once complete, it copies the hello's
//! fragments into one buffer of the length the handshake header declared, which is at most [`MAX_CLIENT_HELLO`]
//! plus the 4-byte header: no length field can make it allocate more (NFR-SEC-07).

use crate::gate::Refusal;
use crate::target::Host;

/// Longest `ClientHello` body accepted, in bytes: the most one record can carry (2^14). Real hellos are well under it
/// (about 0.5 to 2 KiB, post-quantum key shares included); a longer one is refused ([`HelloError::TooLarge`]).
pub const MAX_CLIENT_HELLO: usize = 16_384;

/// Most bytes the proxy reads from a client before its `ClientHello` must be complete: the hello and its handshake
/// header, plus room for the headers of the records it is split into. Over it, the hello is refused.
pub const MAX_HELLO_BYTES: usize = 20_480;

/// Length of a TLS record header: type, version, length.
const RECORD_HEADER: usize = 5;
/// Length of a handshake message header: type, 24-bit length.
const HANDSHAKE_HEADER: usize = 4;
/// Longest record fragment (`TLSPlaintext.length`, RFC 8446, section 5.1).
const MAX_FRAGMENT: usize = 16_384;
/// Record content type `handshake`.
const CONTENT_HANDSHAKE: u8 = 22;
/// Handshake message type `client_hello`.
const CLIENT_HELLO: u8 = 1;
/// Extension `server_name` (RFC 6066).
const EXT_SERVER_NAME: u16 = 0;
/// Extension `encrypted_client_hello` (RFC 9849, formerly draft-ietf-tls-esni).
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// `NameType.host_name` (RFC 6066).
const HOST_NAME: u8 = 0;
/// Longest `legacy_session_id` (RFC 8446, section 4.1.2).
const MAX_SESSION_ID: usize = 32;

/// The server name a complete `ClientHello` carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerName {
    /// A host name, normalised like a destination name ([`Host::Name`]): ASCII lower case, no trailing dot.
    Name(String),
    /// No `server_name` extension at all.
    Absent,
    /// The client offered Encrypted Client Hello: the clear name is not the one it means, so none is trusted.
    Encrypted,
}

/// Why bytes were refused as a `ClientHello`. All of them refuse the tunnel ([`Refusal::NotTls`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloError {
    /// The bytes are not a TLS handshake starting with a `ClientHello` (plain HTTP, SSH, an SSL 2 hello, …).
    NotTls,
    /// A TLS-looking `ClientHello` that breaks the grammar: a length that overruns its parent or leaves bytes over,
    /// a repeated extension, an empty or invalid server name, another record type in the middle.
    Malformed,
    /// The hello is longer than [`MAX_CLIENT_HELLO`], or is not complete within [`MAX_HELLO_BYTES`].
    TooLarge,
}

/// How far the bytes read so far get toward a `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloState {
    /// Valid so far, but more bytes are needed. Only returned for input shorter than [`MAX_HELLO_BYTES`].
    Incomplete,
    /// A complete, well-formed `ClientHello` and the server name it carries. Bytes after its last record (a
    /// `change_cipher_spec`, early data) are not looked at: they belong to the tunnel.
    Complete(ServerName),
    /// Refused: the tunnel must not open.
    Refused(HelloError),
}

/// Reads the `ClientHello` at the start of `data` (module documentation). Pure and total: it never panics, whatever
/// `data` holds, and can be called again with the same bytes plus more.
#[must_use]
pub fn read_client_hello(data: &[u8]) -> HelloState {
    match hello_bounds(data) {
        Ok(Some(total)) => match join_fragments(data, total).and_then(|hello| parse_client_hello(&hello)) {
            Ok(name) => HelloState::Complete(name),
            Err(error) => HelloState::Refused(error),
        },
        // The caller reads at most `MAX_HELLO_BYTES`: still incomplete at that point is too large.
        Ok(None) if data.len() >= MAX_HELLO_BYTES => HelloState::Refused(HelloError::TooLarge),
        Ok(None) => HelloState::Incomplete,
        Err(error) => HelloState::Refused(error),
    }
}

/// Whether a tunnel to `host` may open for a `ClientHello` naming `name` (FR-NET-06): the names are equal (both are
/// normalised, so case and a trailing dot do not matter). An IP-literal destination has no name to compare, and
/// RFC 6066 forbids naming an address, so it opens only for a hello that names no server.
///
/// # Errors
///
/// [`Refusal::ServerNameMismatch`] for another name (or any name for an IP literal);
/// [`Refusal::ServerNameMissing`] for a name host with no name, or Encrypted Client Hello.
pub fn check_server_name(host: &Host, name: &ServerName) -> Result<(), Refusal> {
    match (host, name) {
        (Host::Name(host), ServerName::Name(name)) if host == name => Ok(()),
        (Host::Ip(_), ServerName::Absent) => Ok(()),
        (Host::Name(_) | Host::Ip(_), ServerName::Name(_)) => Err(Refusal::ServerNameMismatch),
        (Host::Name(_), ServerName::Absent) | (Host::Name(_) | Host::Ip(_), ServerName::Encrypted) => {
            Err(Refusal::ServerNameMissing)
        }
    }
}

/// Walks the record headers at the start of `data` and returns the total length of the `ClientHello` message
/// (handshake header included) once every byte of it is there, `None` while more are needed. Refuses as early as
/// the bytes allow, so a client that is not speaking TLS is turned away on its first byte.
fn hello_bounds(data: &[u8]) -> Result<Option<usize>, HelloError> {
    let mut pos = 0;
    // Handshake bytes in the complete records walked so far.
    let mut handshake = 0;
    // The handshake header, which may itself be split across records, and the message length it declares.
    let mut header = [0; HANDSHAKE_HEADER];
    let mut total: Option<usize> = None;
    loop {
        let rest = data.get(pos..).unwrap_or_default();
        // A bad record header on the first record means the client is not speaking TLS at all; on a later one, it is
        // a TLS client that broke the record layer.
        let bad_record = if pos == 0 {
            HelloError::NotTls
        } else {
            HelloError::Malformed
        };
        // Each header byte is checked as soon as it arrives, so a non-TLS client is refused on its first byte. The
        // record version must be 3.0 to 3.3: TLS 1.3 still writes 3.1 or 3.3 here (RFC 8446, section 5.1).
        match rest {
            [] => return Ok(None),
            [kind, ..] if *kind != CONTENT_HANDSHAKE => return Err(bad_record),
            [_, major, ..] if *major != 3 => return Err(bad_record),
            [_, _, minor, ..] if *minor > 3 => return Err(bad_record),
            _ => {}
        }
        let Some(&[_, _, _, high, low]) = rest.get(..RECORD_HEADER) else {
            return Ok(None);
        };
        let length = usize::from(u16::from_be_bytes([high, low]));
        // RFC 8446 forbids empty handshake fragments; a longer one than 2^14 is a record-layer error.
        if length == 0 || length > MAX_FRAGMENT {
            return Err(HelloError::Malformed);
        }
        let end = pos + RECORD_HEADER + length;
        if end > MAX_HELLO_BYTES {
            return Err(HelloError::TooLarge);
        }
        // The handshake header may be readable before the whole record is: check its type and length early, so a
        // client that is not sending a ClientHello is not waited for.
        if total.is_none() {
            // Cannot panic: `rest` holds at least the record header (checked above).
            let available = &rest[RECORD_HEADER..rest.len().min(RECORD_HEADER + length)];
            for (at, &byte) in (handshake..HANDSHAKE_HEADER).zip(available) {
                if at == 0 && byte != CLIENT_HELLO {
                    return Err(HelloError::NotTls);
                }
                header[at] = byte;
            }
            if handshake + available.len() >= HANDSHAKE_HEADER {
                let body = (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
                if body > MAX_CLIENT_HELLO {
                    return Err(HelloError::TooLarge);
                }
                total = Some(HANDSHAKE_HEADER + body);
            }
        }
        if data.len() < end {
            return Ok(None);
        }
        handshake += length;
        pos = end;
        if let Some(total) = total {
            if handshake == total {
                return Ok(Some(total));
            }
            // A ClientHello must end with its record: anything after it in the same record is another handshake
            // message, which no client sends before the server answers.
            if handshake > total {
                return Err(HelloError::Malformed);
            }
        }
    }
}

/// Copies the `ClientHello`'s `total` bytes out of the records at the start of `data` into one buffer, without the
/// handshake header. [`hello_bounds`] checked the records and that they hold exactly `total` handshake bytes.
fn join_fragments(data: &[u8], total: usize) -> Result<Vec<u8>, HelloError> {
    let mut message = Vec::with_capacity(total);
    let mut pos = 0;
    while message.len() < total {
        let Some(&[_, _, _, high, low]) = data.get(pos..pos + RECORD_HEADER) else {
            return Err(HelloError::Malformed);
        };
        let length = usize::from(u16::from_be_bytes([high, low]));
        let fragment = data
            .get(pos + RECORD_HEADER..pos + RECORD_HEADER + length)
            .ok_or(HelloError::Malformed)?;
        message.extend_from_slice(fragment);
        pos += RECORD_HEADER + length;
    }
    // Unreachable while `hello_bounds` holds; kept so a record overrunning `total` is refused, never accepted.
    if message.len() != total {
        return Err(HelloError::Malformed);
    }
    message.drain(..HANDSHAKE_HEADER);
    Ok(message)
}

/// A bounds-checked reader over a byte slice: every read past the end is [`HelloError::Malformed`].
struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], HelloError> {
        if len > self.data.len() {
            return Err(HelloError::Malformed);
        }
        let (taken, rest) = self.data.split_at(len);
        self.data = rest;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8, HelloError> {
        match self.take(1)? {
            &[byte] => Ok(byte),
            _ => Err(HelloError::Malformed),
        }
    }

    fn u16(&mut self) -> Result<u16, HelloError> {
        match self.take(2)? {
            &[high, low] => Ok(u16::from_be_bytes([high, low])),
            _ => Err(HelloError::Malformed),
        }
    }

    /// A vector with a one-byte length prefix.
    fn vec8(&mut self) -> Result<&'a [u8], HelloError> {
        let len = self.u8()?;
        self.take(usize::from(len))
    }

    /// A vector with a two-byte length prefix.
    fn vec16(&mut self) -> Result<&'a [u8], HelloError> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Parses a `ClientHello` body and returns its server name.
fn parse_client_hello(body: &[u8]) -> Result<ServerName, HelloError> {
    let mut hello = Cursor { data: body };
    // `legacy_version`: 3.1 (TLS 1.0) to 3.3 (TLS 1.2, and TLS 1.3, which keeps 3.3 here). SSL 3.0 has no
    // extensions, so it could never name a server.
    let version = hello.u16()?;
    if !(0x0301..=0x0303).contains(&version) {
        return Err(HelloError::NotTls);
    }
    hello.take(32)?; // random
    if hello.vec8()?.len() > MAX_SESSION_ID {
        return Err(HelloError::Malformed);
    }
    let suites = hello.vec16()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(HelloError::Malformed);
    }
    if hello.vec8()?.is_empty() {
        return Err(HelloError::Malformed); // compression methods: at least `null`
    }
    // TLS 1.2 and earlier may omit the extensions entirely: such a hello names no server.
    if hello.is_empty() {
        return Ok(ServerName::Absent);
    }
    let extensions = hello.vec16()?;
    if !hello.is_empty() {
        return Err(HelloError::Malformed);
    }
    parse_extensions(extensions)
}

/// Walks the extensions block, refusing repeats (RFC 8446, section 4.2), and returns the server name.
fn parse_extensions(block: &[u8]) -> Result<ServerName, HelloError> {
    let mut extensions = Cursor { data: block };
    // One bit per extension type: repeats are found without allocating.
    let mut seen = [0_u64; 1024];
    let mut name = None;
    let mut encrypted = false;
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        // `kind / 64` is at most 1023, so the index is always in bounds.
        let (word, bit) = (usize::from(kind / 64), kind % 64);
        if seen[word] & (1 << bit) != 0 {
            return Err(HelloError::Malformed);
        }
        seen[word] |= 1 << bit;
        match kind {
            EXT_SERVER_NAME => name = Some(parse_server_name(data)?),
            EXT_ENCRYPTED_CLIENT_HELLO => encrypted = true,
            _ => {}
        }
    }
    // With ECH, the clear name is the provider's public name, not the host the client means (story note: treated as
    // missing, so refused).
    Ok(match (encrypted, name) {
        (true, _) => ServerName::Encrypted,
        (false, Some(name)) => ServerName::Name(name),
        (false, None) => ServerName::Absent,
    })
}

/// The `server_name` extension: a list holding exactly one `host_name` (RFC 6066 allows one per type and defines
/// no other type), a valid DNS name and not an address.
fn parse_server_name(data: &[u8]) -> Result<String, HelloError> {
    let mut extension = Cursor { data };
    let list = extension.vec16()?;
    if !extension.is_empty() {
        return Err(HelloError::Malformed);
    }
    let mut list = Cursor { data: list };
    if list.u8()? != HOST_NAME {
        return Err(HelloError::Malformed);
    }
    let name = list.vec16()?;
    if !list.is_empty() {
        return Err(HelloError::Malformed);
    }
    // The same normalisation as a destination name, so the two compare byte for byte.
    match Host::parse(name) {
        Some(Host::Name(name)) => Ok(name),
        Some(Host::Ip(_)) | None => Err(HelloError::Malformed),
    }
}

#[cfg(test)]
pub(crate) mod tests;
