//! A strict, hand-written reader for HTTP proxy request heads, and the proxy's fixed responses (FR-NET-01,
//! NFR-SEC-05, NFR-SEC-07).
//!
//! The proxy serves one thing over HTTP: `CONNECT host:port` with `Proxy-Authorization: Basic` (decision 14). Its
//! reader accepts exactly RFC 9112's request-line and header-field grammar and nothing looser:
//!
//! - lines end with CRLF; a bare CR or LF anywhere is malformed;
//! - the request line is `method SP target SP HTTP/1.1` (or `HTTP/1.0`), one space each, at most
//!   [`MAX_REQUEST_LINE`] bytes; a request line still unfinished after that many bytes is refused before more is
//!   read ([`head_state`]);
//! - at most [`MAX_HEADERS`] header lines of [`MAX_HEADER_LINE`] bytes, the whole head at most [`MAX_HEAD`] bytes;
//! - a header name is a token, a value has no control characters but tab; folded lines (`obs-fold`) are malformed;
//! - one `Proxy-Authorization` at most; `Transfer-Encoding`, or a `Content-Length` other than `0`, is malformed: a
//!   tunnel request carries no body, and a body would be smuggled into the tunnel.
//!
//! Malformed requests are refused, never repaired: no trimming beyond the optional whitespace around a header value,
//! no case folding of the method, no guessing.

/// Longest request line, without its CRLF.
pub const MAX_REQUEST_LINE: usize = 4096;
/// Longest header line, without its CRLF.
pub const MAX_HEADER_LINE: usize = 8192;
/// Most header lines.
pub const MAX_HEADERS: usize = 64;
/// Longest request head, its final empty line included.
pub const MAX_HEAD: usize = 16 * 1024;

/// The realm of the `407` challenge (decision 14).
pub const REALM: &str = "knsh";

/// How far a buffer holds a request head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadState {
    /// More bytes are needed.
    Incomplete,
    /// The head is the first `n` bytes, its empty line included.
    Complete(usize),
    /// The request line or the head is over its limit: refuse without reading more.
    TooLarge,
    /// A line ending other than CRLF (a bare LF, or a CR not followed by LF): refuse without waiting for a CRLF CRLF
    /// that a client using bare LF would never send.
    Malformed,
}

/// Where the head in `buf` ends, if it does, and whether it already broke a size limit. Only the first
/// [`MAX_HEAD`] bytes are ever looked at.
#[must_use]
pub fn head_state(buf: &[u8]) -> HeadState {
    let window = &buf[..buf.len().min(MAX_HEAD)];
    let end = find(window, b"\r\n\r\n").map(|at| at + 4);
    // Only the head itself is checked: bytes after it (a TLS ClientHello sent without waiting for the `200`)
    // belong to the tunnel and may hold any byte, a bare LF included.
    let head = &window[..end.unwrap_or(window.len())];
    let bare = head.iter().enumerate().any(|(at, &byte)| match byte {
        b'\n' => at == 0 || head[at - 1] != b'\r',
        b'\r' => head.get(at + 1).is_some_and(|&next| next != b'\n'),
        _ => false,
    });
    if bare {
        return HeadState::Malformed;
    }
    // The request line must end within its limit; refusing early keeps a client from making the proxy read 16 KiB
    // of a request line it will refuse anyway.
    let line_window = &window[..window.len().min(MAX_REQUEST_LINE + 2)];
    if find(line_window, b"\r\n").is_none() && window.len() >= MAX_REQUEST_LINE + 2 {
        return HeadState::TooLarge;
    }
    match end {
        Some(len) => HeadState::Complete(len),
        None if buf.len() >= MAX_HEAD => HeadState::TooLarge,
        None => HeadState::Incomplete,
    }
}

/// The first position of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Why a head was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    /// It broke the grammar or a rule of this module.
    Malformed,
    /// It is over a size or count limit.
    TooLarge,
}

/// What `Proxy-Authorization` carried.
#[derive(Clone, PartialEq, Eq)]
pub enum Authorization {
    /// No `Proxy-Authorization` header.
    Missing,
    /// Basic credentials: the user and password, split at the first `:` (RFC 7617).
    Basic {
        /// The user name.
        user: Vec<u8>,
        /// The password.
        password: Vec<u8>,
    },
    /// Another scheme, or Basic credentials that do not decode: never accepted (decision 14).
    Unusable,
}

impl std::fmt::Debug for Authorization {
    /// Never the password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("Missing"),
            Self::Basic { .. } => f.write_str("Basic { .. }"),
            Self::Unusable => f.write_str("Unusable"),
        }
    }
}

/// A request head that passed the grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    /// The method, exactly as sent (methods are case-sensitive).
    pub method: &'a [u8],
    /// The request target, exactly as sent.
    pub target: &'a [u8],
    /// The proxy credentials.
    pub authorization: Authorization,
}

impl Request<'_> {
    /// Whether this is a `CONNECT`, the only method the proxy serves.
    #[must_use]
    pub fn is_connect(&self) -> bool {
        self.method == b"CONNECT"
    }
}

/// Reads a complete head (as [`head_state`] delimits it, the final CRLF CRLF included).
///
/// # Errors
///
/// [`HttpError::TooLarge`] over a limit, [`HttpError::Malformed`] for anything outside the grammar (module
/// documentation).
pub fn parse_head(head: &[u8]) -> Result<Request<'_>, HttpError> {
    if head.len() > MAX_HEAD {
        return Err(HttpError::TooLarge);
    }
    let body = head.strip_suffix(b"\r\n\r\n").ok_or(HttpError::Malformed)?;
    let mut lines = split_crlf(body);
    let request_line = lines.next().ok_or(HttpError::Malformed)?;
    let (method, target) = parse_request_line(request_line)?;
    let mut authorization = None;
    let mut content_length = false;
    for (count, line) in lines.enumerate() {
        if count >= MAX_HEADERS || line.len() > MAX_HEADER_LINE {
            return Err(HttpError::TooLarge);
        }
        let (name, value) = parse_header(line)?;
        if name.eq_ignore_ascii_case(b"proxy-authorization") {
            if authorization.is_some() {
                return Err(HttpError::Malformed);
            }
            authorization = Some(parse_authorization(value));
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(HttpError::Malformed);
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if content_length || value != b"0" {
                return Err(HttpError::Malformed);
            }
            content_length = true;
        }
    }
    Ok(Request {
        method,
        target,
        authorization: authorization.unwrap_or(Authorization::Missing),
    })
}

/// Splits on CRLF. A line that still holds a CR or LF is caught by the line parsers.
fn split_crlf(body: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(body);
    std::iter::from_fn(move || {
        let current = rest?;
        if let Some(at) = find(current, b"\r\n") {
            rest = Some(&current[at + 2..]);
            Some(&current[..at])
        } else {
            rest = None;
            Some(current)
        }
    })
}

/// `method SP target SP version`: the method and target.
fn parse_request_line(line: &[u8]) -> Result<(&[u8], &[u8]), HttpError> {
    if line.len() > MAX_REQUEST_LINE {
        return Err(HttpError::TooLarge);
    }
    let mut parts = line.split(|&byte| byte == b' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HttpError::Malformed);
    };
    let valid = is_token(method)
        && !target.is_empty()
        && target.iter().all(|&byte| (0x21..=0x7e).contains(&byte))
        && (version == b"HTTP/1.1" || version == b"HTTP/1.0");
    if valid {
        Ok((method, target))
    } else {
        Err(HttpError::Malformed)
    }
}

/// `name ":" OWS value OWS`: the name and the value without its surrounding whitespace.
fn parse_header(line: &[u8]) -> Result<(&[u8], &[u8]), HttpError> {
    let colon = line.iter().position(|&byte| byte == b':').ok_or(HttpError::Malformed)?;
    let (name, value) = (&line[..colon], &line[colon + 1..]);
    // A name that is not a token covers `obs-fold` (a line starting with whitespace) and a space before the colon.
    if !is_token(name) {
        return Err(HttpError::Malformed);
    }
    let is_ows = |byte: &u8| *byte == b' ' || *byte == b'\t';
    let start = value.iter().position(|byte| !is_ows(byte)).unwrap_or(value.len());
    let end = value.iter().rposition(|byte| !is_ows(byte)).map_or(start, |at| at + 1);
    let value = &value[start..end];
    // Visible ASCII, space, tab and obs-text; never a control character (CR and LF included) or DEL.
    if value.iter().any(|&byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f) {
        return Err(HttpError::Malformed);
    }
    Ok((name, value))
}

/// Whether `text` is an RFC 9110 token: one or more `tchar`.
fn is_token(text: &[u8]) -> bool {
    !text.is_empty()
        && text
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// `Basic <base64(user:password)>`, or [`Authorization::Unusable`] for anything else (another scheme, extra
/// parameters, bad base64, no `:`).
fn parse_authorization(value: &[u8]) -> Authorization {
    let Some(space) = value.iter().position(|&byte| byte == b' ') else {
        return Authorization::Unusable;
    };
    let (scheme, encoded) = (&value[..space], &value[space + 1..]);
    if !scheme.eq_ignore_ascii_case(b"basic") {
        return Authorization::Unusable;
    }
    let Some(decoded) = crate::base64::decode(encoded) else {
        return Authorization::Unusable;
    };
    let Some(colon) = decoded.iter().position(|&byte| byte == b':') else {
        return Authorization::Unusable;
    };
    Authorization::Basic {
        user: decoded[..colon].to_vec(),
        password: decoded[colon + 1..].to_vec(),
    }
}

/// The proxy's responses. Every one but [`Response::Established`] closes the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    /// `200`: the tunnel is open.
    Established,
    /// `400`: malformed request.
    BadRequest,
    /// `403`: the destination is refused.
    Forbidden,
    /// `405`: only CONNECT is served.
    MethodNotAllowed,
    /// `407` with the Basic challenge: git sends credentials only after it (KNSH-027, C9).
    ProxyAuthenticationRequired,
    /// `431`: the head is over a size limit.
    HeadersTooLarge,
    /// `502`: the destination could not be reached.
    BadGateway,
    /// `503`: the proxy is at its connection limit.
    ServiceUnavailable,
    /// `504`: the destination did not answer in time.
    GatewayTimeout,
}

impl Response {
    /// The response's bytes.
    #[must_use]
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Established => b"HTTP/1.1 200 Connection established\r\n\r\n",
            Self::BadRequest => b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Self::Forbidden => b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Self::MethodNotAllowed => {
                b"HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            Self::ProxyAuthenticationRequired => {
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"knsh\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            Self::HeadersTooLarge => {
                b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            Self::BadGateway => b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Self::ServiceUnavailable => {
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            Self::GatewayTimeout => b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect(headers: &str) -> String {
        format!("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n{headers}\r\n")
    }

    // Decision 14: Basic credentials are split into user and password.
    #[test]
    fn parses_connect_with_basic_credentials() {
        let head = connect("Proxy-Authorization: Basic a25zaC0xOnRvaw==\r\nUser-Agent: curl/8\r\n");
        assert_eq!(head_state(head.as_bytes()), HeadState::Complete(head.len()));
        let request = parse_head(head.as_bytes()).unwrap();
        assert!(request.is_connect());
        assert_eq!(request.target, b"example.com:443");
        assert_eq!(
            request.authorization,
            Authorization::Basic {
                user: b"knsh-1".to_vec(),
                password: b"tok".to_vec()
            }
        );
        // The scheme is case-insensitive; other schemes and bad encodings are unusable.
        let lower = connect("proxy-authorization: basic a25zaC0xOnRvaw==\r\n");
        assert!(matches!(
            parse_head(lower.as_bytes()).unwrap().authorization,
            Authorization::Basic { .. }
        ));
        for value in [
            "Bearer abc",
            "Basic",
            "Basic a25zaC0x",
            "Basic  a25zaC0xOnRvaw==",
            "Digest x=1",
        ] {
            let head = connect(&format!("Proxy-Authorization: {value}\r\n"));
            assert_eq!(
                parse_head(head.as_bytes()).unwrap().authorization,
                Authorization::Unusable,
                "{value}"
            );
        }
        assert_eq!(
            parse_head(connect("").as_bytes()).unwrap().authorization,
            Authorization::Missing
        );
    }

    // NFR-SEC-07: a request line past its limit is refused before the rest is read.
    #[test]
    fn rejects_oversized_request_line() {
        let long = format!("CONNECT {}:443 HTTP/1.1", "a".repeat(MAX_REQUEST_LINE));
        // No CRLF yet, and already past the limit: refused without waiting for more.
        assert_eq!(head_state(long.as_bytes()), HeadState::TooLarge);
        // Bare line endings are refused as soon as they are seen.
        assert_eq!(head_state(b"CONNECT a.com:443 HTTP/1.1\n"), HeadState::Malformed);
        assert_eq!(
            head_state(b"CONNECT a.com:443 HTTP/1.1\r\nX: 1\rY"),
            HeadState::Malformed
        );
        assert_eq!(head_state(b"CONNECT a.com:443 HTTP/1.1\r"), HeadState::Incomplete);
        // Bytes after a complete head belong to the tunnel: a bare LF or CR there is not the head's.
        let pipelined = b"CONNECT a.com:443 HTTP/1.1\r\n\r\n\x16\x03\x01\n\r\x00";
        assert_eq!(head_state(pipelined), HeadState::Complete(pipelined.len() - 6));
        // Within the limit and unfinished: wait.
        assert_eq!(head_state(&long.as_bytes()[..MAX_REQUEST_LINE]), HeadState::Incomplete);
        let complete = format!("{long}\r\n\r\n");
        assert_eq!(head_state(complete.as_bytes()), HeadState::TooLarge);
        // Exactly at the limit is accepted; one byte over is refused by the parser too.
        let line = |len: usize| format!("CONNECT {}:443 HTTP/1.1\r\n\r\n", "a".repeat(len - 21));
        let at_limit = line(MAX_REQUEST_LINE);
        assert_eq!(head_state(at_limit.as_bytes()), HeadState::Complete(at_limit.len()));
        assert!(parse_head(at_limit.as_bytes()).is_ok());
        let over = line(MAX_REQUEST_LINE + 1);
        assert_eq!(head_state(over.as_bytes()), HeadState::TooLarge);
        assert_eq!(parse_head(over.as_bytes()), Err(HttpError::TooLarge));
    }

    // NFR-SEC-07: the head, each header line and the header count are bounded.
    #[test]
    fn rejects_oversized_heads_and_too_many_headers() {
        let mut huge = b"CONNECT a.com:443 HTTP/1.1\r\n".to_vec();
        huge.resize(MAX_HEAD, b'x');
        assert_eq!(head_state(&huge), HeadState::TooLarge);
        let long_header = connect(&format!("X-Long: {}\r\n", "v".repeat(MAX_HEADER_LINE)));
        assert_eq!(parse_head(long_header.as_bytes()), Err(HttpError::TooLarge));
        let many = connect(&"X-A: 1\r\n".repeat(MAX_HEADERS));
        assert_eq!(parse_head(many.as_bytes()), Err(HttpError::TooLarge));
        let enough = connect(&"X-A: 1\r\n".repeat(MAX_HEADERS - 1));
        assert!(parse_head(enough.as_bytes()).is_ok());
    }

    // NFR-SEC-05: anything outside the grammar is refused, never repaired.
    #[test]
    fn rejects_malformed_connect_without_recovery() {
        for head in [
            "CONNECT example.com:443 HTTP/1.1\n\n",
            "CONNECT example.com:443 HTTP/1.1\r\nHost: a\n\r\n\r\n",
            "CONNECT  example.com:443 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:443  HTTP/1.1\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1 \r\n\r\n",
            "CONNECT example.com:443\r\n\r\n",
            "CONNECT example.com:443 HTTP/2.0\r\n\r\n",
            "CONNECT example.com:443 http/1.1\r\n\r\n",
            "CONNECT exa\u{7f}mple.com:443 HTTP/1.1\r\n\r\n",
            "CON NECT example.com:443 HTTP/1.1\r\n\r\n",
            " CONNECT example.com:443 HTTP/1.1\r\n\r\n",
            "\r\nCONNECT example.com:443 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nHost : a\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nNoColon\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\n: empty\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nX: a\rb\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nX: a\x00b\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic a25zaC0xOnRvaw==\r\nProxy-Authorization: Basic a25zaC0xOnRvaw==\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\n",
        ] {
            assert_eq!(parse_head(head.as_bytes()), Err(HttpError::Malformed), "{head:?}");
        }
        // Tolerated by the grammar, decided by the caller: other methods parse and are refused as unsupported.
        let get = parse_head(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert!(!get.is_connect());
        assert!(
            !parse_head(b"connect example.com:443 HTTP/1.1\r\n\r\n")
                .unwrap()
                .is_connect()
        );
        assert!(parse_head(b"CONNECT a.com:443 HTTP/1.1\r\nContent-Length: 0\r\nX:\t v \t\r\n\r\n").is_ok());
    }

    // KNSH-027, C9: the 407 carries the Basic challenge git waits for, and closes the connection.
    #[test]
    fn challenge_names_basic_realm() {
        let text = std::str::from_utf8(Response::ProxyAuthenticationRequired.bytes()).unwrap();
        assert!(text.starts_with("HTTP/1.1 407 "));
        assert!(text.contains("\r\nProxy-Authenticate: Basic realm=\"knsh\"\r\n"));
        assert!(text.contains("\r\nConnection: close\r\n"));
        assert!(text.contains(REALM));
    }
}
