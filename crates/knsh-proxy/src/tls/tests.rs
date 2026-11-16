//! The `ClientHello` reader over hand-built hellos (KNSH-061; FR-NET-06, NFR-SEC-05, NFR-SEC-07).

use super::*;

/// One extension: type and data.
fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// A `server_name` extension naming `name` once.
fn sni(name: &[u8]) -> Vec<u8> {
    let mut entry = vec![HOST_NAME];
    entry.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
    entry.extend_from_slice(name);
    let mut list = u16::try_from(entry.len()).unwrap().to_be_bytes().to_vec();
    list.extend_from_slice(&entry);
    extension(EXT_SERVER_NAME, &list)
}

/// A `ClientHello` body like curl's: TLS 1.2 legacy version, a session id, two suites, null compression, and
/// `extensions` (`None` leaves the block out entirely).
fn body(extensions: Option<&[Vec<u8>]>) -> Vec<u8> {
    let mut out = vec![0x03, 0x03];
    out.extend_from_slice(&[0x11; 32]); // random
    out.push(32);
    out.extend_from_slice(&[0x22; 32]); // legacy_session_id
    out.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // two cipher suites
    out.extend_from_slice(&[0x01, 0x00]); // compression: null
    if let Some(extensions) = extensions {
        let block: Vec<u8> = extensions.concat();
        out.extend_from_slice(&u16::try_from(block.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&block);
    }
    out
}

/// The handshake message: type 1 and a 24-bit length.
fn message(body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut out = vec![CLIENT_HELLO, len[1], len[2], len[3]];
    out.extend_from_slice(body);
    out
}

/// `payload` in handshake records of at most `chunk` bytes each.
fn records(payload: &[u8], chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for fragment in payload.chunks(chunk) {
        out.extend_from_slice(&[CONTENT_HANDSHAKE, 0x03, 0x01]);
        out.extend_from_slice(&u16::try_from(fragment.len()).unwrap().to_be_bytes());
        out.extend_from_slice(fragment);
    }
    out
}

/// A complete one-record `ClientHello` naming `name`, with a few other extensions around it. Also used by the server
/// tests.
pub(crate) fn hello_for(name: &str) -> Vec<u8> {
    let extensions = [
        extension(0x0a0a, &[]), // GREASE
        sni(name.as_bytes()),
        extension(0x0010, &[0x00, 0x03, 0x02, b'h', b'2']), // ALPN
        extension(0x002b, &[0x02, 0x03, 0x04]),             // supported_versions: TLS 1.3
    ];
    records(&message(&body(Some(&extensions))), MAX_FRAGMENT)
}

/// A complete one-record `ClientHello` that names no server.
pub(crate) fn hello_without_name() -> Vec<u8> {
    records(
        &message(&body(Some(&[extension(0x002b, &[0x02, 0x03, 0x04])]))),
        MAX_FRAGMENT,
    )
}

fn name(text: &str) -> ServerName {
    ServerName::Name(text.to_owned())
}

fn host(text: &str) -> Host {
    Host::parse(text.as_bytes()).unwrap()
}

// FR-NET-06: the server name is read from a complete ClientHello, normalised (case, trailing dot).
#[test]
fn extracts_sni_from_client_hello() {
    assert_eq!(
        read_client_hello(&hello_for("github.com")),
        HelloState::Complete(name("github.com"))
    );
    assert_eq!(
        read_client_hello(&hello_for("GitHub.COM.")),
        HelloState::Complete(name("github.com"))
    );
    // Bytes after the hello's last record (a compatibility `change_cipher_spec`) belong to the tunnel.
    let mut with_more = hello_for("example.com");
    with_more.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    assert_eq!(read_client_hello(&with_more), HelloState::Complete(name("example.com")));
}

// FR-NET-06: the name must equal the requested host; matching ignores case and a trailing dot because both sides
// are normalised the same way.
#[test]
fn refuses_mismatched_sni() {
    let HelloState::Complete(sent) = read_client_hello(&hello_for("Example.com.")) else {
        panic!("hello not read");
    };
    assert_eq!(check_server_name(&host("example.com"), &sent), Ok(()));
    assert_eq!(check_server_name(&host("EXAMPLE.com."), &sent), Ok(()));
    assert_eq!(
        check_server_name(&host("github.com"), &sent),
        Err(Refusal::ServerNameMismatch)
    );
    assert_eq!(
        check_server_name(&host("www.example.com"), &sent),
        Err(Refusal::ServerNameMismatch)
    );
    // An IP-literal destination has no name: a hello that names one does not match it.
    assert_eq!(
        check_server_name(&host("10.0.0.5"), &sent),
        Err(Refusal::ServerNameMismatch)
    );
}

// FR-NET-06: no server name, or Encrypted Client Hello (whose clear name is a public front), is refused for a named
// host. An IP literal is the one destination that expects no name (RFC 6066).
#[test]
fn refuses_missing_sni() {
    let without = records(&message(&body(Some(&[extension(0x0010, &[0x00, 0x00])]))), MAX_FRAGMENT);
    assert_eq!(read_client_hello(&without), HelloState::Complete(ServerName::Absent));
    let no_extensions = records(&message(&body(None)), MAX_FRAGMENT);
    assert_eq!(
        read_client_hello(&no_extensions),
        HelloState::Complete(ServerName::Absent)
    );
    let ech = records(
        &message(&body(Some(&[
            sni(b"public.example"),
            extension(EXT_ENCRYPTED_CLIENT_HELLO, &[0; 8]),
        ]))),
        MAX_FRAGMENT,
    );
    assert_eq!(read_client_hello(&ech), HelloState::Complete(ServerName::Encrypted));

    let named = host("example.com");
    assert_eq!(
        check_server_name(&named, &ServerName::Absent),
        Err(Refusal::ServerNameMissing)
    );
    assert_eq!(
        check_server_name(&named, &ServerName::Encrypted),
        Err(Refusal::ServerNameMissing)
    );
    assert_eq!(check_server_name(&host("10.0.0.5"), &ServerName::Absent), Ok(()));
    assert_eq!(
        check_server_name(&host("10.0.0.5"), &ServerName::Encrypted),
        Err(Refusal::ServerNameMissing)
    );
}

// NFR-SEC-05: a hello cut short is incomplete while it could still grow, and a hello whose inner lengths overrun
// the message it declared is refused, never repaired.
#[test]
fn refuses_truncated_client_hello() {
    let hello = hello_for("example.com");
    for cut in 0..hello.len() {
        assert_eq!(read_client_hello(&hello[..cut]), HelloState::Incomplete, "cut at {cut}");
    }
    // The message is shorter than its extensions say: the record and handshake lengths agree, the inner ones do
    // not.
    let mut short = message(&body(Some(&[sni(b"example.com")])));
    short.truncate(short.len() - 3);
    let declared = u32::try_from(short.len() - 4).unwrap().to_be_bytes();
    short[1..4].copy_from_slice(&declared[1..]);
    assert_eq!(
        read_client_hello(&records(&short, MAX_FRAGMENT)),
        HelloState::Refused(HelloError::Malformed)
    );
    // A record that ends inside the ClientHello, followed by a record of another type.
    let message = message(&body(Some(&[sni(b"example.com")])));
    let mut cut = records(&message[..20], MAX_FRAGMENT);
    cut.extend_from_slice(&[23, 3, 3, 0, 1, 0]);
    assert_eq!(read_client_hello(&cut), HelloState::Refused(HelloError::Malformed));
}

// FR-NET-06: a ClientHello split across records (even one byte each) reads the same as in one record.
#[test]
fn handles_client_hello_split_across_records() {
    let message = message(&body(Some(&[sni(b"registry.npmjs.org")])));
    for chunk in [1, 2, 3, 7, 100] {
        let split = records(&message, chunk);
        assert_eq!(
            read_client_hello(&split),
            HelloState::Complete(name("registry.npmjs.org")),
            "records of {chunk}"
        );
        // Every proper prefix is incomplete, never refused.
        for cut in 0..split.len() {
            assert_eq!(
                read_client_hello(&split[..cut]),
                HelloState::Incomplete,
                "records of {chunk}, cut at {cut}"
            );
        }
    }
}

// Data that is not TLS is refused on its first bytes, so a plain-text client is not waited for.
#[test]
fn refuses_data_that_is_not_tls() {
    for data in [
        &b"G"[..],
        b"GET / HTTP/1.1\r\n\r\n",
        b"SSH-2.0-OpenSSH_9.6\r\n",
        &[0x80, 0x2e, 0x01, 0x03, 0x01], // SSLv2-compatible hello
        &[22, 4, 0],                     // record version 4.x
        &[22, 3, 4],                     // record version 3.4
        &[21, 3, 3, 0, 2, 2, 40],        // an alert
        &[22, 3, 1, 0, 4, 2, 0, 0, 0],   // a ServerHello
    ] {
        assert_eq!(
            read_client_hello(data),
            HelloState::Refused(HelloError::NotTls),
            "{data:?}"
        );
    }
    // SSL 3.0 in the hello itself: it cannot carry a server name.
    let mut old = body(None);
    old[1] = 0x00;
    assert_eq!(
        read_client_hello(&records(&message(&old), MAX_FRAGMENT)),
        HelloState::Refused(HelloError::NotTls)
    );
}

// NFR-SEC-05: grammar violations inside a complete hello are refused.
#[test]
fn refuses_malformed_client_hello() {
    let refused = |extensions: &[Vec<u8>]| read_client_hello(&records(&message(&body(Some(extensions))), MAX_FRAGMENT));
    let malformed = HelloState::Refused(HelloError::Malformed);
    // Repeated extensions, repeated `server_name` included.
    assert_eq!(refused(&[sni(b"a.example"), sni(b"b.example")]), malformed);
    assert_eq!(refused(&[extension(0x0010, &[]), extension(0x0010, &[])]), malformed);
    // An empty name, a name that is an address, an invalid name, a non-ASCII name.
    assert_eq!(refused(&[sni(b"")]), malformed);
    assert_eq!(refused(&[sni(b"192.0.2.1")]), malformed);
    assert_eq!(refused(&[sni(b"bad name.example")]), malformed);
    assert_eq!(refused(&[sni("exämple.com".as_bytes())]), malformed);
    // Two entries in the list, another name type, an empty extension, a list length that leaves bytes over.
    let mut two = sni(b"a.example");
    let list = &two[6..].to_vec();
    two = extension(
        EXT_SERVER_NAME,
        &[&(u16::try_from(list.len() * 2).unwrap().to_be_bytes())[..], list, list].concat(),
    );
    assert_eq!(refused(&[two]), malformed);
    assert_eq!(
        refused(&[extension(EXT_SERVER_NAME, &[0x00, 0x04, 0x01, 0x00, 0x01, b'a'])]),
        malformed
    );
    assert_eq!(refused(&[extension(EXT_SERVER_NAME, &[])]), malformed);
    assert_eq!(refused(&[extension(EXT_SERVER_NAME, &[0x00, 0x00, 0xff])]), malformed);
    // No cipher suite, an odd suite length, no compression method, a session id over 32 bytes.
    let mut hello = body(None);
    hello[67..69].copy_from_slice(&[0x00, 0x00]);
    hello.drain(69..73);
    assert_eq!(read_client_hello(&records(&message(&hello), MAX_FRAGMENT)), malformed);
    let mut hello = body(None);
    hello[68] = 0x03;
    hello.remove(72);
    assert_eq!(read_client_hello(&records(&message(&hello), MAX_FRAGMENT)), malformed);
    let mut hello = body(None);
    hello[73..75].copy_from_slice(&[0x00, 0x00]);
    hello.pop();
    assert_eq!(read_client_hello(&records(&message(&hello), MAX_FRAGMENT)), malformed);
    let mut hello = body(None);
    hello[34] = 33;
    hello.insert(35, 0x22);
    assert_eq!(read_client_hello(&records(&message(&hello), MAX_FRAGMENT)), malformed);
    // Bytes after the extensions block.
    let mut hello = body(Some(&[sni(b"example.com")]));
    hello.push(0);
    assert_eq!(read_client_hello(&records(&message(&hello), MAX_FRAGMENT)), malformed);
    // Another handshake message in the hello's last record.
    let mut two_messages = message(&body(Some(&[sni(b"example.com")])));
    two_messages.extend_from_slice(&[CLIENT_HELLO, 0, 0, 0]);
    assert_eq!(read_client_hello(&records(&two_messages, MAX_FRAGMENT)), malformed);
    // Empty and oversized records.
    assert_eq!(read_client_hello(&[22, 3, 1, 0, 0]), malformed);
    assert_eq!(read_client_hello(&[22, 3, 1, 0x40, 0x01]), malformed);
}

// NFR-SEC-07: the declared length is checked before anything is buffered, and no more than `MAX_HELLO_BYTES` are
// ever waited for.
#[test]
fn refuses_oversized_client_hello() {
    // A handshake header declaring 16 MiB.
    assert_eq!(
        read_client_hello(&[22, 3, 1, 0, 4, 1, 0xff, 0xff, 0xff]),
        HelloState::Refused(HelloError::TooLarge)
    );
    // Just over the body limit.
    let len = u32::try_from(MAX_CLIENT_HELLO + 1).unwrap().to_be_bytes();
    assert_eq!(
        read_client_hello(&[22, 3, 1, 0, 4, 1, len[1], len[2], len[3]]),
        HelloState::Refused(HelloError::TooLarge)
    );
    // A hello at the limit, in one-byte records, needs more than `MAX_HELLO_BYTES` on the wire.
    let mut big = body(Some(&[sni(b"example.com")]));
    let padding = MAX_CLIENT_HELLO - big.len() - 4;
    let extensions_len = u16::try_from(big.len() - 77 + 4 + padding).unwrap().to_be_bytes();
    big[75..77].copy_from_slice(&extensions_len);
    big.extend_from_slice(&extension(0x0015, &vec![0; padding]));
    assert_eq!(big.len(), MAX_CLIENT_HELLO);
    let whole = records(&message(&big), MAX_FRAGMENT);
    assert!(whole.len() > MAX_FRAGMENT, "a body of 2^14 needs two records");
    assert_eq!(read_client_hello(&whole), HelloState::Complete(name("example.com")));
    let fragmented = records(&message(&big), 1);
    assert_eq!(
        read_client_hello(&fragmented[..MAX_HELLO_BYTES + 5]),
        HelloState::Refused(HelloError::TooLarge)
    );
    // Waiting stops at the limit even when no single record crosses it.
    let tiny = records(&message(&big), 1);
    assert_eq!(
        read_client_hello(&tiny[..MAX_HELLO_BYTES]),
        HelloState::Refused(HelloError::TooLarge)
    );
}

// NFR-SEC-05: the reader is total over arbitrary bytes (the fuzz target checks this at scale).
#[test]
fn never_panics_on_prefixes_and_mutations() {
    let hello = hello_for("example.com");
    for index in 0..hello.len() {
        for value in [0x00, 0x01, 0x7f, 0x80, 0xff] {
            let mut mutated = hello.clone();
            mutated[index] = value;
            let _ = read_client_hello(&mutated);
        }
    }
}
