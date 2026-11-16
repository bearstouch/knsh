//! The properties of the `tls_client_hello` fuzz target (KNSH-061; FR-NET-06, NFR-SEC-05, NFR-SEC-07;
//! `specs/07-testing/fuzzing.md`).
//!
//! Also compiled on stable by `crates/knsh-proxy/tests/tls_fuzz_regressions.rs`, which includes it by path, so it
//! depends only on `knsh-proxy` and `std`. A failed property panics, which libFuzzer records as a crash. The target
//! runs with `-malloc_limit_mb=1` (`scripts/fuzz.sh`): the reader allocates at most one hello's length, never what
//! a length field claims.

use knsh_proxy::Host;
use knsh_proxy::tls::{self, HelloState, MAX_HELLO_BYTES, ServerName};

/// `tls_client_hello`: the reader never panics and depends only on its input; it waits for more bytes only below
/// the read limit; a name it extracts is a valid, normalised host name that matches itself and nothing else; a
/// decision never changes when more bytes arrive behind a complete hello, and is never made early for a hello that
/// later completes.
pub fn tls_client_hello(data: &[u8]) {
    let state = tls::read_client_hello(data);
    assert_eq!(
        state,
        tls::read_client_hello(data),
        "read_client_hello is not deterministic"
    );
    match &state {
        HelloState::Incomplete => assert!(data.len() < MAX_HELLO_BYTES, "still waiting past the read limit"),
        HelloState::Complete(name) => complete(data, name),
        HelloState::Refused(_) => {}
    }
}

fn complete(data: &[u8], name: &ServerName) {
    if let ServerName::Name(name) = name {
        // Normalised exactly as a destination name is, so the comparison with the requested host is byte for byte.
        assert_eq!(
            Host::parse(name.as_bytes()),
            Some(Host::Name(name.clone())),
            "extracted name is not a normalised host name"
        );
        let own = Host::Name(name.clone());
        assert_eq!(tls::check_server_name(&own, &ServerName::Name(name.clone())), Ok(()));
        let other = Host::Name(format!("x{name}"));
        assert!(tls::check_server_name(&other, &ServerName::Name(name.clone())).is_err());
    }
    // A named host never opens for a hello without a name, or with Encrypted Client Hello (fail closed).
    let named = Host::Name("example.com".to_owned());
    assert!(tls::check_server_name(&named, &ServerName::Absent).is_err());
    assert!(tls::check_server_name(&named, &ServerName::Encrypted).is_err());
    // Bytes behind a complete hello belong to the tunnel and do not change the decision.
    let mut longer = data.to_vec();
    longer.extend_from_slice(&[0x17, 0x03, 0x03, 0xff, 0xff]);
    assert_eq!(
        tls::read_client_hello(&longer),
        HelloState::Complete(name.clone()),
        "trailing bytes changed the decision"
    );
    // A hello that completes was never refused early: its prefixes only wait for more.
    for cut in [0, 1, 5, 6, 9, data.len() / 2] {
        if let Some(prefix) = data.get(..cut)
            && let HelloState::Refused(error) = tls::read_client_hello(prefix)
        {
            panic!("prefix of {cut} bytes refused ({error:?}) although the whole hello completes");
        }
    }
}
