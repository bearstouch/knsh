//! The properties of the `proxy_handshake` fuzz target (KNSH-059; `specs/07-testing/fuzzing.md`, NFR-SUP-06).
//!
//! Also compiled on stable by `crates/knsh-proxy/tests/fuzz_regressions.rs`, which includes it by path, so it
//! depends only on `knsh-proxy` and `std`. A failed property panics, which libFuzzer records as a crash.

use knsh_proxy::http::{self, HeadState, MAX_HEAD, MAX_REQUEST_LINE};
use knsh_proxy::socks5;
use knsh_proxy::{Host, Target};

/// `proxy_handshake`: the same bytes are read as an HTTP request head and as a SOCKS5 handshake. Neither reader
/// panics or depends on anything but its input; a head is delimited only within its limits and ends with CRLF
/// CRLF; whatever is accepted is within the grammar; and every destination either protocol accepts prints back to
/// itself, so a rule matches exactly what will be connected to.
pub fn proxy_handshake(data: &[u8]) {
    http_head(data);
    socks5_handshake(data);
}

fn http_head(data: &[u8]) {
    let state = http::head_state(data);
    assert_eq!(state, http::head_state(data), "head_state is not deterministic");
    match state {
        HeadState::Complete(len) => {
            assert!(
                len <= data.len() && len <= MAX_HEAD,
                "head beyond the input or the limit"
            );
            assert!(data[..len].ends_with(b"\r\n\r\n"), "head does not end with CRLF CRLF");
            check_request(&data[..len]);
        }
        HeadState::TooLarge => assert!(
            data.len() >= MAX_REQUEST_LINE + 2,
            "refused as too large before any limit was reached"
        ),
        HeadState::Incomplete => assert!(data.len() < MAX_HEAD, "still waiting past the head limit"),
        HeadState::Malformed => {}
    }
    // The parser also takes any bytes on its own.
    let _ = http::parse_head(data);
}

fn check_request(head: &[u8]) {
    let Ok(request) = http::parse_head(head) else {
        return;
    };
    assert!(!request.method.is_empty(), "empty method accepted");
    assert!(
        request.target.iter().all(|&byte| (0x21..=0x7e).contains(&byte)),
        "request target with a space or control character accepted"
    );
    if let Some(target) = Target::parse_authority(request.target) {
        round_trip(&target);
    }
}

fn socks5_handshake(data: &[u8]) {
    let mut reader = data;
    let _ = socks5::read_greeting(&mut reader);
    if let Ok(credentials) = socks5::read_user_password(&mut reader) {
        assert!(
            (1..=255).contains(&credentials.user.len()) && (1..=255).contains(&credentials.password.len()),
            "credential field out of bounds"
        );
    }
    // The request reader alone, from the start, and after whatever the handshake consumed.
    for mut input in [data, reader] {
        if let Some(target) = socks5::read_request(&mut input)
            .ok()
            .and_then(|request| request.target())
        {
            round_trip(&target);
        }
    }
}

/// A destination prints as an authority that reads back to the same destination; a name is normalised.
fn round_trip(target: &Target) {
    let printed = target.to_string();
    assert_eq!(
        Target::parse_authority(printed.as_bytes()).as_ref(),
        Some(target),
        "destination does not read back to itself"
    );
    if let Host::Name(name) = &target.host {
        assert!(
            !name.is_empty() && name.len() <= knsh_proxy::target::MAX_NAME_LEN,
            "name out of bounds"
        );
        assert!(!name.ends_with('.'), "trailing dot kept");
        assert_eq!(name.to_ascii_lowercase(), *name, "name not lower case");
        assert!(name.parse::<std::net::IpAddr>().is_err(), "address accepted as a name");
    }
}
