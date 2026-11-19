//! The secrets broker (KNSH-089): Keychain lookups, authority-supplied secrets, expiry and revocation (FR-SEC-07).

use knsh_json::Value;
use knsh_platform::testing::{FakeClock, MemSecretStore};

use super::*;
use crate::dispatch::Endpoint;
use crate::policy::tests::call_with;
use crate::sessions::SessionBinding;

/// 2026-11-19T10:00:00Z.
const START_MICROS: u64 = 1_795_082_400_000_000;

struct Fixture {
    keychain: Arc<MemSecretStore>,
    clock: Arc<FakeClock>,
    broker: Arc<SecretBroker>,
    handlers: Handlers,
}

fn fixture() -> Fixture {
    let keychain = Arc::new(MemSecretStore::new());
    let clock = Arc::new(FakeClock::new(Timestamp::from_unix_micros(START_MICROS).unwrap()));
    let broker = SecretBroker::new(keychain.clone(), clock.clone());
    let handlers = broker.handlers();
    Fixture {
        keychain,
        clock,
        broker,
        handlers,
    }
}

fn name(text: &str) -> SecretName {
    SecretName::new(text).unwrap()
}

fn call(fixture: &Fixture, endpoint: Endpoint, method: &'static str, params: &str) -> Reply {
    call_with(&fixture.handlers, endpoint, &SessionBinding::new(), method, params)
}

fn control(fixture: &Fixture, method: &'static str, params: &str) -> knsh_json::Object {
    call(fixture, Endpoint::Control, method, params)
        .unwrap()
        .result
        .as_object()
        .cloned()
        .unwrap()
}

fn provide(fixture: &Fixture, secret: &str, value: &str, duration_s: u64) -> knsh_json::Object {
    control(
        fixture,
        "secrets.provide",
        &format!(r#"{{"name":"{secret}","value":"{value}","duration_s":{duration_s}}}"#),
    )
}

fn value_of(fixture: &Fixture, secret: &str) -> Result<Vec<u8>, Unavailable> {
    fixture
        .broker
        .lookup(&name(secret))
        .map(|value| value.expose().to_vec())
}

// Keychain store: a secret stored under service `knsh` is read by name; a missing one is a typed "not found".
#[test]
fn missing_secret_returns_not_found() {
    let fixture = fixture();
    assert_eq!(value_of(&fixture, "npm-token"), Err(Unavailable::NotFound));
    fixture.keychain.insert(&name("npm-token"), b"from-keychain");
    assert_eq!(value_of(&fixture, "npm-token").unwrap(), b"from-keychain");
}

// Keychain store: an item knshd may not read (decision 11) is "access denied", never a value.
#[test]
fn unreadable_keychain_secret_is_access_denied() {
    let fixture = fixture();
    fixture.keychain.insert(&name("npm-token"), b"v");
    fixture.keychain.deny(&name("npm-token"), -25293);
    assert_eq!(value_of(&fixture, "npm-token"), Err(Unavailable::AccessDenied));
}

// A line gets every secret it needs or is denied naming the first missing one: never run without it.
#[test]
fn line_needing_an_unavailable_secret_is_denied() {
    let fixture = fixture();
    fixture.keychain.insert(&name("a"), b"1");
    fixture.keychain.insert(&name("c"), b"3");
    fixture.keychain.deny(&name("c"), -25293);
    let resolved = fixture.broker.resolve(&[name("a")]).unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].1.expose(), b"1");
    assert_eq!(
        fixture.broker.resolve(&[name("a"), name("b"), name("c")]).unwrap_err(),
        Missing {
            name: name("b"),
            reason: Unavailable::NotFound
        }
    );
    assert_eq!(
        fixture.broker.resolve(&[name("a"), name("c")]).unwrap_err(),
        Missing {
            name: name("c"),
            reason: Unavailable::AccessDenied
        }
    );
}

// FR-SEC-07: a provided secret lives for its duration, then is gone.
#[test]
fn provided_secret_expires_after_duration() {
    let fixture = fixture();
    let provided = provide(&fixture, "deploy", "tok-1", 60);
    assert_eq!(provided.get("name").and_then(Value::as_str), Some("deploy"));
    assert_eq!(
        provided.get("expires_at").and_then(Value::as_str),
        Some("2026-11-19T10:01:00.000000Z")
    );
    assert_eq!(provided.get("replaced"), Some(&Value::Bool(false)));
    fixture.clock.advance(Duration::from_secs(59));
    assert_eq!(value_of(&fixture, "deploy").unwrap(), b"tok-1");
    fixture.clock.advance(Duration::from_secs(1));
    assert_eq!(value_of(&fixture, "deploy"), Err(Unavailable::NotFound));
}

// FR-SEC-07: moving the wall clock back never extends a provided secret (the monotonic deadline holds), and a wall
// clock that cannot be read makes it unavailable (fail closed).
#[test]
fn provided_secret_expiry_survives_clock_changes() {
    let fixture = fixture();
    provide(&fixture, "deploy", "tok", 60);
    fixture.clock.advance(Duration::from_secs(61));
    fixture.clock.set_wall(START_MICROS);
    assert_eq!(value_of(&fixture, "deploy"), Err(Unavailable::NotFound));

    let fixture = self::fixture();
    provide(&fixture, "deploy", "tok", 60);
    fixture.clock.set_wall(u64::MAX);
    assert_eq!(value_of(&fixture, "deploy"), Err(Unavailable::NotFound));
    fixture.clock.set_wall(START_MICROS);
    assert_eq!(
        value_of(&fixture, "deploy"),
        Err(Unavailable::NotFound),
        "dropped, not hidden"
    );
}

// FR-SEC-07: `secrets.revoke` removes a provided secret at once; revoking again reports nothing removed.
#[test]
fn revoked_secret_is_unavailable_immediately() {
    let fixture = fixture();
    provide(&fixture, "deploy", "tok", 600);
    let revoked = control(&fixture, "secrets.revoke", r#"{"name":"deploy"}"#);
    assert_eq!(revoked.get("revoked"), Some(&Value::Bool(true)));
    assert_eq!(value_of(&fixture, "deploy"), Err(Unavailable::NotFound));
    let again = control(&fixture, "secrets.revoke", r#"{"name":"deploy"}"#);
    assert_eq!(again.get("revoked"), Some(&Value::Bool(false)));
}

// FR-SEC-07: revoking a provided secret leaves a Keychain item of the same name alone; while provided, the
// authority's value takes the Keychain item's place.
#[test]
fn provided_secret_shadows_the_keychain_until_revoked() {
    let fixture = fixture();
    fixture.keychain.insert(&name("npm-token"), b"stored");
    provide(&fixture, "npm-token", "short-lived", 600);
    assert_eq!(value_of(&fixture, "npm-token").unwrap(), b"short-lived");
    control(&fixture, "secrets.revoke", r#"{"name":"npm-token"}"#);
    assert_eq!(value_of(&fixture, "npm-token").unwrap(), b"stored");
}

// FR-SEC-07: providing a name again replaces its value and expiry.
#[test]
fn providing_again_replaces_value_and_expiry() {
    let fixture = fixture();
    provide(&fixture, "deploy", "old", 10);
    let again = provide(&fixture, "deploy", "new", 100);
    assert_eq!(again.get("replaced"), Some(&Value::Bool(true)));
    fixture.clock.advance(Duration::from_secs(50));
    assert_eq!(value_of(&fixture, "deploy").unwrap(), b"new");
}

// FR-SEC-07: authority-supplied secrets are held in memory only: nothing reaches the Keychain (the store has no
// write path), and a new broker, as after `knshd` restarts, has none of them.
#[test]
fn provided_secret_is_never_persisted() {
    let fixture = fixture();
    provide(&fixture, "deploy", "tok", 600);
    let reads = fixture.keychain.reads();
    assert!(matches!(
        fixture.keychain.read(&name("deploy")),
        Err(PlatformError::SecretNotFound)
    ));
    assert_eq!(fixture.keychain.reads(), reads + 1);
    let restarted = SecretBroker::new(fixture.keychain.clone(), fixture.clock.clone());
    assert_eq!(restarted.lookup(&name("deploy")).unwrap_err(), Unavailable::NotFound);
}

// Expired secrets are dropped from memory, not only hidden.
#[test]
fn purge_drops_expired_secrets() {
    let fixture = fixture();
    provide(&fixture, "a", "1", 10);
    provide(&fixture, "b", "2", 100);
    fixture.clock.advance(Duration::from_secs(10));
    fixture.broker.purge_expired();
    let held: Vec<SecretName> = fixture.broker.provided.lock().unwrap().keys().cloned().collect();
    assert_eq!(held, [name("b")]);
}

// At most MAX_PROVIDED_SECRETS names at once; a replacement is always accepted, and expired ones free their place.
#[test]
fn provided_secrets_are_bounded() {
    let fixture = fixture();
    for index in 0..MAX_PROVIDED_SECRETS {
        provide(&fixture, &format!("s{index}"), "v", 10);
    }
    let refused = call(
        &fixture,
        Endpoint::Control,
        "secrets.provide",
        r#"{"name":"one-more","value":"v","duration_s":10}"#,
    )
    .unwrap_err();
    assert_eq!(refused.code, ErrorCode::InvalidParams);
    assert_eq!(value_of(&fixture, "one-more"), Err(Unavailable::NotFound));
    provide(&fixture, "s0", "w", 10);
    fixture.clock.advance(Duration::from_secs(10));
    provide(&fixture, "one-more", "v", 10);
}

// Both methods exist only on the control service, and no answer carries a value.
#[test]
fn methods_are_control_only_and_never_return_values() {
    let fixture = fixture();
    for endpoint in [Endpoint::User, Endpoint::Agent] {
        for (method, params) in [
            ("secrets.provide", r#"{"name":"x","value":"hunter2","duration_s":1}"#),
            ("secrets.revoke", r#"{"name":"x"}"#),
        ] {
            let refused = call(&fixture, endpoint, method, params).unwrap_err();
            assert_eq!(refused.code, ErrorCode::NotAllowed, "{method} on {endpoint:?}");
        }
    }
    assert_eq!(value_of(&fixture, "x"), Err(Unavailable::NotFound));
    let provided = provide(&fixture, "x", "hunter2", 1);
    assert!(!knsh_json::write(&Value::Object(provided)).unwrap().contains("hunter2"));
}

// Malformed params store nothing.
#[test]
fn invalid_params_store_nothing() {
    let fixture = fixture();
    for params in [
        r#"{"name":"x","value":"v","duration_s":0}"#,
        r#"{"name":"x y","value":"v","duration_s":1}"#,
        r#"{"name":"x","value":"","duration_s":1}"#,
        r#"{"name":"x","value":"v","duration_s":86401}"#,
    ] {
        let refused = call(&fixture, Endpoint::Control, "secrets.provide", params).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidParams, "{params}");
    }
    assert_eq!(value_of(&fixture, "x"), Err(Unavailable::NotFound));
}
