//! Secret injection's pure parts (KNSH-092): pairing looked-up values, denial reasons and the record's names.

use super::*;

fn name(text: &str) -> SecretName {
    SecretName::new(text).unwrap()
}

fn value(text: &[u8]) -> SecretValue {
    SecretValue::from_vec(text.to_vec())
}

fn needed(variable: &str, secret: &str) -> Needed {
    Needed {
        variable: variable.to_owned(),
        name: name(secret),
    }
}

// FR-SEC-01: each variable gets its own secret's value; a value no environment can carry, or an answer for other
// names, denies the line (fail closed).
#[test]
fn pairs_values_with_variables_or_refuses() {
    let injected = pair(
        vec![needed("GH_TOKEN", "gh-token"), needed("NPM_TOKEN", "npm-token")],
        vec![
            (name("gh-token"), value(b"ghp_1")),
            (name("npm-token"), value(b"npm_2")),
        ],
    )
    .unwrap();
    let pairs: Vec<_> = injected
        .iter()
        .map(|secret| (secret.variable.as_str(), secret.name.as_str(), secret.value.expose()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("GH_TOKEN", "gh-token", &b"ghp_1"[..]),
            ("NPM_TOKEN", "npm-token", &b"npm_2"[..])
        ]
    );
    assert_eq!(
        pair(vec![needed("T", "t")], vec![(name("t"), value(b"a\0b"))]).err(),
        Some(InjectionError::NotAnEnvironmentValue { name: name("t") })
    );
    assert_eq!(
        pair(vec![needed("T", "t")], vec![(name("u"), value(b"x"))]).err(),
        Some(InjectionError::NotRedacted)
    );
    assert_eq!(
        pair(vec![needed("T", "t")], Vec::new()).err(),
        Some(InjectionError::NotRedacted)
    );
}

// KNSH-092 unavailable_secret_denies_line: the reason names the secret (or variable), never a value.
#[test]
fn denial_reasons_name_the_secret() {
    let missing = InjectionError::Unavailable(Missing {
        name: name("npm-token"),
        reason: Unavailable::AccessDenied,
    });
    let reason = denial_reason(&missing);
    assert!(
        reason.contains("npm-token") && reason.contains("access denied"),
        "{reason}"
    );
    let reason = denial_reason(&InjectionError::ReservedVariable {
        variable: "HTTPS_PROXY".to_owned(),
    });
    assert!(reason.contains("HTTPS_PROXY"), "{reason}");
    assert!(denial_reason(&InjectionError::NotRedacted).contains("send it again"));
}

// FR-SEC-06, FR-REC-11: the record lists each secret's name once, sorted, and never a value.
#[test]
fn record_lists_names_only() {
    let injected = pair(
        vec![needed("B", "zeta"), needed("A", "alpha"), needed("C", "alpha")],
        vec![
            (name("zeta"), value(b"v1")),
            (name("alpha"), value(b"v2")),
            (name("alpha"), value(b"v2")),
        ],
    )
    .unwrap();
    assert_eq!(injected_names(&injected), ["alpha", "zeta"]);
    assert!(!format!("{injected:?}").contains("v1"));
}
