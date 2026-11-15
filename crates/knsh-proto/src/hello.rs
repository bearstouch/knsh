//! The `hello` handshake: parameters, protocol negotiation and result (`specs/06-api/handshake.md`, KNSH-014).
//!
//! Parameters come from an unprocessed client, so every field is bounded before it is kept: a string longer than its
//! limit or a protocol list longer than [`MAX_PROTOCOLS`] is invalid params (`-32602`), never truncated. The session
//! token is kept [`Redacted`] from the moment it is read.

use knsh_core::{Redacted, SessionId};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value, base64_encode};

use crate::capability::{Capabilities, Platform};
use crate::catalogue::MethodSpec;

/// The protocol versions this engine speaks, oldest first. `protocol` is one integer; changes within a version are
/// additive only.
pub const SUPPORTED_PROTOCOLS: &[u32] = &[1];

/// Most entries in `protocols`. Real clients send one or two; the bound keeps a hostile list small.
pub const MAX_PROTOCOLS: usize = 16;

/// Longest `client` and `client_version`, in bytes.
pub const MAX_CLIENT_FIELD_LEN: usize = 128;

/// Longest `session_token`, in bytes. Tokens the engine issues are far shorter.
pub const MAX_SESSION_TOKEN_LEN: usize = 256;

/// The capability name sent in `-32005` `data.capability` when no protocol is shared.
pub const PROTOCOL_CAPABILITY: &str = "protocol";

/// How raw bytes reach this client (`specs/06-api/wire-format.md#frames-unix-sockets`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ByteTransport {
    /// In binary chunk frames beside the JSON message (the default).
    #[default]
    BinaryFrames,
    /// Inline in the JSON, as canonical standard base64 with padding: the client opted out of binary frames.
    Base64,
}

impl ByteTransport {
    /// The bytes as an inline JSON value: a base64 string for [`ByteTransport::Base64`], or `None` when they go in
    /// binary chunks instead.
    #[must_use]
    pub fn inline(self, bytes: &[u8]) -> Option<Value> {
        match self {
            Self::BinaryFrames => None,
            Self::Base64 => Some(Value::from(base64_encode(bytes))),
        }
    }

    /// Whether binary frames are used, as echoed in the `hello` result.
    #[must_use]
    pub const fn uses_binary_frames(self) -> bool {
        matches!(self, Self::BinaryFrames)
    }
}

/// The parameters of `hello`.
#[derive(Debug, Clone)]
pub struct HelloParams {
    /// Client name.
    pub client: String,
    /// Client version.
    pub client_version: String,
    /// Protocol versions the client supports, 1 to [`MAX_PROTOCOLS`] entries.
    pub protocols: Vec<u32>,
    /// On `agent.sock`, the token from the envelope's environment.
    pub session_token: Option<Redacted<String>>,
    /// How the client wants raw bytes: `binary_frames: false` opts out of binary frames.
    pub bytes: ByteTransport,
}

impl FromJson for HelloParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let client = bounded_string(fields.required("client")?, MAX_CLIENT_FIELD_LEN, "client")?;
        let client_version = bounded_string(
            fields.required("client_version")?,
            MAX_CLIENT_FIELD_LEN,
            "client_version",
        )?;
        // Checked as a list of values first, so a huge list is refused before any entry is converted.
        let protocols: Vec<Value> = fields.required("protocols")?;
        if protocols.is_empty() || protocols.len() > MAX_PROTOCOLS {
            return Err(JsonError::OutOfRange {
                field: Some("protocols"),
            });
        }
        let protocols = protocols
            .iter()
            .map(u32::from_json)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| JsonError::OutOfRange {
                field: Some("protocols"),
            })?;
        let session_token = fields
            .optional::<String>("session_token")?
            .map(|token| bounded_string(token, MAX_SESSION_TOKEN_LEN, "session_token"))
            .transpose()?
            .map(Redacted::new);
        let bytes = match fields.optional::<bool>("binary_frames")? {
            Some(false) => ByteTransport::Base64,
            Some(true) | None => ByteTransport::BinaryFrames,
        };
        fields.finish()?;
        Ok(Self {
            client,
            client_version,
            protocols,
            session_token,
            bytes,
        })
    }
}

/// `value` if it is at most `max` bytes; otherwise out of range for `field`.
fn bounded_string(value: String, max: usize, field: &'static str) -> Result<String, JsonError> {
    if value.len() <= max {
        Ok(value)
    } else {
        Err(JsonError::OutOfRange { field: Some(field) })
    }
}

/// The protocol to speak: the highest version both sides support, or `None` when they share none (the call fails
/// and the connection closes).
#[must_use]
pub fn negotiate(offered: &[u32]) -> Option<u32> {
    SUPPORTED_PROTOCOLS
        .iter()
        .rev()
        .copied()
        .find(|version| offered.contains(version))
}

/// The result of `hello`.
#[derive(Debug, Clone)]
pub struct HelloResult<'a> {
    /// The engine version (`CARGO_PKG_VERSION` of `knshd`).
    pub engine_version: &'a str,
    /// The negotiated protocol.
    pub protocol: u32,
    /// The platform string, for example `macos-15-arm64`.
    pub platform: Platform,
    /// On `agent.sock`, the caller's session; absent elsewhere.
    pub session_id: Option<SessionId>,
    /// Whether this build is advisory only (phase 1: no security guarantees, not for running agents unattended).
    pub advisory: bool,
    /// How this connection receives raw bytes.
    pub bytes: ByteTransport,
    /// The probed backends.
    pub capabilities: &'a Capabilities,
    /// The methods callable on this endpoint on this machine, from the catalogue.
    pub methods: Vec<&'a MethodSpec>,
}

impl ToJson for HelloResult<'_> {
    fn to_json(&self) -> Result<Value, JsonError> {
        let mut capabilities = self.capabilities.to_object()?;
        let methods: Vec<Value> = self.methods.iter().map(|spec| Value::from(spec.name)).collect();
        capabilities.insert("methods", Value::from(methods))?;
        // Every listed method that is deprecated, with when it was marked and the first release that may drop it.
        let mut deprecated = Object::new();
        for spec in &self.methods {
            if let Some(deprecation) = spec.deprecated {
                let entry = Object::new()
                    .with("since", deprecation.since.to_string())?
                    .with("earliest_removal", deprecation.earliest_removal().to_string())?;
                deprecated.insert(spec.name, Value::Object(entry))?;
            }
        }
        capabilities.insert("deprecated", Value::Object(deprecated))?;

        let mut result = Object::new()
            .with("engine_version", self.engine_version)?
            .with("protocol", self.protocol.to_json()?)?
            .with("platform", self.platform.to_string())?;
        if let Some(session_id) = self.session_id {
            result.insert("session_id", Value::from(session_id.to_string()))?;
        }
        result
            .with("advisory", self.advisory)?
            .with("binary_frames", self.bytes.uses_binary_frames())?
            .with("capabilities", capabilities)
            .map(Value::Object)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use knsh_json::parse;

    use super::*;
    use crate::capability::{FileEvents, NetworkFilter, Sandbox, Secrets};
    use crate::catalogue::{Availability, Deprecation, Endpoints, Release};

    fn params(json: &str) -> Result<HelloParams, JsonError> {
        HelloParams::from_json(&parse(json.as_bytes(), 1 << 16).unwrap())
    }

    #[test]
    fn reads_hello_params() {
        let hello = params(
            r#"{"client":"my-agent","client_version":"0.4.0","protocols":[1,2],"session_token":"t0k","future":1}"#,
        )
        .unwrap();
        assert_eq!(
            (hello.client.as_str(), hello.client_version.as_str()),
            ("my-agent", "0.4.0")
        );
        assert_eq!(hello.protocols, [1, 2]);
        assert_eq!(hello.session_token.as_ref().map(|t| t.expose().as_str()), Some("t0k"));
        assert!(!format!("{hello:?}").contains("t0k"), "the token never prints");
        assert_eq!(hello.bytes, ByteTransport::BinaryFrames);
    }

    #[test]
    fn refuses_missing_wrong_or_oversized_fields() {
        let long = "a".repeat(MAX_CLIENT_FIELD_LEN + 1);
        let many = format!("[{}]", vec!["1"; MAX_PROTOCOLS + 1].join(","));
        let token = "t".repeat(MAX_SESSION_TOKEN_LEN + 1);
        for bad in [
            r#"{"client_version":"1","protocols":[1]}"#.to_owned(),
            r#"{"client":"c","client_version":"1"}"#.to_owned(),
            r#"{"client":"c","client_version":"1","protocols":[]}"#.to_owned(),
            r#"{"client":"c","client_version":"1","protocols":[-1]}"#.to_owned(),
            r#"{"client":"c","client_version":"1","protocols":["1"]}"#.to_owned(),
            r#"{"client":"c","client_version":"1","protocols":1}"#.to_owned(),
            r#"{"client":"c","client_version":"1","protocols":[1],"binary_frames":"no"}"#.to_owned(),
            format!(r#"{{"client":"{long}","client_version":"1","protocols":[1]}}"#),
            format!(r#"{{"client":"c","client_version":"1","protocols":{many}}}"#),
            format!(r#"{{"client":"c","client_version":"1","protocols":[1],"session_token":"{token}"}}"#),
        ] {
            assert!(params(&bad).is_err(), "{bad}");
        }
    }

    // KNSH-014: a client that cannot handle binary frames gets bytes as base64 inside JSON.
    #[test]
    fn binary_opt_out_switches_to_base64() {
        let hello = params(r#"{"client":"c","client_version":"1","protocols":[1],"binary_frames":false}"#).unwrap();
        assert_eq!(hello.bytes, ByteTransport::Base64);
        assert_eq!(hello.bytes.inline(b"knsh"), Some(Value::from("a25zaA==")));
        assert_eq!(ByteTransport::BinaryFrames.inline(b"knsh"), None);
        let explicit = params(r#"{"client":"c","client_version":"1","protocols":[1],"binary_frames":true}"#).unwrap();
        assert_eq!(explicit.bytes, ByteTransport::BinaryFrames);
    }

    // KNSH-014: version negotiation picks the highest shared version, or none.
    #[test]
    fn unsupported_protocol_list_is_refused() {
        assert_eq!(negotiate(&[1]), Some(1));
        assert_eq!(negotiate(&[7, 1, 3]), Some(1));
        assert_eq!(negotiate(&[0, 2, 99]), None);
        assert_eq!(negotiate(&[]), None);
    }

    #[test]
    fn writes_the_result_with_every_capability_and_deprecations() {
        static METHODS: [MethodSpec; 2] = [
            MethodSpec {
                name: "hello",
                endpoints: Endpoints::ALL,
                availability: Availability::Available,
                requires: None,
                deprecated: None,
            },
            MethodSpec {
                name: "records.old",
                endpoints: Endpoints::USER,
                availability: Availability::Available,
                requires: None,
                deprecated: Some(Deprecation {
                    since: Release::new(0, 3),
                }),
            },
        ];
        let caps = Capabilities {
            sandbox: Sandbox::None,
            network_filter: NetworkFilter::None,
            file_events: FileEvents::FsEvents,
            secrets: Secrets::None,
            checkpoints: BTreeMap::new(),
            sandbox_violations: crate::capability::SandboxViolations::None,
        };
        let result = HelloResult {
            engine_version: "0.1.0",
            protocol: 1,
            platform: Platform::new("macos", Some(15), "arm64"),
            session_id: None,
            advisory: true,
            bytes: ByteTransport::Base64,
            capabilities: &caps,
            methods: METHODS.iter().collect(),
        };
        let text = knsh_json::write(&result.to_json().unwrap()).unwrap();
        assert_eq!(
            text,
            concat!(
                r#"{"engine_version":"0.1.0","protocol":1,"platform":"macos-15-arm64","advisory":true,"#,
                r#""binary_frames":false,"capabilities":{"sandbox":"none","network_filter":"none","#,
                r#""file_events":"fsevents","secrets":"none","checkpoints":{},"sandbox_violations":"none","methods":["hello","records.old"],"#,
                r#""deprecated":{"records.old":{"since":"0.3","earliest_removal":"0.6"}}}}"#
            )
        );
    }
}
