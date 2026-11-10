//! What the extension may ask the host for. Only the requests of the browser
//! host scope can be represented. The host builds each broker request itself
//! and sets `client` and `caller` from its own parent check, so the extension
//! cannot set them. A message with any field not listed here is refused.

use serde::Deserialize;

use super::super::wire::{BrowserClient, WireRequest};
use crate::secrets::password::PasswordPolicy;

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ExtensionRequest {
    /// See [`WireRequest::ListLogins`].
    ListLogins {
        url: String,
        frame_url: String,
        #[serde(default)]
        all: bool,
    },

    /// See [`WireRequest::ListLoginsLocked`].
    ListLoginsLocked { url: String, frame_url: String },

    /// See [`WireRequest::FillLogin`].
    FillLogin {
        url: String,
        frame_url: String,
        record_id: String,
        #[serde(default)]
        account: Option<String>,
        #[serde(default)]
        unmatched: bool,
    },

    /// See [`WireRequest::GenerateTotp`].
    GenerateTotp {
        url: String,
        frame_url: String,
        record_id: String,
    },

    /// See [`WireRequest::GeneratePassword`].
    GeneratePassword {
        #[serde(default)]
        policy: Option<PasswordPolicy>,
    },

    /// See [`WireRequest::SaveLogin`].
    SaveLogin {
        url: String,
        frame_url: String,
        #[serde(default)]
        username: Option<String>,
        password: String,
    },

    /// See [`WireRequest::UpdateLoginPassword`].
    UpdateLoginPassword {
        url: String,
        frame_url: String,
        record_id: String,
        password: String,
        #[serde(default)]
        account: Option<String>,
    },
}

impl ExtensionRequest {
    /// Request kind for the log. The request body is never logged.
    pub(super) fn kind(&self) -> &'static str {
        match self {
            ExtensionRequest::ListLogins { .. } => "list_logins",
            ExtensionRequest::ListLoginsLocked { .. } => "list_logins_locked",
            ExtensionRequest::FillLogin { .. } => "fill_login",
            ExtensionRequest::GenerateTotp { .. } => "generate_totp",
            ExtensionRequest::GeneratePassword { .. } => "generate_password",
            ExtensionRequest::SaveLogin { .. } => "save_login",
            ExtensionRequest::UpdateLoginPassword { .. } => "update_login_password",
        }
    }

    /// Build the broker request. `client` is the host's own report of the
    /// browser that started it, and the caller is that browser's name.
    pub(super) fn into_wire(self, client: BrowserClient) -> WireRequest {
        let caller = client.browser.as_ref().map(|b| b.name.clone());
        match self {
            ExtensionRequest::ListLogins {
                url,
                frame_url,
                all,
            } => WireRequest::ListLogins {
                url,
                frame_url,
                all,
                requester: None,
                caller,
                client,
            },
            ExtensionRequest::ListLoginsLocked { url, frame_url } => {
                WireRequest::ListLoginsLocked {
                    url,
                    frame_url,
                    requester: None,
                    caller,
                    client,
                }
            },
            ExtensionRequest::FillLogin {
                url,
                frame_url,
                record_id,
                account,
                unmatched,
            } => WireRequest::FillLogin {
                url,
                frame_url,
                record_id,
                account,
                unmatched,
                requester: None,
                caller,
                client,
            },
            ExtensionRequest::GenerateTotp {
                url,
                frame_url,
                record_id,
            } => WireRequest::GenerateTotp {
                url,
                frame_url,
                record_id,
                requester: None,
                caller,
                client,
            },
            ExtensionRequest::GeneratePassword { policy } => {
                WireRequest::GeneratePassword { policy, caller }
            },
            ExtensionRequest::SaveLogin {
                url,
                frame_url,
                username,
                password,
            } => WireRequest::SaveLogin {
                url,
                frame_url,
                username,
                password,
                caller,
                client,
            },
            ExtensionRequest::UpdateLoginPassword {
                url,
                frame_url,
                record_id,
                password,
                account,
            } => WireRequest::UpdateLoginPassword {
                url,
                frame_url,
                record_id,
                password,
                account,
                caller,
                client,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::{Map, Value};

    use super::*;
    use crate::core::app_broker::access::RequestScope;
    use crate::core::app_broker::wire::VerifiedBrowser;

    /// Fixtures shared with the extension tests, one file per request kind.
    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/native-messaging/requests")
    }

    fn fixtures() -> Vec<(String, Value)> {
        let mut out: Vec<(String, Value)> = std::fs::read_dir(fixtures_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .map(|path| {
                let name = path.file_stem().unwrap().to_string_lossy().into_owned();
                let text = std::fs::read_to_string(&path).unwrap();
                (name, serde_json::from_str(&text).unwrap())
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn parse(value: &Value) -> Result<ExtensionRequest, serde_json::Error> {
        serde_json::from_value(value.clone())
    }

    fn chrome() -> BrowserClient {
        BrowserClient {
            browser: Some(VerifiedBrowser {
                name: "Google Chrome".to_string(),
                team_id: "EQHXZ8M8AV".to_string(),
            }),
            extension: Some("chrome-extension://abc/".to_string()),
        }
    }

    #[test]
    fn fixture_for_every_request_kind() {
        let names: Vec<String> = fixtures().into_iter().map(|(name, _)| name).collect();
        assert_eq!(
            names,
            [
                "fill_login",
                "generate_password",
                "generate_totp",
                "list_logins",
                "list_logins_locked",
                "save_login",
                "update_login_password",
            ]
        );
    }

    /// Every fixture parses, names its own kind, and serializes back to the
    /// same JSON. Fixtures list every field, defaults included.
    #[test]
    fn fixtures_round_trip() {
        for (name, value) in fixtures() {
            let request = parse(&value).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(request.kind(), name);
            assert_eq!(value["request"], name, "{name}");
            assert_eq!(serde_json::to_value(&request).unwrap(), value, "{name}");
        }
    }

    /// Every fixture field reaches the broker request unchanged, and the host
    /// fills in `client` and `caller`.
    #[test]
    fn fixtures_become_broker_requests() {
        for (name, value) in fixtures() {
            let wire = parse(&value).unwrap().into_wire(chrome());
            assert!(RequestScope::BrowserHost.allows(&wire), "{name}");

            let wire = serde_json::to_value(&wire).unwrap();
            for (key, field) in value.as_object().unwrap() {
                assert_eq!(&wire[key], field, "{name}.{key}");
            }
            assert_eq!(wire["caller"], "Google Chrome", "{name}");
            if name != "generate_password" {
                assert_eq!(wire["client"]["browser"]["team_id"], "EQHXZ8M8AV", "{name}");
                assert_eq!(
                    wire["client"]["extension"], "chrome-extension://abc/",
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn unverified_host_sends_no_browser_or_caller() {
        let (_, value) = fixtures()
            .into_iter()
            .find(|(name, _)| name == "list_logins")
            .unwrap();
        let wire = parse(&value).unwrap().into_wire(BrowserClient::default());
        let wire = serde_json::to_value(&wire).unwrap();
        assert_eq!(wire["caller"], Value::Null);
        assert_eq!(wire["client"]["browser"], Value::Null);
    }

    fn with_field(value: &Value, key: &str, field: Value) -> Value {
        let mut object: Map<String, Value> = value.as_object().unwrap().clone();
        object.insert(key.to_string(), field);
        Value::Object(object)
    }

    /// A message cannot set the fields the host owns, in any request kind.
    #[test]
    fn refuses_client_and_caller_from_extension() {
        let client = serde_json::json!({
            "browser": {"name": "Google Chrome", "team_id": "EQHXZ8M8AV"},
            "extension": "chrome-extension://abc/",
        });
        for (name, value) in fixtures() {
            for (key, field) in [
                ("client", client.clone()),
                ("caller", Value::from("Google Chrome")),
                ("requester", Value::from("Notes")),
            ] {
                let error = parse(&with_field(&value, key, field)).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains(&format!("unknown field `{key}`")),
                    "{name}.{key}: {error}"
                );
            }
        }
    }

    #[test]
    fn refuses_unknown_fields() {
        for (name, value) in fixtures() {
            assert!(
                parse(&with_field(&value, "extra", Value::Bool(true))).is_err(),
                "{name}"
            );
        }
    }

    /// Request kinds outside the browser host scope cannot be represented,
    /// including the passkey requests.
    #[test]
    fn refuses_requests_outside_scope() {
        for line in [
            r#"{"request":"create_passkey","rp_id":"example.com","user_handle":"","user_name":"u","user_display_name":"u","client_data_hash":"","algorithms":[-7]}"#,
            r#"{"request":"assert_passkey","rp_id":"example.com","client_data_hash":""}"#,
            r#"{"request":"list_passkeys","rp_id":"example.com"}"#,
            r#"{"request":"report_unknown_passkey","rp_id":"example.com","credential_id":"AQ=="}"#,
            r#"{"request":"read_vault_secret","vault_key":"v","item_key":"i","credential_key":"c"}"#,
            r#"{"request":"resolve_secrets","refs":[],"purpose":"read"}"#,
            r#"{"request":"list_vault_items","vault_key":"v"}"#,
            r#"{"request":"list_identities"}"#,
            r#"{"request":"sign","key_label":"k","data":"aGk="}"#,
            r#"{"request":"list_keychain_passwords"}"#,
            r#"{"request":"confirm","description":"x"}"#,
            r#"{"url":"https://example.com","frame_url":"https://example.com"}"#,
        ] {
            let error = serde_json::from_str::<ExtensionRequest>(line).unwrap_err();
            assert!(
                error.to_string().contains("unknown variant")
                    || error.to_string().contains("missing field `request`"),
                "{line}: {error}"
            );
        }
    }

    #[test]
    fn refuses_unknown_password_policy_fields() {
        let line = r#"{"request":"generate_password","policy":{"length":20,"emoji":true}}"#;
        assert!(serde_json::from_str::<ExtensionRequest>(line).is_err());
    }
}
