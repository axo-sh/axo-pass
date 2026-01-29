use std::fmt::{Debug, Display};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use ssh_encoding::Decode;
use ssh_key::PublicKey;
use ssh_key::public::KeyData;

use crate::ssh::utils::compute_short_sha256_fingerprint;

const SSH2_MSG_USERAUTH_REQUEST: u8 = 50;
const OPENSSH_PUBLIC_KEY_HOSTBOUND_METHOD: &str = "publickey-hostbound-v00@openssh.com";

#[derive(Debug, Clone)]
pub struct UserauthRequest {
    pub session_id: Vec<u8>,
    pub user: Option<String>,
    pub service: String,
    pub method: String,
    pub pubkey_algorithm: String,
    pub pubkey: KeyData,
    pub hostkey: Option<KeyData>,
}

// Parse SSH userauth request message using Decode from ssh-encoding
// see: https://www.openssh.org/agent-restrict.html#:~:text=SSH2_MSG_USERAUTH_REQUEST
impl UserauthRequest {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut reader = data;

        // Read session_id (length-prefixed bytes)
        let session_id = <Vec<u8>>::decode(&mut reader).context("Failed to decode session_id")?;
        if session_id.is_empty() {
            bail!("Invalid message: no session_id");
        }

        // Read message type (should be SSH2_MSG_USERAUTH_REQUEST = 50)
        let msg_type = u8::decode(&mut reader).context("Failed to decode message type")?;
        if msg_type != SSH2_MSG_USERAUTH_REQUEST {
            bail!("Invalid message: expected SSH2_MSG_USERAUTH_REQUEST (50) got {msg_type}");
        }

        // Read user name
        let raw_user = String::decode(&mut reader).context("Failed to decode user")?;
        let user = if raw_user.is_empty() {
            None
        } else {
            Some(raw_user)
        };

        // Read service (should be "ssh-connection")
        let service = String::decode(&mut reader).context("Failed to decode service")?;
        if service != "ssh-connection" {
            bail!("Invalid service: expected 'ssh-connection', got '{service}'");
        }

        // Read method
        let method = String::decode(&mut reader).context("Failed to decode method")?;

        // Read sig_follows (should be 1/true)
        // todo: I think we require this to be true, but double-check
        let has_signature = u8::decode(&mut reader).context("Failed to decode has_signature")? == 1;
        if !has_signature {
            bail!("Invalid has_signature: expected true (1)");
        }

        // Read public key algorithm name
        let pkalg = String::decode(&mut reader).context("Failed to decode public key algorithm")?;

        // Read public key blob
        let pubkey_blob = <Vec<u8>>::decode(&mut reader).context("Failed to decode key blob")?;
        let pubkey: KeyData = PublicKey::from_bytes(&pubkey_blob)
            .context("Failed to parse public key from blob")?
            .key_data()
            .clone();

        // Verify algorithm matches key type
        let expected_algorithms = match pubkey.algorithm() {
            ssh_key::Algorithm::Rsa { .. } => {
                vec![
                    "ssh-rsa".to_string(),
                    "rsa-sha2-256".to_string(),
                    "rsa-sha2-512".to_string(),
                ]
            },
            alg => vec![alg.as_str().to_string()],
        };
        if !expected_algorithms.contains(&pkalg) {
            bail!(
                "Algorithm mismatch: key is {}, but request specifies {pkalg}",
                pubkey.algorithm().as_str()
            );
        }

        // For hostbound method, i.e. publickey-hostbound-v00@openssh.com,
        // we read the hostkey
        let hostkey = if method == OPENSSH_PUBLIC_KEY_HOSTBOUND_METHOD {
            let hostkey_blob =
                <Vec<u8>>::decode(&mut reader).context("Failed to decode hostkey blob")?;
            let hostkey_pub = PublicKey::from_bytes(&hostkey_blob)
                .context("Failed to parse hostkey from blob")?;
            Some(hostkey_pub.key_data().clone())
        } else {
            None
        };

        // Verify no extra data remains
        if !reader.is_empty() {
            bail!("Extra data in message");
        }

        Ok(Self {
            session_id,
            user,
            service,
            method,
            pubkey_algorithm: pkalg,
            pubkey,
            hostkey,
        })
    }
}

impl Display for UserauthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let session_id = b64.encode(&self.session_id)[..8].to_string();
        f.debug_struct("UserauthRequest")
            .field("session_id", &session_id)
            .field("user", &self.user.clone().unwrap_or("ANY".to_string()))
            .field("svc", &self.service)
            .field("method", &self.method)
            .field("alg", &self.pubkey_algorithm)
            .field("pubkey", &compute_short_sha256_fingerprint(&self.pubkey))
            .field(
                "hostkey",
                &self.hostkey.as_ref().map(compute_short_sha256_fingerprint),
            )
            .finish()
    }
}
