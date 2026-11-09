use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use ssh_agent_lib::proto::extension::{HostTuple, KeySpec};
use ssh_key::PrivateKey;

use super::*;

mod permitted;
mod session_hop;

static TEST_RSA_KEY: LazyLock<KeyData> = LazyLock::new(|| {
    let data = include_str!("../fixtures/b64_rsa");
    let privkey = PrivateKey::from_bytes(b64.decode(data).unwrap().as_slice()).unwrap();
    privkey.public_key().key_data().clone()
});

static TEST_ED25519_KEY: LazyLock<KeyData> = LazyLock::new(|| {
    let data = include_str!("../fixtures/b64_ed25519");
    let privkey = PrivateKey::from_bytes(b64.decode(data).unwrap().as_slice()).unwrap();
    privkey.public_key().key_data().clone()
});

fn empty_host_tuple() -> HostTuple {
    HostTuple {
        username: "".to_string(),
        hostname: "".to_string(),
        keys: vec![],
    }
}

fn host_tuple(hostname: &str, key_data: &KeyData) -> HostTuple {
    HostTuple {
        username: "".to_string(),
        hostname: hostname.to_string(),
        keys: vec![KeySpec {
            keyblob: key_data.clone(),
            is_ca: false,
        }],
    }
}
