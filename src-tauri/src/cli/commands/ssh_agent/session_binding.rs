use std::fmt::Debug;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use ssh_agent_lib::proto::extension::SessionBind;

use crate::ssh::known_hosts::KnownHosts;
use crate::ssh::utils::compute_short_sha256_fingerprint;

#[derive(Clone)]
pub(crate) struct SessionBinding {
    pub inner: SessionBind,
    pub host_name: Option<String>,
}

impl SessionBinding {
    pub fn new(bind: SessionBind) -> Self {
        let hostkey = bind.host_key.clone();
        let host_name = KnownHosts::load_from_user_ssh_dir()
            .ok()
            .and_then(|parser| parser.find_host_by_key(&hostkey).first().cloned());
        Self {
            inner: bind,
            host_name,
        }
    }
}

impl Debug for SessionBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = "".to_string();

        if let Some(host_name) = &self.host_name {
            out.push_str(host_name);
        } else {
            out.push_str("<unknown>");
        }

        out.push_str(&format!(
            " {}",
            compute_short_sha256_fingerprint(&self.inner.host_key),
        ));
        if self.inner.is_forwarding {
            out.push_str(" (forwarding)");
        } else {
            out.push_str(" (signing)");
        }

        write!(
            f,
            "SessionBinding({}) {{ {} }}",
            &b64.encode(&self.inner.session_id)[..8],
            out
        )
    }
}
