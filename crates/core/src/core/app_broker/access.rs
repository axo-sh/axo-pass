//! Who may use the broker and what each kind of client may ask for: the peer
//! policies, the request scopes, and the identities that prompts and audit
//! events name.

use super::vault::ClientIdentity;
use super::wire::{BrowserClient, WireRequest};
use super::{AGENT_EXECUTABLE_NAME, AUTOFILL_EXTENSION_NAME, BROWSER_HOST_EXECUTABLE_NAME};
use crate::audit;
use crate::core::provenance::{PeerError, PeerIdentity, PeerPolicy, ProcessNode};

/// How prompts, grants, and audit events name a request that arrived through
/// the AutoFill extension.
pub(super) const AUTOFILL_CALLER: &str = "AutoFill extension";

/// What a prompt calls a request from a browser host that could not verify the
/// browser that started it.
pub(super) const UNKNOWN_CLIENT: &str = "Unknown process";

/// Which requests a client may send. Checked after the peer is verified and
/// before the request is dispatched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RequestScope {
    /// `ap`: every request.
    Agent,
    /// The AutoFill extension: the login requests and the passkey requests. It
    /// cannot read a vault secret by name.
    AutofillExtension,
    /// The browser host: the same requests as the AutoFill extension, plus
    /// password generation and saving. It cannot read a vault secret by name.
    BrowserHost,
}

impl RequestScope {
    pub(super) fn allows(self, request: &WireRequest) -> bool {
        let autofill = matches!(
            request,
            WireRequest::ListLogins { .. }
                | WireRequest::ListLoginsLocked { .. }
                | WireRequest::FillLogin { .. }
                | WireRequest::GenerateTotp { .. }
                | WireRequest::CreatePasskey { .. }
                | WireRequest::AssertPasskey { .. }
        );
        match self {
            RequestScope::Agent => true,
            RequestScope::AutofillExtension => autofill,
            RequestScope::BrowserHost => {
                autofill
                    || matches!(
                        request,
                        WireRequest::GeneratePassword { .. }
                            | WireRequest::SaveLogin { .. }
                            | WireRequest::UpdateLoginPassword { .. }
                    )
            },
        }
    }

    /// Whether a client may list logins from the index without a prompt. Any
    /// other caller could use it to learn the user's sites, so the agent may
    /// not, and a browser host may only when it verified its browser.
    pub(super) fn may_list_locked(self, client: &ClientIdentity) -> bool {
        match self {
            RequestScope::Agent => false,
            RequestScope::AutofillExtension => true,
            RequestScope::BrowserHost => matches!(client, ClientIdentity::Browser { .. }),
        }
    }
}

/// One kind of client a socket accepts: the peer it must be, and what it may
/// ask for.
pub(super) struct Client {
    pub(super) policy: PeerPolicy,
    pub(super) scope: RequestScope,
}

/// Who the broker takes requests from: only the agent staged beside us in the
/// app bundle, signed by the same team.
///
/// The socket's mode keeps out other users, but every process this user runs
/// can open it, including anything a compromised dependency drops on the
/// machine. The peer check narrows that to the agent.
///
/// An unsigned local build has no team to anchor to, so the requirement is
/// dropped and only the executable path and the user are checked.
pub(super) fn agent_policy() -> PeerPolicy {
    let policy = PeerPolicy::sibling_executable(AGENT_EXECUTABLE_NAME);
    let accepts = policy.executable.as_ref().map_or_else(
        || "any process running as this user".to_string(),
        |path| path.display().to_string(),
    );
    if policy.requirement.is_some() {
        log::debug!("App broker accepts {accepts}, signed by our own team");
    } else {
        log::warn!(
            "App broker cannot check its peer's code signature: this build carries no team \
             identifier. Accepting {accepts}"
        );
    }
    policy
}

/// Who the AutoFill broker takes requests from: only the credential provider
/// extension staged in our own bundle, signed by the same team.
pub(super) fn extension_policy() -> PeerPolicy {
    let policy = PeerPolicy::bundled_executable(&format!(
        "PlugIns/{AUTOFILL_EXTENSION_NAME}.appex/Contents/MacOS/{AUTOFILL_EXTENSION_NAME}"
    ));
    match policy.executable.as_ref() {
        Some(path) => log::debug!("AutoFill broker accepts {}", path.display()),
        None => log::warn!("AutoFill broker could not resolve the extension's executable"),
    }
    policy
}

/// Who the broker takes browser requests from: only the native messaging host
/// staged beside us in the app bundle, signed by the same team. The host
/// reports which browser started it, and the broker believes that report only
/// because it verified the host.
pub(super) fn browser_host_policy() -> PeerPolicy {
    let policy = PeerPolicy::sibling_executable(BROWSER_HOST_EXECUTABLE_NAME);
    match policy.executable.as_ref() {
        Some(path) => log::debug!("App broker accepts the browser host {}", path.display()),
        None => log::warn!("App broker could not resolve the browser host's executable"),
    }
    policy
}

/// Verify `fd`'s peer against each client's policy in turn. The first policy it
/// satisfies gives the peer and the scope. When none does, the error is the
/// first policy's, which is the main client's.
pub(super) fn verify_client(
    fd: std::os::fd::RawFd,
    clients: &[Client],
) -> Result<(PeerIdentity, RequestScope), PeerError> {
    let mut first_error = None;
    for client in clients {
        match PeerIdentity::verify(fd, &client.policy) {
            Ok(peer) => return Ok((peer, client.scope)),
            // Nothing is left to check on a closed connection.
            Err(e) if e.is_disconnected() => return Err(e),
            Err(e) => {
                first_error.get_or_insert(e);
            },
        }
    }
    Err(first_error.unwrap_or_else(|| PeerError::Unidentified("no client is accepted".to_string())))
}

/// Record a peer that failed its transport's policy. `peer` describes it with
/// no policy applied. The executable and signature come from code that failed
/// the policy, so the event marks them unverified.
pub(super) fn record_rejected_peer(error: &PeerError, peer: Option<PeerIdentity>) {
    let mut event = audit::AuditEvent::new(
        audit::process_source(),
        audit::Action::BrokerPeerRejected,
        audit::Outcome::Denied,
    )
    .message(error.to_string())
    .detail("peer_verified", "false");
    if let Some(peer) = peer {
        log::debug!("App broker rejected peer: {peer:#?}");
        event = event.actor(peer_actor(&peer));
    }
    audit::record(event);
}

/// Build an audit actor from a peer. Whether the peer passed the policy is the
/// caller's to record: the same fields are read either way.
pub(super) fn peer_actor(peer: &PeerIdentity) -> audit::Actor {
    audit::Actor {
        caller: peer.caller(),
        pid: Some(peer.pid()),
        executable: peer.executable(),
        bundle_id: peer.bundle_id(),
        team_id: peer.team_id(),
        chain: peer.provenance().chain_labels(),
        chain_detail: peer.provenance().chain_nodes(),
    }
}

/// Who a request is for. Only a browser host reports a browser, and the report
/// counts only from a peer verified as our host, so any other scope ignores
/// what the request says.
pub(super) fn client_identity(
    scope: RequestScope,
    reported: Option<&BrowserClient>,
) -> ClientIdentity {
    if scope != RequestScope::BrowserHost {
        return ClientIdentity::Process;
    }
    let reported = reported.cloned().unwrap_or_default();
    match reported.browser {
        Some(browser) => ClientIdentity::Browser {
            name: browser.name,
            team_id: browser.team_id,
            extension: reported.extension,
        },
        None => ClientIdentity::Unverified {
            extension: reported.extension,
        },
    }
}

/// The caller to put in a prompt. The AutoFill extension and the browser host
/// are our own verified code, so they name the caller themselves and the
/// request's `caller` is ignored. Any other client names its own caller, which
/// is trusted by delegation.
pub(super) fn vouched_caller(
    scope: RequestScope,
    client: &ClientIdentity,
    delegated: Option<String>,
) -> Option<String> {
    match scope {
        RequestScope::Agent => delegated,
        RequestScope::AutofillExtension => Some(AUTOFILL_CALLER.to_string()),
        RequestScope::BrowserHost => Some(match client {
            ClientIdentity::Browser { name, .. } => name.clone(),
            _ => UNKNOWN_CLIENT.to_string(),
        }),
    }
}

/// The name of the app a login request is for. Only the AutoFill extension
/// names one. For any other client the request is for a browser, and a name it
/// sent is dropped.
pub(super) fn requester_for(scope: RequestScope, requester: Option<String>) -> Option<String> {
    (scope == RequestScope::AutofillExtension)
        .then_some(requester)
        .flatten()
}

/// Describe who a request is for: the peer we verified, named by the caller it
/// delegated to us.
///
/// The process identity comes from the peer, which we checked ourselves. The
/// caller comes from the request when it carries one, because a long-running
/// peer's own chain leads to launchd rather than to whoever asked it: the
/// agent knows `git` made the request, and we cannot see that from the socket.
/// A peer that names nobody falls back to its own chain root.
pub(super) fn request_actor(
    peer: &PeerIdentity,
    delegated_caller: Option<&str>,
    delegated_chain: &[ProcessNode],
) -> audit::Actor {
    let mut actor = peer_actor(peer);
    if let Some(caller) = delegated_caller.filter(|c| !c.is_empty()) {
        actor.caller = Some(caller.to_string());
    }
    if !delegated_chain.is_empty() {
        actor.chain_detail = delegated_chain.to_vec();
    }
    actor
}
