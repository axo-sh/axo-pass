//! The AutoFill extension's transport: a Mach service named under the App
//! Group.
//!
//! The extension is sandboxed. A sandboxed process may look up a Mach service
//! whose name starts with an App Group it belongs to, and the lookup touches no
//! files. A socket in the group's container would also reach it, but an
//! unsandboxed app touching that container raises the "access data from other
//! apps" consent prompt.
//!
//! `NSXPCListener(machServiceName:)` only listens on services a launchd plist
//! declares, so the app registers its own receive right with
//! `bootstrap_register`. That call has been deprecated since macOS 10.5 and
//! still works. `CFMessagePort` registers its names the same way.
//!
//! One request is one message:
//!
//! - Request: a complex message with `msgh_id` [`REQUEST_ID`] and one
//!   out-of-line descriptor holding the request JSON. The client's reply port
//!   travels as a send-once right in the header.
//! - Reply: a complex message with `msgh_id` [`REPLY_ID`] and one out-of-line
//!   descriptor holding the response JSON.
//!
//! Every request is received with an audit trailer, and its sender is verified
//! from that token, as the socket verifies its peer from `LOCAL_PEERTOKEN`. A
//! sender that fails the policy, or a malformed or unreadable request, gets no
//! reply: its reply right is destroyed, which the client receives as a
//! send-once notification instead of a reply.
//!
//! The client side is `BrokerClient` in app/Sources/AxoPassAutoFill.

use std::ffi::{CString, c_char};
use std::ptr::addr_of_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::{
    Authorizers, RequestScope, WireRequest, WireResponse, record_rejected_peer, serve_request,
};
use crate::core::provenance::{PeerIdentity, PeerPolicy};

/// `msgh_id` of a request. Matches `BrokerClient.requestID`.
const REQUEST_ID: i32 = 0x4158_5001;
/// `msgh_id` of a reply. Matches `BrokerClient.replyID`.
const REPLY_ID: i32 = 0x4158_5002;

/// Requests larger than this are dropped unread.
const MAX_REQUEST_BYTES: u32 = 1 << 20;
/// How long a receive waits before checking whether the service is stopping.
const RECEIVE_TIMEOUT_MS: u32 = 500;
/// How long a reply may wait for room in the client's queue.
const REPLY_TIMEOUT_MS: u32 = 1000;
/// How often a request in progress checks whether its client has gone away.
const DEAD_CLIENT_POLL: Duration = Duration::from_millis(250);

type MachPort = u32;
type KernReturn = i32;

// From mach/kern_return.h, mach/port.h, and mach/message.h.
const KERN_SUCCESS: KernReturn = 0;
const MACH_PORT_RIGHT_RECEIVE: u32 = 1;
const MACH_PORT_TYPE_DEAD_NAME: u32 = 1 << 20;
const MACH_MSG_TYPE_MOVE_SEND_ONCE: u32 = 18;
const MACH_MSG_TYPE_MAKE_SEND: u32 = 20;
const MACH_MSGH_BITS_REMOTE_MASK: u32 = 0x1f;
const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;
const MACH_MSG_OOL_DESCRIPTOR: u8 = 1;
const MACH_MSG_VIRTUAL_COPY: u8 = 1;
const MACH_SEND_MSG: i32 = 0x1;
const MACH_RCV_MSG: i32 = 0x2;
const MACH_SEND_TIMEOUT: i32 = 0x10;
const MACH_RCV_TIMEOUT: i32 = 0x100;
/// `MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
/// MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT)`.
const MACH_RCV_TRAILER_AUDIT: i32 = 3 << 24;
const MACH_RCV_INVALID_NAME: KernReturn = 0x1000_4002;
const MACH_RCV_TIMED_OUT: KernReturn = 0x1000_4003;
const MACH_RCV_PORT_DIED: KernReturn = 0x1000_4009;

/// `mach_msg_header_t`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Header {
    bits: u32,
    size: u32,
    remote_port: MachPort,
    local_port: MachPort,
    voucher_port: MachPort,
    id: i32,
}

/// `mach_msg_ool_descriptor_t` for a 64-bit process. The four one-byte fields
/// are C bitfields in declaration order, which is byte order on little-endian
/// Macs.
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
struct OolDescriptor {
    address: u64,
    deallocate: u8,
    copy: u8,
    pad1: u8,
    kind: u8,
    size: u32,
}

/// A request or a reply: header, body, and one out-of-line descriptor.
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
struct OolMessage {
    header: Header,
    descriptor_count: u32,
    descriptor: OolDescriptor,
}

/// `mach_msg_audit_trailer_t`.
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
struct AuditTrailer {
    kind: u32,
    size: u32,
    seqno: u32,
    sender: [u32; 2],
    audit: [u32; 8],
}

/// Room for a well-formed request and its trailer. Anything larger fails the
/// receive with `MACH_RCV_TOO_LARGE`, and the kernel destroys it.
#[repr(C, packed(4))]
struct ReceiveBuffer {
    message: OolMessage,
    trailer: AuditTrailer,
}

unsafe extern "C" {
    static mach_task_self_: MachPort;
    static bootstrap_port: MachPort;

    fn mach_port_allocate(task: MachPort, right: u32, name: *mut MachPort) -> KernReturn;
    fn mach_port_insert_right(
        task: MachPort,
        name: MachPort,
        poly: MachPort,
        poly_poly: u32,
    ) -> KernReturn;
    fn mach_port_mod_refs(task: MachPort, name: MachPort, right: u32, delta: i32) -> KernReturn;
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;
    fn mach_port_type(task: MachPort, name: MachPort, port_type: *mut u32) -> KernReturn;
    fn mach_msg(
        msg: *mut Header,
        option: i32,
        send_size: u32,
        rcv_size: u32,
        rcv_name: MachPort,
        timeout: u32,
        notify: MachPort,
    ) -> KernReturn;
    fn mach_msg_destroy(msg: *mut Header);
    fn vm_deallocate(task: MachPort, address: usize, size: usize) -> KernReturn;
    fn bootstrap_register(bp: MachPort, service_name: *const c_char, sp: MachPort) -> KernReturn;
}

fn task() -> MachPort {
    // SAFETY: a process-wide constant set before `main`.
    unsafe { mach_task_self_ }
}

fn check(kr: KernReturn, call: &str) -> std::io::Result<()> {
    if kr == KERN_SUCCESS {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("{call} failed: {kr:#x}")))
    }
}

/// A registered Mach service and the thread receiving on it. The thread
/// serves one request at a time and destroys the port when it exits, which
/// removes the name from the bootstrap namespace.
pub(super) struct MachService {
    stopping: Arc<AtomicBool>,
}

impl MachService {
    /// Register `name` and start serving it. Fails if the name is already
    /// registered, for example by another running copy of the app.
    pub(super) fn start(
        name: &str,
        policy: PeerPolicy,
        scope: RequestScope,
        authorizers: Authorizers,
    ) -> std::io::Result<Self> {
        let c_name = CString::new(name).map_err(std::io::Error::other)?;
        let mut port: MachPort = 0;
        // SAFETY: plain Mach calls on our own task with valid out-pointers.
        unsafe {
            check(
                mach_port_allocate(task(), MACH_PORT_RIGHT_RECEIVE, &mut port),
                "mach_port_allocate",
            )?;
            let registered = check(
                mach_port_insert_right(task(), port, port, MACH_MSG_TYPE_MAKE_SEND),
                "mach_port_insert_right",
            )
            .and_then(|()| {
                // bootstrap_register copies the send right, so ours is
                // released afterward.
                let result = check(
                    bootstrap_register(bootstrap_port, c_name.as_ptr(), port),
                    "bootstrap_register",
                );
                mach_port_deallocate(task(), port);
                result
            });
            if let Err(e) = registered {
                mach_port_mod_refs(task(), port, MACH_PORT_RIGHT_RECEIVE, -1);
                return Err(e);
            }
        }
        log::debug!("AutoFill broker listening on Mach service {name}");

        let stopping = Arc::new(AtomicBool::new(false));
        let rt = tokio::runtime::Handle::current();
        let thread_stopping = Arc::clone(&stopping);
        let spawned = std::thread::Builder::new()
            .name("autofill-broker".to_string())
            .spawn(move || {
                receive_loop(port, &policy, scope, &authorizers, &rt, &thread_stopping);
                // SAFETY: the receive right is ours and nothing else uses it.
                unsafe { mach_port_mod_refs(task(), port, MACH_PORT_RIGHT_RECEIVE, -1) };
                log::debug!("AutoFill broker stopped");
            });
        if let Err(e) = spawned {
            // SAFETY: as above; the thread never started.
            unsafe { mach_port_mod_refs(task(), port, MACH_PORT_RIGHT_RECEIVE, -1) };
            return Err(e);
        }
        Ok(Self { stopping })
    }

    /// Stop serving. The thread notices within [`RECEIVE_TIMEOUT_MS`], or after
    /// the request it is serving finishes.
    pub(super) fn stop(self) {
        self.stopping.store(true, Ordering::Relaxed);
    }
}

fn receive_loop(
    port: MachPort,
    policy: &PeerPolicy,
    scope: RequestScope,
    authorizers: &Authorizers,
    rt: &tokio::runtime::Handle,
    stopping: &AtomicBool,
) {
    while !stopping.load(Ordering::Relaxed) {
        // SAFETY: an all-zero buffer is a valid value for these plain structs.
        let mut buffer: ReceiveBuffer = unsafe { std::mem::zeroed() };
        // SAFETY: the buffer is as large as the size passed.
        let kr = unsafe {
            mach_msg(
                addr_of_mut!(buffer).cast(),
                MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_TRAILER_AUDIT,
                0,
                size_of::<ReceiveBuffer>() as u32,
                port,
                RECEIVE_TIMEOUT_MS,
                0,
            )
        };
        match kr {
            KERN_SUCCESS => {},
            MACH_RCV_TIMED_OUT => continue,
            MACH_RCV_INVALID_NAME | MACH_RCV_PORT_DIED => {
                log::error!("AutoFill broker port is gone: {kr:#x}");
                return;
            },
            _ => {
                log::warn!("AutoFill broker receive failed: {kr:#x}");
                continue;
            },
        }

        let Some((body, reply, token)) = take_request(&mut buffer) else {
            continue;
        };
        serve_one(body, reply, token, policy, scope, authorizers, rt);
    }
}

/// Check a received message's shape and take its request bytes, reply right,
/// and sender audit token. A malformed message is destroyed, which releases
/// any rights and memory it carried.
fn take_request(buffer: &mut ReceiveBuffer) -> Option<(Vec<u8>, MachPort, [u32; 8])> {
    let message = buffer.message;
    let header = message.header;
    let descriptor = message.descriptor;
    let trailer = buffer.trailer;

    let well_formed = header.bits & MACH_MSGH_BITS_COMPLEX != 0
        && header.bits & MACH_MSGH_BITS_REMOTE_MASK == MACH_MSG_TYPE_MOVE_SEND_ONCE
        && header.remote_port != 0
        && header.size as usize == size_of::<OolMessage>()
        && header.id == REQUEST_ID
        && message.descriptor_count == 1
        && descriptor.kind == MACH_MSG_OOL_DESCRIPTOR
        && descriptor.size <= MAX_REQUEST_BYTES
        && trailer.kind == 0
        && trailer.size as usize >= size_of::<AuditTrailer>();
    if !well_formed {
        log::warn!("AutoFill broker dropped a malformed message (id {:#x})", {
            header.id
        });
        // SAFETY: the buffer holds the message the kernel just delivered.
        unsafe { mach_msg_destroy(addr_of_mut!(*buffer).cast()) };
        return None;
    }

    let address = descriptor.address as usize;
    let size = descriptor.size as usize;
    let body = if size == 0 {
        Vec::new()
    } else {
        // SAFETY: the kernel mapped `size` bytes at `address` for this message,
        // and they are ours until deallocated below.
        let body = unsafe { std::slice::from_raw_parts(address as *const u8, size) }.to_vec();
        unsafe { vm_deallocate(task(), address, size) };
        body
    };
    Some((body, header.remote_port, trailer.audit))
}

fn serve_one(
    body: Vec<u8>,
    reply: MachPort,
    token: [u32; 8],
    policy: &PeerPolicy,
    scope: RequestScope,
    authorizers: &Authorizers,
    rt: &tokio::runtime::Handle,
) {
    let peer = match PeerIdentity::verify_audit_token(token, policy) {
        Ok(peer) => peer,
        Err(e) => {
            log::warn!("AutoFill broker refused a request: {e}");
            record_rejected_peer(
                &e,
                PeerIdentity::verify_audit_token(token, &PeerPolicy::default()).ok(),
            );
            release(reply);
            return;
        },
    };
    log::debug!("AutoFill broker peer: {peer:#?}");

    let request: WireRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("AutoFill broker could not read a request: {e}");
            release(reply);
            return;
        },
    };

    // A client that gave up while its request waited in the queue is not
    // served at all, so the app shows no prompt and records nothing for it.
    if client_gone(reply) {
        log::debug!("AutoFill broker client went away before its request was served");
        release(reply);
        return;
    }

    let response = rt.block_on(serve_request(
        request,
        &peer,
        scope,
        authorizers.clone(),
        client_departure(reply),
    ));
    match response {
        Ok(Some(response)) => send_reply(reply, &response),
        Ok(None) => release(reply),
        Err(e) => {
            log::debug!("AutoFill broker request failed: {e}");
            release(reply);
        },
    }
}

/// Whether the client's reply port is gone. Our send-once right to it turns
/// into a dead name when the client exits or destroys the port.
fn client_gone(reply: MachPort) -> bool {
    let mut port_type = 0;
    // SAFETY: a plain Mach call with a valid out-pointer.
    let kr = unsafe { mach_port_type(task(), reply, &mut port_type) };
    kr != KERN_SUCCESS || port_type & MACH_PORT_TYPE_DEAD_NAME != 0
}

/// Resolves once the client is gone.
async fn client_departure(reply: MachPort) {
    while !client_gone(reply) {
        tokio::time::sleep(DEAD_CLIENT_POLL).await;
    }
}

/// Drop a reply right without replying. A live client receives a send-once
/// notification in place of the reply.
fn release(reply: MachPort) {
    // SAFETY: the right is ours and is not used again.
    unsafe { mach_port_deallocate(task(), reply) };
}

fn send_reply(reply: MachPort, response: &WireResponse) {
    let body = match serde_json::to_vec(response) {
        Ok(body) => body,
        Err(e) => {
            log::error!("AutoFill broker could not encode a response: {e}");
            release(reply);
            return;
        },
    };
    let mut message = OolMessage {
        header: Header {
            bits: MACH_MSG_TYPE_MOVE_SEND_ONCE | MACH_MSGH_BITS_COMPLEX,
            size: size_of::<OolMessage>() as u32,
            remote_port: reply,
            id: REPLY_ID,
            ..Header::default()
        },
        descriptor_count: 1,
        descriptor: OolDescriptor {
            address: body.as_ptr() as u64,
            deallocate: 0,
            copy: MACH_MSG_VIRTUAL_COPY,
            pad1: 0,
            kind: MACH_MSG_OOL_DESCRIPTOR,
            size: body.len() as u32,
        },
    };
    // SAFETY: the message points at `body`, which outlives the call, and the
    // kernel copies it before returning.
    let kr = unsafe {
        mach_msg(
            addr_of_mut!(message).cast(),
            MACH_SEND_MSG | MACH_SEND_TIMEOUT,
            size_of::<OolMessage>() as u32,
            0,
            0,
            REPLY_TIMEOUT_MS,
            0,
        )
    };
    if kr != KERN_SUCCESS {
        log::debug!("AutoFill broker could not send a reply: {kr:#x}");
        release(reply);
    }
}

/// A client for tests, speaking the same protocol as the extension's
/// `BrokerClient`. Returns the response bytes, or `None` when the service
/// dropped the request without replying.
#[cfg(test)]
pub(super) fn send_test_request(name: &str, body: &[u8]) -> Option<Vec<u8>> {
    const MACH_MSG_TYPE_COPY_SEND: u32 = 19;
    const MACH_MSG_TYPE_MAKE_SEND_ONCE: u32 = 21;

    unsafe extern "C" {
        fn bootstrap_look_up(
            bp: MachPort,
            service_name: *const c_char,
            sp: *mut MachPort,
        ) -> KernReturn;
    }

    let c_name = CString::new(name).unwrap();
    let mut service: MachPort = 0;
    let mut reply: MachPort = 0;
    // SAFETY: plain Mach calls with valid pointers; `body` outlives the send.
    unsafe {
        check(
            bootstrap_look_up(bootstrap_port, c_name.as_ptr(), &mut service),
            "look up",
        )
        .ok()?;
        check(
            mach_port_allocate(task(), MACH_PORT_RIGHT_RECEIVE, &mut reply),
            "mach_port_allocate",
        )
        .unwrap();

        let mut request = OolMessage {
            header: Header {
                bits: MACH_MSG_TYPE_COPY_SEND
                    | (MACH_MSG_TYPE_MAKE_SEND_ONCE << 8)
                    | MACH_MSGH_BITS_COMPLEX,
                size: size_of::<OolMessage>() as u32,
                remote_port: service,
                local_port: reply,
                id: REQUEST_ID,
                ..Header::default()
            },
            descriptor_count: 1,
            descriptor: OolDescriptor {
                address: body.as_ptr() as u64,
                deallocate: 0,
                copy: MACH_MSG_VIRTUAL_COPY,
                pad1: 0,
                kind: MACH_MSG_OOL_DESCRIPTOR,
                size: body.len() as u32,
            },
        };
        check(
            mach_msg(
                addr_of_mut!(request).cast(),
                MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                size_of::<OolMessage>() as u32,
                0,
                0,
                1000,
                0,
            ),
            "send",
        )
        .unwrap();

        let mut buffer: ReceiveBuffer = std::mem::zeroed();
        check(
            mach_msg(
                addr_of_mut!(buffer).cast(),
                MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                0,
                size_of::<ReceiveBuffer>() as u32,
                reply,
                5000,
                0,
            ),
            "receive",
        )
        .unwrap();

        let message = buffer.message;
        let response = (message.header.id == REPLY_ID).then(|| {
            let descriptor = message.descriptor;
            let address = descriptor.address as usize;
            let size = descriptor.size as usize;
            let bytes = std::slice::from_raw_parts(address as *const u8, size).to_vec();
            vm_deallocate(task(), address, size);
            bytes
        });
        mach_port_mod_refs(task(), reply, MACH_PORT_RIGHT_RECEIVE, -1);
        mach_port_deallocate(task(), service);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layouts must match the kernel's, or every request is dropped as
    /// malformed.
    #[test]
    fn message_layouts_match_the_kernel() {
        assert_eq!(size_of::<Header>(), 24);
        assert_eq!(size_of::<OolDescriptor>(), 16);
        assert_eq!(size_of::<OolMessage>(), 44);
        assert_eq!(size_of::<AuditTrailer>(), 52);
        assert_eq!(std::mem::offset_of!(OolMessage, descriptor), 28);
    }
}
