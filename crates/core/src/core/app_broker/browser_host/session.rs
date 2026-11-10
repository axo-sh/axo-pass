//! Nonce exchange at the start of each host process.
//!
//! The host writes [`Hello`] before it reads anything. It carries the protocol
//! version and a random nonce. The extension echoes both in the [`Envelope`]
//! around its request. The host refuses a request without the nonce, a request
//! for another protocol version, and any input written before the hello.
//!
//! The nonce adds no protection until the pipe holder scan of M8 runs before
//! the hello. Until then a process that started the host can read the nonce
//! from the host's stdout.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};

use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use serde::Serialize;
use subtle::ConstantTimeEq;

use super::super::wire::WireResponse;
use super::framing::{read_message, write_message};
use super::request::{Envelope, ExtensionRequest};
use super::{HostStatus, failed};

/// Protocol version between the host and the extension. The extension sends a
/// request only if the hello carries the version it speaks.
pub(super) const PROTOCOL_VERSION: u32 = 1;

/// Random value of one host process. 32 bytes, written as 64 lowercase hex
/// characters. `Debug` shows no value, and the nonce is never logged.
pub(super) struct Nonce(String);

impl Nonce {
    pub(super) fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    #[cfg(test)]
    pub(super) fn from_text(text: &str) -> Self {
        Self(text.to_string())
    }

    /// Whether `text` is this nonce. The comparison takes constant time for
    /// inputs of the nonce length.
    fn matches(&self, text: &str) -> bool {
        self.0.as_bytes().ct_eq(text.as_bytes()).into()
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Nonce(..)")
    }
}

/// First message from the host.
#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug, PartialEq))]
#[serde(deny_unknown_fields)]
pub(super) struct Hello {
    pub(super) version: u32,
    pub(super) nonce: String,
}

/// Reply to a request the host refuses before it reaches the broker.
#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum Refusal {
    Broker(Box<WireResponse>),
    Host(HostStatus),
}

/// Shows the host status only. `WireResponse` has no `Debug`.
impl fmt::Debug for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Broker(_) => f.write_str("Refusal::Broker(..)"),
            Refusal::Host(status) => f.debug_tuple("Refusal::Host").field(status).finish(),
        }
    }
}

impl Refusal {
    fn failed(message: impl Into<String>) -> Self {
        Refusal::Broker(Box::new(failed(message.into())))
    }
}

/// Write the hello with a new nonce. Refused if `stdin` already holds input,
/// since a request written before the nonce cannot be from an extension that
/// read it.
pub(super) fn greet(stdin: BorrowedFd<'_>, stdout: &mut impl Write) -> Result<Nonce, Refusal> {
    match pending_input(stdin) {
        Ok(0) => {},
        Ok(n) => {
            log::warn!("Browser host refused {n} bytes written before the nonce");
            return Err(Refusal::failed("Input was written before the host nonce"));
        },
        Err(e) => {
            log::warn!("Browser host could not check its input: {e}");
            return Err(Refusal::failed(format!("Could not check input: {e}")));
        },
    }
    let nonce = Nonce::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        nonce: nonce.0.clone(),
    };
    let body = serde_json::to_vec(&hello).map_err(|e| Refusal::failed(e.to_string()))?;
    write_message(stdout, &body).map_err(|e| {
        log::warn!("Browser host could not write the hello: {e}");
        Refusal::failed(e.to_string())
    })?;
    Ok(nonce)
}

/// Bytes waiting to be read on `fd`, from `FIONREAD`. Works for pipes, which
/// browsers use for stdin, and for terminals and files.
fn pending_input(fd: BorrowedFd<'_>) -> io::Result<usize> {
    let mut count: libc::c_int = 0;
    // SAFETY: FIONREAD writes one c_int through the pointer, which is valid
    // for the duration of the call.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FIONREAD, &mut count) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(count).unwrap_or(0))
}

/// Read one request and check its envelope. `Ok(None)` if input ends before a
/// message starts. The nonce is checked before the version, so input without
/// the nonce gets no answer beyond the refusal.
pub(super) fn read_request(
    input: &mut impl Read,
    nonce: &Nonce,
) -> Result<Option<ExtensionRequest>, Refusal> {
    let body = match read_message(input) {
        Ok(Some(body)) => body,
        Ok(None) => return Ok(None),
        Err(e) => {
            log::warn!("Browser host could not read a message: {e}");
            return Err(Refusal::failed(e.to_string()));
        },
    };

    // Parse errors can quote the input, so their text goes back to the
    // extension and not to the log.
    let envelope: Envelope = serde_json::from_slice(&body).map_err(|e| {
        log::warn!(
            "Browser host refused a malformed envelope ({:?})",
            e.classify()
        );
        Refusal::failed(format!("Malformed request: {e}"))
    })?;
    if !nonce.matches(&envelope.nonce) {
        log::warn!("Browser host refused a request without its nonce");
        return Err(Refusal::failed("The request does not carry the host nonce"));
    }
    if envelope.version != PROTOCOL_VERSION {
        log::warn!(
            "Browser host refused protocol version {}, it speaks {PROTOCOL_VERSION}",
            envelope.version
        );
        return Err(Refusal::Host(HostStatus::VersionMismatch {
            version: PROTOCOL_VERSION,
        }));
    }
    let request = serde_json::from_value(envelope.body).map_err(|e| {
        log::warn!(
            "Browser host refused a malformed request ({:?})",
            e.classify()
        );
        Refusal::failed(format!("Malformed request: {e}"))
    })?;
    Ok(Some(request))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::os::fd::AsFd;
    use std::path::PathBuf;

    use serde_json::{Value, json};

    use super::*;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/native-messaging")
    }

    fn fixture(path: &str) -> Value {
        let text = std::fs::read_to_string(fixtures_dir().join(path)).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn framed(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        write_message(&mut out, value.to_string().as_bytes()).unwrap();
        out
    }

    fn list_logins(version: Value, nonce: Option<&str>) -> Value {
        let mut envelope = json!({
            "version": version,
            "body": {
                "request": "list_logins",
                "url": "https://github.com/login",
                "frame_url": "https://github.com/login",
                "all": false,
            },
        });
        if let Some(nonce) = nonce {
            envelope["nonce"] = Value::from(nonce);
        }
        envelope
    }

    fn read(value: &Value, nonce: &Nonce) -> Result<Option<ExtensionRequest>, Refusal> {
        read_request(&mut Cursor::new(framed(value)), nonce)
    }

    fn refusal_json(refusal: Refusal) -> Value {
        serde_json::to_value(refusal).unwrap()
    }

    fn assert_failed(result: Result<Option<ExtensionRequest>, Refusal>, text: &str) {
        let reply = refusal_json(result.unwrap_err());
        assert_eq!(reply["status"], "failed", "{reply}");
        let message = reply["message"].as_str().unwrap();
        assert!(message.contains(text), "{message}");
    }

    #[test]
    fn nonces_are_random_hex() {
        let a = Nonce::generate();
        let b = Nonce::generate();
        assert_eq!(a.0.len(), 64);
        assert!(
            a.0.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(a.0, b.0);
        assert!(a.matches(&a.0));
        assert!(!a.matches(&b.0));
        assert!(!a.matches(&a.0[..63]));
        assert!(!a.matches(""));
        assert_eq!(format!("{a:?}"), "Nonce(..)");
    }

    #[test]
    fn accepts_request_with_nonce() {
        let nonce = Nonce::generate();
        let request = read(
            &list_logins(json!(PROTOCOL_VERSION), Some(&nonce.0)),
            &nonce,
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.kind(), "list_logins");
    }

    #[test]
    fn refuses_request_without_nonce() {
        let nonce = Nonce::generate();
        assert_failed(
            read(&list_logins(json!(PROTOCOL_VERSION), None), &nonce),
            "missing field `nonce`",
        );
        // A request without the envelope, as sent before M3.b.
        let bare = list_logins(json!(PROTOCOL_VERSION), None)["body"].clone();
        assert_failed(read(&bare, &nonce), "Malformed request");
    }

    #[test]
    fn refuses_request_with_wrong_nonce() {
        let nonce = Nonce::generate();
        let other = Nonce::generate();
        for wrong in [
            other.0.as_str(),
            &nonce.0[..63],
            &nonce.0.to_uppercase(),
            "",
        ] {
            assert_failed(
                read(&list_logins(json!(PROTOCOL_VERSION), Some(wrong)), &nonce),
                "does not carry the host nonce",
            );
        }
    }

    /// The nonce is checked first, so a wrong nonce with another version gets
    /// no version reply.
    #[test]
    fn refuses_wrong_nonce_before_version() {
        let nonce = Nonce::generate();
        assert_failed(
            read(&list_logins(json!(PROTOCOL_VERSION + 1), Some("x")), &nonce),
            "does not carry the host nonce",
        );
    }

    #[test]
    fn version_mismatch_reports_host_version() {
        let nonce = Nonce::generate();
        for version in [0, PROTOCOL_VERSION + 1] {
            let reply = refusal_json(
                read(&list_logins(json!(version), Some(&nonce.0)), &nonce).unwrap_err(),
            );
            assert_eq!(
                reply,
                json!({"status": "version_mismatch", "version": PROTOCOL_VERSION})
            );
        }
    }

    #[test]
    fn refuses_unknown_envelope_fields_and_bad_body() {
        let nonce = Nonce::generate();
        let mut extra = list_logins(json!(PROTOCOL_VERSION), Some(&nonce.0));
        extra["client"] = json!({"browser": null});
        assert_failed(read(&extra, &nonce), "unknown field `client`");

        let mut body = list_logins(json!(PROTOCOL_VERSION), Some(&nonce.0));
        body["body"]["caller"] = json!("Google Chrome");
        assert_failed(read(&body, &nonce), "unknown field `caller`");
    }

    #[test]
    fn end_of_input_is_no_request() {
        let nonce = Nonce::generate();
        assert!(
            read_request(&mut Cursor::new(Vec::new()), &nonce)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn greets_with_version_and_nonce() {
        let (reader, mut writer) = io::pipe().unwrap();
        let mut out = Vec::new();
        let nonce = greet(reader.as_fd(), &mut out).unwrap();

        let hello = read_message(&mut Cursor::new(out)).unwrap().unwrap();
        let hello: Hello = serde_json::from_slice(&hello).unwrap();
        assert_eq!(hello.version, PROTOCOL_VERSION);
        assert!(nonce.matches(&hello.nonce));

        // The extension answers with the nonce from the hello.
        let request = list_logins(json!(hello.version), Some(&hello.nonce));
        writer.write_all(&framed(&request)).unwrap();
        drop(writer);
        let mut reader = reader;
        let request = read_request(&mut reader, &nonce).unwrap().unwrap();
        assert_eq!(request.kind(), "list_logins");
    }

    #[test]
    fn refuses_request_written_before_nonce() {
        let (reader, mut writer) = io::pipe().unwrap();
        let early = list_logins(json!(PROTOCOL_VERSION), Some(&"0".repeat(64)));
        writer.write_all(&framed(&early)).unwrap();

        let mut out = Vec::new();
        let refusal = greet(reader.as_fd(), &mut out).unwrap_err();
        assert!(out.is_empty(), "no hello after early input");
        let reply = refusal_json(refusal);
        assert_eq!(reply["status"], "failed");
        assert!(
            reply["message"]
                .as_str()
                .unwrap()
                .contains("before the host nonce")
        );
    }

    /// A single byte is enough to refuse. A closed pipe with nothing in it is
    /// not early input.
    #[test]
    fn counts_pending_input() {
        let (reader, mut writer) = io::pipe().unwrap();
        assert_eq!(pending_input(reader.as_fd()).unwrap(), 0);
        writer.write_all(b"x").unwrap();
        assert_eq!(pending_input(reader.as_fd()).unwrap(), 1);
        drop(writer);
        let (reader, writer) = io::pipe().unwrap();
        drop(writer);
        assert_eq!(pending_input(reader.as_fd()).unwrap(), 0);
    }

    /// The hello fixture shared with the extension tests parses as a hello and
    /// serializes back to the same JSON.
    #[test]
    fn hello_fixture_round_trips() {
        let value = fixture("hello.json");
        let hello: Hello = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(hello.version, PROTOCOL_VERSION);
        assert_eq!(hello.nonce.len(), 64);
        assert_eq!(serde_json::to_value(&hello).unwrap(), value);
    }

    /// Each request fixture carries the nonce of the hello fixture and is
    /// accepted with it.
    #[test]
    fn request_fixtures_carry_hello_nonce() {
        let hello: Hello = serde_json::from_value(fixture("hello.json")).unwrap();
        let nonce = Nonce::from_text(&hello.nonce);
        for entry in std::fs::read_dir(fixtures_dir().join("requests")).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_stem().unwrap().to_string_lossy().into_owned();
            let value = fixture(&format!("requests/{name}.json"));
            let request = read(&value, &nonce)
                .unwrap_or_else(|e| panic!("{name}: {e:?}"))
                .unwrap();
            assert_eq!(request.kind(), name);
            assert_failed(read(&value, &Nonce::generate()), "host nonce");
        }
    }
}
