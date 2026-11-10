//! Native messaging framing: a 4-byte length in native byte order, then that
//! many bytes of JSON.

use std::io::{self, Read, Write};

use thiserror::Error;

/// Largest message accepted in either direction. Chrome refuses a message over
/// 1 MiB from a host, and the extension never needs to send one this large.
pub(super) const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub(super) enum FrameError {
    #[error("Message of {0} bytes is over the {MAX_MESSAGE_BYTES} byte limit")]
    TooLarge(usize),

    #[error("Input ended inside a message")]
    Truncated,

    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Read one message. `Ok(None)` if input ends before a message starts.
pub(super) fn read_message(reader: &mut impl Read) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {},
            Err(e) => return Err(e.into()),
        }
    }

    let len = u32::from_ne_bytes(header) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => FrameError::Truncated,
        _ => FrameError::Io(e),
    })?;
    Ok(Some(body))
}

/// Write one message and flush it.
pub(super) fn write_message(writer: &mut impl Write, body: &[u8]) -> Result<(), FrameError> {
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(FrameError::TooLarge(body.len()));
    }
    let len = body.len() as u32;
    writer.write_all(&len.to_ne_bytes())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_message(&mut out, body).unwrap();
        out
    }

    #[test]
    fn length_prefix_is_native_endian() {
        let out = framed(b"{}");
        assert_eq!(&out[..4], &2u32.to_ne_bytes());
        assert_eq!(&out[4..], b"{}");
    }

    #[test]
    fn reads_consecutive_messages() {
        let mut input = framed(br#"{"a":1}"#);
        input.extend(framed(b"[]"));
        let mut reader = Cursor::new(input);
        assert_eq!(read_message(&mut reader).unwrap().unwrap(), br#"{"a":1}"#);
        assert_eq!(read_message(&mut reader).unwrap().unwrap(), b"[]");
        assert!(read_message(&mut reader).unwrap().is_none());
    }

    #[test]
    fn empty_input_is_end_of_stream() {
        assert!(
            read_message(&mut Cursor::new(Vec::new()))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn accepts_message_at_limit() {
        let body = vec![b' '; MAX_MESSAGE_BYTES];
        let read = read_message(&mut Cursor::new(framed(&body)))
            .unwrap()
            .unwrap();
        assert_eq!(read.len(), MAX_MESSAGE_BYTES);
    }

    #[test]
    fn refuses_message_over_limit() {
        let len = (MAX_MESSAGE_BYTES + 1) as u32;
        let mut input = len.to_ne_bytes().to_vec();
        input.extend(vec![b' '; MAX_MESSAGE_BYTES + 1]);
        let error = read_message(&mut Cursor::new(input)).unwrap_err();
        assert!(
            matches!(error, FrameError::TooLarge(n) if n == MAX_MESSAGE_BYTES + 1),
            "{error}"
        );
    }

    /// The length alone decides. The body is never allocated or read.
    #[test]
    fn refuses_oversized_length_before_reading_body() {
        let input = u32::MAX.to_ne_bytes().to_vec();
        let error = read_message(&mut Cursor::new(input)).unwrap_err();
        assert!(matches!(error, FrameError::TooLarge(_)), "{error}");
    }

    #[test]
    fn refuses_oversized_reply() {
        let body = vec![b' '; MAX_MESSAGE_BYTES + 1];
        let mut out = Vec::new();
        assert!(matches!(
            write_message(&mut out, &body),
            Err(FrameError::TooLarge(_))
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn truncated_length_prefix() {
        let error = read_message(&mut Cursor::new(vec![2u8, 0])).unwrap_err();
        assert!(matches!(error, FrameError::Truncated), "{error}");
    }

    #[test]
    fn truncated_body() {
        let mut input = framed(br#"{"request":"list_logins"}"#);
        input.truncate(input.len() - 3);
        let error = read_message(&mut Cursor::new(input)).unwrap_err();
        assert!(matches!(error, FrameError::Truncated), "{error}");
    }
}
