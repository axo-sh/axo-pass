//! Canonical encoding of authenticated fields.
//!
//! Each field is its 4-byte big-endian length and its bytes. Each list is its
//! 4-byte big-endian count and its items. Moving bytes from one field to the
//! next changes the encoded bytes. The pairing HMACs and the rotation
//! signature use it.

/// Canonical encoding of a sequence of fields and lists.
#[derive(Debug, Default)]
pub struct Canonical {
    bytes: Vec<u8>,
}

impl Canonical {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append the field `bytes` with its length.
    pub fn field(mut self, bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        self.bytes.extend_from_slice(&Self::length(bytes.len()));
        self.bytes.extend_from_slice(bytes);
        self
    }

    /// Append the list `items` with its count. `encode` appends each item.
    pub fn list<T>(
        mut self,
        items: impl ExactSizeIterator<Item = T>,
        mut encode: impl FnMut(Self, T) -> Self,
    ) -> Self {
        self.bytes.extend_from_slice(&Self::length(items.len()));
        for item in items {
            self = encode(self, item);
        }
        self
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// 4-byte big-endian form of `length`.
    fn length(length: usize) -> [u8; 4] {
        u32::try_from(length)
            .expect("field is shorter than 4 GiB")
            .to_be_bytes()
    }
}
