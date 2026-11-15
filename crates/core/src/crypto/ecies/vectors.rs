//! Test vectors of Apple's ECIES algorithm, from `vectors.json`.

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

const VECTORS_JSON: &str = include_str!("vectors.json");

/// Contents of `vectors.json`.
#[derive(Serialize, Deserialize)]
pub struct VectorFile {
    pub vectors: Vec<Vector>,
}

/// One ciphertext made by Security.framework to `public_key`.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct Vector {
    pub name: String,
    /// P-256 scalar, 32 bytes.
    #[serde_as(as = "Base64")]
    pub private_key: Vec<u8>,
    /// Uncompressed SEC1 point, 65 bytes.
    #[serde_as(as = "Base64")]
    pub public_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub plaintext: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub ciphertext: Vec<u8>,
}

/// Vectors checked into the repository.
pub fn load() -> Vec<Vector> {
    serde_json::from_str::<VectorFile>(VECTORS_JSON)
        .expect("vectors.json parses")
        .vectors
}
