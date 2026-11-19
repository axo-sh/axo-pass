use anyhow::{Context, bail};
use ssh_key::public::{EcdsaPublicKey, KeyData};

// per the docs, SecKeyCopyExternalRepresentation exports an EC key to ANSI
// X9.63 uncompressed point. This converts that to a KeyData struct. SEC1 is the
// newer specification but the format is the same:
// 04 || X || Y [ || K] where 04 denotes uncompressed point and X and Y are 32
// bytes
pub fn sec1_to_ssh_ecdsa(sec1_bytes: &[u8]) -> Result<KeyData, anyhow::Error> {
    // ANSI X9.63 uncompressed format: 0x04 || X || Y (65 bytes for P-256)
    if sec1_bytes.len() != 65 || sec1_bytes[0] != 0x04 {
        bail!("Invalid SEC1 format");
    }
    let ecdsa_key =
        EcdsaPublicKey::from_sec1_bytes(sec1_bytes).context("Failed to parse SEC1 public key")?;

    Ok(KeyData::Ecdsa(ecdsa_key))
}
