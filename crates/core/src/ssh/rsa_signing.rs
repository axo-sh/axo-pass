/*!
Signing with an SSH private key held in memory, honouring the agent request's
flags.

RSA keys are signed here rather than through ssh_key to backport some fixes:

The ssh_key crate doesn't properly handle RSA signing with specific hash
algorithms.
<https://github.com/RustCrypto/SSH/issues/436>
<https://github.com/RustCrypto/SSH/commit/3b41fd934ce2bed02a234845c28dbc14ff5a6e4a>

The rsa crate had a bug where the PKCS#1 v1.5 DigestInfo prefix was
omitted when using the `try_from` or `try_into` methods for signing, leading to invalid signatures.
<https://github.com/RustCrypto/RSA/issues/341>
<https://github.com/RustCrypto/RSA/commit/a9fcf2275ba1afbf43cdd418059aa6b944c7dd97+>
*/

use anyhow::{Context, anyhow};
use rsa::sha2::{Sha256, Sha512};
use rsa::signature::{SignatureEncoding, Signer};
use ssh_agent_lib::proto::signature;
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, Mpint, Signature};

/// Sign `data` with `privkey`. `flags` are the agent sign request's flags,
/// which select the hash for an RSA key and are ignored for other key types.
pub fn sign_with_flags(
    privkey: &KeypairData,
    data: &[u8],
    flags: u32,
) -> anyhow::Result<Signature> {
    let algorithm = privkey
        .algorithm()
        .map_err(|e| anyhow!("Failed to get key algorithm: {e}"))?;
    if matches!(algorithm, Algorithm::Rsa { .. }) {
        return sign_rsa(privkey, data, flags);
    }
    privkey
        .try_sign(data)
        .map_err(|e| anyhow!("Failed to sign data with private key: {e}"))
}

fn biguint(mpint: &Mpint) -> anyhow::Result<rsa::BigUint> {
    rsa::BigUint::try_from(mpint).map_err(|e| anyhow!("Invalid RSA key component: {e}"))
}

/// Sign data with an RSA key using the hash algorithm specified by flags.
pub fn sign_rsa(privkey: &KeypairData, data: &[u8], flags: u32) -> anyhow::Result<Signature> {
    let rsa_keypair = privkey.rsa().context("Not an RSA key")?;

    // Convert an ssh_key RsaKeypair to an rsa::RsaPrivateKey.
    // https://github.com/RustCrypto/SSH/issues/436
    let rsa_private_key = rsa::RsaPrivateKey::from_components(
        biguint(&rsa_keypair.public.n)?,
        biguint(&rsa_keypair.public.e)?,
        biguint(&rsa_keypair.private.d)?,
        vec![
            biguint(&rsa_keypair.private.p)?,
            biguint(&rsa_keypair.private.q)?,
        ],
    )
    .context("Failed to construct RSA private key")?;

    // Do not use SigningKey try_from/into as that calls new_unprefixed() which
    // produces invalid signatures.
    // https://github.com/RustCrypto/RSA/issues/341
    // note: rsa-sha2-256 is default (ssh-rsa aka sha1 not supported)
    let (hash, signed_data) = match flags {
        signature::RSA_SHA2_512 => rsa::pkcs1v15::SigningKey::<Sha512>::new(rsa_private_key)
            .try_sign(data)
            .map(|signed| (Some(HashAlg::Sha512), signed)),

        _ => rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_private_key)
            .try_sign(data)
            .map(|signed| (Some(HashAlg::Sha256), signed)),
    }
    .context("RSA signing failed")?;

    Signature::new(Algorithm::Rsa { hash }, signed_data.to_vec())
        .context("Failed to create SSH signature from RSA")
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
    use rsa::signature::Verifier;
    use ssh_key::PrivateKey;

    use super::*;

    const DATA: &[u8] = b"test data to sign";

    fn fixture(data: &str) -> PrivateKey {
        PrivateKey::from_bytes(&b64.decode(data.trim()).unwrap()).unwrap()
    }

    fn rsa_key() -> PrivateKey {
        fixture(include_str!(
            "../../../cli/src/cli/commands/ssh_agent/fixtures/b64_rsa"
        ))
    }

    #[test]
    fn rsa_defaults_to_sha256() {
        let key = rsa_key();
        let sig = sign_with_flags(key.key_data(), DATA, 0).unwrap();
        assert_eq!(
            sig.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            }
        );
        key.public_key().key_data().verify(DATA, &sig).unwrap();
    }

    #[test]
    fn rsa_sha512_flag() {
        let key = rsa_key();
        let sig = sign_with_flags(key.key_data(), DATA, signature::RSA_SHA2_512).unwrap();
        assert_eq!(
            sig.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            }
        );
        key.public_key().key_data().verify(DATA, &sig).unwrap();
    }

    #[test]
    fn ed25519_ignores_flags() {
        let key = fixture(include_str!(
            "../../../cli/src/cli/commands/ssh_agent/fixtures/b64_ed25519"
        ));
        let sig = sign_with_flags(key.key_data(), DATA, signature::RSA_SHA2_512).unwrap();
        assert_eq!(sig.algorithm(), Algorithm::Ed25519);
        key.public_key().key_data().verify(DATA, &sig).unwrap();
    }
}
