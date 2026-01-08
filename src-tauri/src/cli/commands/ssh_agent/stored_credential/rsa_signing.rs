/*!
This module provides RSA signing functionality to backport some fixes:

The ssh_key crate doesn't properly handle RSA signing with specific hash
algorithms.
<https://github.com/RustCrypto/SSH/issues/436>
<https://github.com/RustCrypto/SSH/commit/3b41fd934ce2bed02a234845c28dbc14ff5a6e4a>

The rsa crate had a bug where the PKCS#1 v1.5 DigestInfo prefix was
omitted when using the `try_from` or `try_into` methods for signing, leading to invalid signatures.
<https://github.com/RustCrypto/RSA/issues/341>
<https://github.com/RustCrypto/RSA/commit/a9fcf2275ba1afbf43cdd418059aa6b944c7dd97+>
*/

use rsa::sha2::{Sha256, Sha512};
use rsa::signature::{SignatureEncoding, Signer};
use ssh_agent_lib::proto::signature;
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, Signature};

use crate::cli::commands::ssh_agent::credential::CredentialError;

/// Sign data with an RSA key using the hash algorithm specified by flags.

pub fn sign_rsa(
    privkey: &KeypairData,
    data: &[u8],
    flags: u32,
) -> Result<Signature, CredentialError> {
    let Some(rsa_keypair) = privkey.rsa() else {
        log::error!("Not an RSA key");
        return Err(CredentialError::SigningFailed);
    };

    // Convert an ssh_key RsaKeypair to an rsa::RsaPrivateKey.
    // https://github.com/RustCrypto/SSH/issues/436
    let rsa_private_key = rsa::RsaPrivateKey::from_components(
        rsa::BigUint::try_from(&rsa_keypair.public.n).unwrap(),
        rsa::BigUint::try_from(&rsa_keypair.public.e).unwrap(),
        rsa::BigUint::try_from(&rsa_keypair.private.d).unwrap(),
        vec![
            rsa::BigUint::try_from(&rsa_keypair.private.p).unwrap(),
            rsa::BigUint::try_from(&rsa_keypair.private.q).unwrap(),
        ],
    )
    .map_err(|e| {
        log::error!("Failed to construct RSA private key: {e}");
        CredentialError::SigningFailed
    })?;

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
    .map_err(|e| {
        log::error!("RSA signing failed: {e}");
        CredentialError::SigningFailed
    })?;

    Signature::new(Algorithm::Rsa { hash }, signed_data.to_vec()).map_err(|e| {
        log::error!("Failed to create SSH signature from RSA: {e}");
        CredentialError::SigningFailed
    })
}
