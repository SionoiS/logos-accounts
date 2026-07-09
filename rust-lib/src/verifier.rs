//! Software Multikey verifier (no card I/O).

use crate::Error;
use bs_traits::asyncro::AsyncVerifier;
use bs_traits::sync::SyncVerifier;
use bs_traits::Verifier;
use multikey::{Multikey, Views};
use multisig::Multisig;
use std::marker::PhantomData;

/// Pure-software signature verifier using Multikey `verify_view()`.
///
/// Verification is product-critical for VLADs and p-log proofs but is not
/// required by `MultiSigner` for `open_plog` / `update_plog`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MultikeyVerifier<E = Error> {
    _phantom: PhantomData<E>,
}

impl<E> MultikeyVerifier<E> {
    /// Create a new verifier.
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<E> Verifier for MultikeyVerifier<E>
where
    E: From<multikey::Error> + From<Error> + std::fmt::Debug,
{
    type Key = Multikey;
    type Signature = Multisig;
    type Error = E;
}

impl<E> SyncVerifier for MultikeyVerifier<E>
where
    E: From<multikey::Error> + From<Error> + std::fmt::Debug,
{
    fn verify(
        &self,
        key: &Self::Key,
        data: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        key.verify_view()?.verify(signature, Some(data))?;
        Ok(())
    }
}

impl<E> AsyncVerifier for MultikeyVerifier<E>
where
    E: From<multikey::Error> + From<Error> + std::fmt::Debug + Send + Sync + 'static,
{
    fn verify<'a>(
        &'a self,
        key: &'a Self::Key,
        data: &'a [u8],
        signature: &'a Self::Signature,
    ) -> std::pin::Pin<
        Box<dyn bs_traits::asyncro::CondSendFuture<Result<bool, Self::Error>> + 'a>,
    > {
        Box::pin(async move {
            match SyncVerifier::verify(self, key, data, signature) {
                Ok(()) => Ok(true),
                Err(e) => Err(e),
            }
        })
    }
}

/// Verify `signature` over `data` with Multikey `key` (convenience free function).
pub fn verify_multikey(
    key: &Multikey,
    data: &[u8],
    signature: &Multisig,
) -> Result<(), Error> {
    SyncVerifier::verify(&MultikeyVerifier::<Error>::new(), key, data, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use multicodec::Codec;
    use multikey::Builder;
    use rand_core::OsRng;

    #[test]
    fn software_sign_verify_roundtrip() {
        let secret = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut OsRng)
            .unwrap()
            .try_build()
            .unwrap();
        let public = secret.conv_view().unwrap().to_public_key().unwrap();
        let data = b"verify roundtrip";
        let signature = secret
            .sign_view()
            .unwrap()
            .sign(data, false, None)
            .unwrap();

        verify_multikey(&public, data, &signature).expect("verify should succeed");

        let bad = verify_multikey(&public, b"tampered", &signature);
        assert!(bad.is_err());
    }
}
