use crate::error::Error;
use crate::models::PublicKeyEntry;
use crate::ybase64::decode as ybase64_decode;
use crate::zts::ZtsClient;
#[cfg(feature = "async-validate")]
use crate::zts_async::ZtsAsyncClient;

pub(in crate::policy::validator) fn get_public_key_pem(
    zts: &ZtsClient,
    domain: &str,
    service: &str,
    key_id: &str,
) -> Result<Vec<u8>, Error> {
    let entry: PublicKeyEntry = zts.get_public_key_entry(domain, service, key_id)?;
    ybase64_decode(&entry.key)
}

#[cfg(feature = "async-validate")]
pub(in crate::policy::validator) async fn get_public_key_pem_async(
    zts: &ZtsAsyncClient,
    domain: &str,
    service: &str,
    key_id: &str,
) -> Result<Vec<u8>, Error> {
    let entry: PublicKeyEntry = zts.get_public_key_entry(domain, service, key_id).await?;
    ybase64_decode(&entry.key)
}
