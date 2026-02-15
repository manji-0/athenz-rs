use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::UserAuthorityAttributeMap;

impl ZmsAsyncClient {
    /// Retrieves user authority attribute values by type.
    pub async fn get_user_authority_attributes(&self) -> Result<UserAuthorityAttributeMap, Error> {
        let url = self.build_url(&["authority", "user", "attribute"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }
}
