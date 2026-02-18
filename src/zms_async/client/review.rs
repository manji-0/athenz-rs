use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::ReviewObjects;
use crate::zms::common;

impl ZmsAsyncClient {
    /// Lists roles that require periodic review.
    pub async fn get_roles_for_review(
        &self,
        principal: Option<&str>,
    ) -> Result<ReviewObjects, Error> {
        let url = self.build_url(&["review", "role"])?;
        let mut req = self.http.get(url);
        let mut query = Vec::new();
        if let Some(principal) = principal {
            query.push(("principal", principal.to_string()));
        }
        req = common::apply_query_params(req, query);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists groups that require periodic review.
    pub async fn get_groups_for_review(
        &self,
        principal: Option<&str>,
    ) -> Result<ReviewObjects, Error> {
        let url = self.build_url(&["review", "group"])?;
        let mut req = self.http.get(url);
        let mut query = Vec::new();
        if let Some(principal) = principal {
            query.push(("principal", principal.to_string()));
        }
        req = common::apply_query_params(req, query);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }
}
