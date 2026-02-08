use super::ZtsClient;
use crate::error::Error;
use crate::models::{
    CertificateAuthorityBundle, RoleAccess, RoleCertificate, RoleCertificateRequest,
    SSHCertRequest, SSHCertificates,
};
use crate::zts::common;
use reqwest::StatusCode;

impl ZtsClient {
    pub fn get_ca_cert_bundle(&self, name: &str) -> Result<CertificateAuthorityBundle, Error> {
        let url = self.build_url(&["cacerts", name])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn post_ssh_cert(&self, request: &SSHCertRequest) -> Result<SSHCertificates, Error> {
        let url = self.build_url(&["sshcert"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        match resp.status() {
            StatusCode::CREATED => resp.json::<SSHCertificates>().map_err(Error::from),
            _ => self.parse_error(resp),
        }
    }
    pub fn post_role_certificate(
        &self,
        request: &RoleCertificateRequest,
    ) -> Result<RoleCertificate, Error> {
        let url = self.build_url(&["rolecert"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_roles_require_role_cert(
        &self,
        principal: Option<&str>,
    ) -> Result<RoleAccess, Error> {
        let url = self.build_url(&["role", "cert"])?;
        let mut req = self.http.get(url);
        let mut params = Vec::new();
        if let Some(principal) = principal {
            params.push(("principal", principal.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }
}
