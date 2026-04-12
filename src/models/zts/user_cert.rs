use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserCertificate {
    #[serde(alias = "x509_certificate")]
    pub x509_certificate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserCertificateRequest {
    pub name: String,
    pub csr: String,
    pub attestation_data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_cert_signer_key_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::UserCertificate;

    #[test]
    fn user_certificate_accepts_camel_case_key() {
        let input = serde_json::json!({ "x509Certificate": "cert" });
        let parsed: UserCertificate = serde_json::from_value(input)
            .expect("UserCertificate: deserialize from camelCase x509Certificate");
        assert_eq!(parsed.x509_certificate, "cert");
    }

    #[test]
    fn user_certificate_accepts_snake_case_key() {
        let input = serde_json::json!({ "x509_certificate": "cert" });
        let parsed: UserCertificate = serde_json::from_value(input)
            .expect("UserCertificate: deserialize from snake_case x509_certificate");
        assert_eq!(parsed.x509_certificate, "cert");
    }
}
