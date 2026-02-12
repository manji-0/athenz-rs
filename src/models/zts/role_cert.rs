use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleCertificate {
    #[serde(alias = "x509_certificate")]
    pub x509_certificate: String,
}

#[cfg(test)]
mod tests {
    use super::RoleCertificate;

    #[test]
    fn role_certificate_accepts_camel_case_key() {
        let input = serde_json::json!({ "x509Certificate": "cert" });
        let parsed: RoleCertificate = serde_json::from_value(input)
            .expect("RoleCertificate: deserialize from camelCase x509Certificate");
        assert_eq!(parsed.x509_certificate, "cert");
    }

    #[test]
    fn role_certificate_accepts_snake_case_key() {
        let input = serde_json::json!({ "x509_certificate": "cert" });
        let parsed: RoleCertificate = serde_json::from_value(input)
            .expect("RoleCertificate: deserialize from snake_case x509_certificate");
        assert_eq!(parsed.x509_certificate, "cert");
    }

    #[test]
    fn role_certificate_serializes_camelcase_key() {
        let value = serde_json::to_value(RoleCertificate {
            x509_certificate: "cert".to_string(),
        })
        .expect("RoleCertificate: serialize to JSON");
        assert_eq!(
            value.get("x509Certificate"),
            Some(&serde_json::json!("cert"))
        );
        assert!(value.get("x509_certificate").is_none());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleCertificateRequest {
    pub csr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_for_principal: Option<String>,
    pub expiry_time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_cert_not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_cert_not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_cert_signer_key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RoleAccess {
    pub roles: Vec<String>,
}
