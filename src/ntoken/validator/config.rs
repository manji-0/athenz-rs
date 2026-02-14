use std::time::Duration;

#[derive(Debug, Clone)]
pub struct NTokenValidatorConfig {
    pub zts_base_url: String,
    pub public_key_fetch_timeout: Duration,
    pub cache_ttl: Duration,
    pub max_cache_entries: usize,
    /// Optional auth header `(name, value)` sent when fetching ZTS public keys.
    pub public_key_fetch_auth_header: Option<(String, String)>,
    pub sys_auth_domain: String,
    pub zms_service: String,
    pub zts_service: String,
}

impl Default for NTokenValidatorConfig {
    fn default() -> Self {
        Self {
            zts_base_url: "https://localhost:4443/zts/v1".to_string(),
            public_key_fetch_timeout: Duration::from_secs(5),
            cache_ttl: Duration::from_secs(600),
            max_cache_entries: 1024,
            public_key_fetch_auth_header: None,
            sys_auth_domain: "sys.auth".to_string(),
            zms_service: "zms".to_string(),
            zts_service: "zts".to_string(),
        }
    }
}
