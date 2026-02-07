use athenz_rs::{IdTokenRequest, NTokenSigner, ZtsClient};
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let zts_url =
        env::var("ATHENZ_ZTS_URL").unwrap_or_else(|_| "https://zts.example.com/zts/v1".to_string());
    let key_path = match env::var("ATHENZ_NTOKEN_PRIVATE_KEY_PEM") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("ATHENZ_NTOKEN_PRIVATE_KEY_PEM is not set. Skipping.");
            eprintln!("Example: ATHENZ_NTOKEN_PRIVATE_KEY_PEM=/path/ntoken-key.pem");
            return Ok(());
        }
    };

    let domain = env::var("ATHENZ_DOMAIN").unwrap_or_else(|_| "sports".to_string());
    let service = env::var("ATHENZ_SERVICE").unwrap_or_else(|_| "api".to_string());
    let key_version = env::var("ATHENZ_KEY_VERSION").unwrap_or_else(|_| "v1".to_string());

    let private_key_pem = fs::read(key_path)?;
    let signer = NTokenSigner::new(&domain, &service, &key_version, &private_key_pem)?;

    let client = ZtsClient::builder(&zts_url)?
        .ntoken_signer("Athenz-Principal-Auth", signer)
        .build()?;

    let mut request = IdTokenRequest::new(
        format!("{}.{}", domain, service),
        "https://example.com/callback",
        "openid",
        "nonce-123",
    );
    request.output = Some("json".to_string());

    let response = client.issue_id_token(&request)?;
    if let Some(body) = response.response {
        println!("{}", body.id_token);
    } else if let Some(location) = response.location {
        println!("redirect: {}", location);
    }

    Ok(())
}
