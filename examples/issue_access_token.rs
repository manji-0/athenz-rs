use athenz_provider_tenant::{AccessTokenRequest, ZtsClient};
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let zts_url = env::var("ATHENZ_ZTS_URL").unwrap_or_else(|_| {
        "https://zts.example.com/zts/v1".to_string()
    });
    let cert_path = match env::var("ATHENZ_CLIENT_CERT_PEM") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("ATHENZ_CLIENT_CERT_PEM is not set. Skipping.");
            eprintln!("Example: ATHENZ_CLIENT_CERT_PEM=/path/client-cert.pem");
            return Ok(());
        }
    };
    let key_path = match env::var("ATHENZ_CLIENT_KEY_PEM") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("ATHENZ_CLIENT_KEY_PEM is not set. Skipping.");
            eprintln!("Example: ATHENZ_CLIENT_KEY_PEM=/path/client-key.pem");
            return Ok(());
        }
    };

    let cert_pem = fs::read(cert_path)?;
    let key_pem = fs::read(key_path)?;

    let client = ZtsClient::builder(&zts_url)?
        .mtls_identity_from_parts(&cert_pem, &key_pem)?
        .build()?;

    let request = AccessTokenRequest::builder("sports")
        .roles(["reader"])
        .build();
    let token = client.issue_access_token(&request)?;

    println!("{}", token.access_token);
    Ok(())
}
