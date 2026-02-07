use athenz_rs::{JwksProvider, JwtValidator};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = match env::var("ATHENZ_JWT") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("ATHENZ_JWT is not set. Skipping.");
            eprintln!("Example: ATHENZ_JWT=eyJhbGciOi... cargo run --example validate_jwt");
            return Ok(());
        }
    };
    let jwks_url = env::var("ATHENZ_JWKS_URL")
        .unwrap_or_else(|_| "https://zts.example.com/zts/v1/oauth2/keys".to_string());

    let jwks = JwksProvider::new(&jwks_url)?;
    let validator = JwtValidator::new(jwks);
    let data = validator.validate_access_token(&token)?;

    println!("claims: {}", data.claims);
    Ok(())
}
