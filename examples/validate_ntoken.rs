use athenz_rs::NTokenValidator;
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = match env::var("ATHENZ_NTOKEN") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("ATHENZ_NTOKEN is not set. Skipping.");
            eprintln!(
                "Example: ATHENZ_NTOKEN='v=S1;d=...;s=...' cargo run --example validate_ntoken"
            );
            return Ok(());
        }
    };
    let key_path = match env::var("ATHENZ_NTOKEN_PUBLIC_KEY_PEM") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("ATHENZ_NTOKEN_PUBLIC_KEY_PEM is not set. Skipping.");
            eprintln!("Example: ATHENZ_NTOKEN_PUBLIC_KEY_PEM=/path/public.pem");
            return Ok(());
        }
    };

    let public_key_pem = fs::read(key_path)?;
    let validator = NTokenValidator::new_with_public_key(&public_key_pem)?;
    let claims = validator.validate(&token)?;

    println!("principal: {}", claims.principal_name());
    Ok(())
}
