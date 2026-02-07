use athenz_provider_tenant::{PolicyClient, PolicyDecision, PolicyStore, ZtsClient};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let zts_url = env::var("ATHENZ_ZTS_URL").unwrap_or_else(|_| {
        "https://zts.example.com/zts/v1".to_string()
    });
    let domain = match env::var("ATHENZ_POLICY_DOMAIN") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("ATHENZ_POLICY_DOMAIN is not set. Skipping.");
            eprintln!("Example: ATHENZ_POLICY_DOMAIN=sports");
            return Ok(());
        }
    };

    let zts = ZtsClient::builder(&zts_url)?.build()?;
    let client = PolicyClient::new(zts);

    let response = client.fetch_signed_policy_data(&domain, None)?;
    if let Some(signed) = response.data {
        let policy_data = client.validate_signed_policy_data(&signed)?;
        let mut store = PolicyStore::new();
        store.insert(policy_data);

        let roles = vec![format!("{}:role.reader", domain)];
        let result = store.allow_action(&domain, &roles, "read", &format!("{}:resource.read", domain));
        if result.decision == PolicyDecision::Allow {
            println!("allowed");
        } else {
            println!("denied: {:?}", result.decision);
        }
    }

    Ok(())
}
