# Policy Validation and Evaluation

This guide covers fetching signed policy data and evaluating access locally.

## Fetch + validate policy data

Use `PolicyClient` to fetch signed policy data and validate signatures.

```rust
use athenz_rs::{PolicyClient, SignedPolicyRequest, ZtsClient};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let zts = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .build()?;
let client = PolicyClient::new(zts);

let response = client.fetch_signed_policy_data("sports", None)?;
if let Some(signed) = response.data {
    let policy_data = client.validate_signed_policy_data(&signed)?;
    println!("domain: {}", policy_data.domain);
}
# Ok(())
# }
```

JWS policy data can be fetched with `fetch_jws_policy_data` + `validate_jws_policy_data`.

## Evaluate access with PolicyStore

```rust
use athenz_rs::{PolicyClient, PolicyDecision, PolicyStore, ZtsClient};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let zts = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .build()?;
let client = PolicyClient::new(zts);

let response = client.fetch_signed_policy_data("sports", None)?;
if let Some(signed) = response.data {
    let policy_data = client.validate_signed_policy_data(&signed)?;
    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["sports:role.reader".to_string()];
    let result = store.allow_action("sports", &roles, "read", "sports:resource.read");
    if result.decision == PolicyDecision::Allow {
        println!("allowed");
    }
}
# Ok(())
# }
```

## Behavior notes

- `allow_action` lowercases `action` and `resource` before matching.
- `PolicyStore` does not apply `case_sensitive` flags during matching.
- `PolicyStore` does not evaluate assertion `conditions` during matching.
- Deny assertions are evaluated before allow assertions.
