use crate::zts::AccessTokenRequest;
use url::form_urlencoded;

use super::helpers::scope_from_form;

fn grant_type_from_form(form: &str) -> String {
    form_urlencoded::parse(form.as_bytes())
        .find(|(key, _)| key == "grant_type")
        .map(|(_, value)| value.to_string())
        .unwrap_or_default()
}

#[test]
fn access_token_scope_domain_only() {
    let req = AccessTokenRequest::new("sports", Vec::new());
    let form = req.to_form();
    assert_eq!(grant_type_from_form(&form), "client_credentials");
    assert!(form.contains("scope=sports%3Adomain"));
}

#[test]
fn access_token_scope_wildcard_role() {
    let req = AccessTokenRequest::new("sports", vec!["*".to_string()]);
    let form = req.to_form();
    let scope = scope_from_form(&form);
    assert_eq!(scope, "sports:role.*");
    assert!(form.contains("scope=sports%3Arole.*") || form.contains("scope=sports%3Arole.%2A"));
}

#[test]
fn access_token_scope_roles() {
    let req = AccessTokenRequest::new("sports", vec!["reader".to_string(), "writer".to_string()]);
    let form = req.to_form();
    let scope = scope_from_form(&form);
    assert_eq!(scope, "sports:role.reader sports:role.writer");
}

#[test]
fn access_token_form_includes_optional_fields() {
    let mut req = AccessTokenRequest::new("sports", vec!["reader".to_string()]);
    req.proxy_for_principal = Some("user.test".to_string());
    req.authorization_details = Some("{\"type\":\"test\"}".to_string());
    req.openid_issuer = Some(true);
    let form = req.to_form();
    assert!(form.contains("proxy_for_principal=user.test"));
    assert!(form.contains("authorization_details=%7B%22type%22%3A%22test%22%7D"));
    assert!(form.contains("openid_issuer=true"));
}

#[test]
fn access_token_scope_includes_id_token_service() {
    let mut req = AccessTokenRequest::new("sports", vec!["reader".to_string()]);
    req.id_token_service = Some("api".to_string());
    let form = req.to_form();
    let scope = scope_from_form(&form);
    assert_eq!(scope, "sports:role.reader openid sports:service.api");
    assert!(form.contains("scope=sports%3Arole.reader+openid+sports%3Aservice.api"));
}

#[test]
fn access_token_raw_scope_overrides_composed_scope() {
    let mut req = AccessTokenRequest::new("sports", vec!["reader".to_string()]);
    req.id_token_service = Some("api".to_string());
    req.raw_scope = Some("custom:scope".to_string());
    let form = req.to_form();
    let scope = scope_from_form(&form);
    assert_eq!(scope, "custom:scope");
    assert!(form.contains("scope=custom%3Ascope"));
}

#[test]
fn access_token_builder_sets_raw_scope() {
    let req = AccessTokenRequest::builder("sports")
        .roles(vec!["reader".to_string()])
        .id_token_service("api")
        .raw_scope("custom:scope")
        .build();
    let form = req.to_form();
    let scope = scope_from_form(&form);
    assert_eq!(scope, "custom:scope");
}

#[test]
fn access_token_custom_grant_type_overrides_default() {
    let mut req = AccessTokenRequest::new("sports", vec!["reader".to_string()]);
    req.grant_type = Some("token-exchange".to_string());
    let form = req.to_form();
    assert_eq!(grant_type_from_form(&form), "token-exchange");
}

#[test]
fn access_token_builder_sets_grant_type() {
    let req = AccessTokenRequest::builder("sports")
        .roles(vec!["reader".to_string()])
        .grant_type("jwt-bearer")
        .build();
    let form = req.to_form();
    assert_eq!(grant_type_from_form(&form), "jwt-bearer");
}

#[test]
fn access_token_infers_token_exchange_grant_type() {
    let req = AccessTokenRequest::builder("sports")
        .roles(vec!["reader".to_string()])
        .subject_token("subject-token")
        .subject_token_type("urn:ietf:params:oauth:token-type:access_token")
        .build();
    let form = req.to_form();
    assert_eq!(
        grant_type_from_form(&form),
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );
}

#[test]
fn access_token_infers_jwt_bearer_grant_type() {
    let req = AccessTokenRequest::builder("sports")
        .roles(vec!["reader".to_string()])
        .assertion("jwt-assertion")
        .build();
    let form = req.to_form();
    assert_eq!(
        grant_type_from_form(&form),
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
}

#[test]
fn access_token_explicit_grant_type_overrides_inferred_grant_type() {
    let req = AccessTokenRequest::builder("sports")
        .roles(vec!["reader".to_string()])
        .subject_token("subject-token")
        .grant_type("custom-grant")
        .build();
    let form = req.to_form();
    assert_eq!(grant_type_from_form(&form), "custom-grant");
}
