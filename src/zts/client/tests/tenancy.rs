use crate::zts::ZtsClient;

use super::helpers::{serve_once, CapturedRequest};

#[test]
fn get_tenant_domains_uses_expected_path_and_query() {
    let body = r#"{"tenantDomainNames":["sports.tenant","media.tenant"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let domains = client
        .get_tenant_domains("sports", "user.jane", Some("reader"), Some("storage"))
        .expect("tenant domains");
    assert_eq!(
        domains.tenant_domain_names,
        vec!["sports.tenant", "media.tenant"]
    );

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/providerdomain/sports/user/user.jane?roleName=reader&serviceName=storage"
    );

    handle.join().expect("server");
}

#[test]
fn get_tenant_domains_with_role_name_only_sets_role_name_query_param() {
    let body = r#"{"tenantDomainNames":["sports.tenant"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let domains = client
        .get_tenant_domains("sports", "user.jane", Some("reader"), None)
        .expect("tenant domains");
    assert_eq!(domains.tenant_domain_names, vec!["sports.tenant"]);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/providerdomain/sports/user/user.jane?roleName=reader"
    );

    handle.join().expect("server");
}

#[test]
fn get_tenant_domains_with_service_name_only_sets_service_name_query_param() {
    let body = r#"{"tenantDomainNames":["sports.tenant"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let domains = client
        .get_tenant_domains("sports", "user.jane", None, Some("storage"))
        .expect("tenant domains");
    assert_eq!(domains.tenant_domain_names, vec!["sports.tenant"]);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/providerdomain/sports/user/user.jane?serviceName=storage"
    );

    handle.join().expect("server");
}

#[test]
fn get_tenant_domains_without_optional_filters_omits_query_params() {
    let body = r#"{"tenantDomainNames":["sports.tenant"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let domains = client
        .get_tenant_domains("sports", "user.jane", None, None)
        .expect("tenant domains");
    assert_eq!(domains.tenant_domain_names, vec!["sports.tenant"]);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/providerdomain/sports/user/user.jane");

    handle.join().expect("server");
}

#[test]
fn get_tenant_domains_applies_auth_header() {
    let body = r#"{"tenantDomainNames":["sports.tenant"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");

    client
        .get_tenant_domains("sports", "user.jane", None, None)
        .expect("tenant domains");

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );
    assert_eq!(req.path, "/zts/v1/providerdomain/sports/user/user.jane");

    handle.join().expect("server");
}
