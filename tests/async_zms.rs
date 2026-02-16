#![cfg(feature = "async-client")]

use athenz_rs::{DomainListOptions, NTokenSigner, PrincipalState, ZmsAsyncClient};
use rand::thread_rng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::RsaPrivateKey;
use std::sync::OnceLock;
use tokio::time::{timeout, Duration};

mod common;
use common::{empty_response, json_response, serve_once};

#[tokio::test]
async fn get_domain_list_sets_query_and_modified_since() {
    let body = r#"{"names":["a","b"]}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let mut options = DomainListOptions::default();
    options.limit = Some(5);
    options.prefix = Some("core".to_string());
    options.modified_since = Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string());

    let list = client
        .get_domain_list(&options)
        .await
        .expect("request")
        .expect("list");
    assert_eq!(list.names, vec!["a".to_string(), "b".to_string()]);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain");
    assert_eq!(
        req.header_value("If-Modified-Since"),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    assert_eq!(req.query_value("limit"), Some("5"));
    assert_eq!(req.query_value("prefix"), Some("core"));
}

#[tokio::test]
async fn get_domain_list_returns_none_on_not_modified() {
    let response = empty_response("304 Not Modified");
    let (base_url, _rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let options = DomainListOptions::default();
    let list = client.get_domain_list(&options).await.expect("request");
    assert!(list.is_none());
}

#[tokio::test]
async fn get_info_calls_sys_info_endpoint() {
    let body = r#"{"buildJdkSpec":"17","implementationTitle":"zms"}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let info = client.get_info().await.expect("info");
    assert_eq!(info.build_jdk_spec.as_deref(), Some("17"));
    assert_eq!(info.implementation_title.as_deref(), Some("zms"));

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/sys/info");
}

#[tokio::test]
async fn get_status_calls_status_endpoint() {
    let body = r#"{"code":200,"message":"ok"}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let status = client.get_status().await.expect("status");
    assert_eq!(status.code, 200);
    assert_eq!(status.message, "ok");

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/status");
}

#[tokio::test]
async fn get_schema_calls_schema_endpoint() {
    let body = r#"{"name":"zms","types":[]}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let schema = client.get_schema().await.expect("schema");
    assert_eq!(schema.0.get("name").and_then(|v| v.as_str()), Some("zms"));

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/schema");
}

#[tokio::test]
async fn get_user_authority_attributes_calls_endpoint() {
    let body = r#"{"attributes":{"employeeType":{"values":["full_time"]}}}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let attributes = client
        .get_user_authority_attributes()
        .await
        .expect("authority attributes");
    let employee_type = attributes
        .attributes
        .get("employeeType")
        .expect("employeeType attribute");
    assert_eq!(employee_type.values, vec!["full_time".to_string()]);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/authority/user/attribute");
}

#[tokio::test]
async fn get_domain_stats_calls_domain_stats_endpoint() {
    let body = r#"{"name":"sports","subdomain":1,"role":2,"roleMember":3,"policy":4,"assertion":5,"entity":6,"service":7,"serviceHost":8,"publicKey":9,"group":10,"groupMember":11}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let stats = client
        .get_domain_stats("sports")
        .await
        .expect("domain stats");
    assert_eq!(stats.name.as_deref(), Some("sports"));
    assert_eq!(stats.subdomain, 1);
    assert_eq!(stats.group_member, 11);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/stats");
}

#[tokio::test]
async fn get_domain_data_check_calls_domain_check_endpoint() {
    let body = r#"{"danglingRoles":["sports:role.admin"],"danglingPolicies":[{"policyName":"sports:policy.readers","roleName":"sports:role.readers"}],"policyCount":4,"assertionCount":9,"roleWildCardCount":2,"providersWithoutTrust":["sports.provider"],"tenantsWithoutAssumeRole":["sports.tenant"]}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let check = client
        .get_domain_data_check("sports")
        .await
        .expect("domain data check");
    assert_eq!(
        check.dangling_roles,
        Some(vec!["sports:role.admin".to_string()])
    );
    let dangling_policy = check
        .dangling_policies
        .as_ref()
        .and_then(|policies| policies.first())
        .expect("dangling policy");
    assert_eq!(dangling_policy.policy_name, "sports:policy.readers");
    assert_eq!(dangling_policy.role_name, "sports:role.readers");
    assert_eq!(check.policy_count, 4);
    assert_eq!(check.assertion_count, 9);
    assert_eq!(check.role_wild_card_count, 2);
    assert_eq!(
        check.providers_without_trust,
        Some(vec!["sports.provider".to_string()])
    );
    assert_eq!(
        check.tenants_without_assume_role,
        Some(vec!["sports.tenant".to_string()])
    );

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/check");
}

#[tokio::test]
async fn put_principal_state_calls_principal_state_endpoint() {
    let response = empty_response("204 No Content");
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let principal_state = PrincipalState { suspended: true };
    client
        .put_principal_state(
            "sports.api",
            &principal_state,
            Some("disable compromised principal"),
        )
        .await
        .expect("put principal state");

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/principal/sports.api/state");
    assert_eq!(
        req.header_value("Y-Audit-Ref"),
        Some("disable compromised principal")
    );
    assert_eq!(req.body, br#"{"suspended":true}"#);
}

#[tokio::test]
async fn get_user_token_calls_user_token_endpoint() {
    let body = r#"{"token":"signed-user-token","header":"Athenz-Principal-Auth"}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let user_token = client
        .get_user_token("jane", Some("sports.api,media.api"), Some(true))
        .await
        .expect("user token");
    assert_eq!(user_token.token, "signed-user-token");
    assert_eq!(user_token.header.as_deref(), Some("Athenz-Principal-Auth"));

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/user/jane/token");
    assert_eq!(req.query_value("services"), Some("sports.api,media.api"));
    assert_eq!(req.query_value("header"), Some("true"));
}

#[tokio::test]
async fn options_user_token_calls_user_token_options_endpoint() {
    let response = empty_response("200 OK");
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .options_user_token("jane", Some("sports.api"))
        .await
        .expect("options user token");

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "OPTIONS");
    assert_eq!(req.path, "/zms/v1/user/jane/token");
    assert_eq!(req.query_value("services"), Some("sports.api"));
}

#[tokio::test]
async fn options_user_token_accepts_no_content_response() {
    let response = empty_response("204 No Content");
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .options_user_token("jane", Some("sports.api"))
        .await
        .expect("options user token");

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "OPTIONS");
    assert_eq!(req.path, "/zms/v1/user/jane/token");
    assert_eq!(req.query_value("services"), Some("sports.api"));
}

#[tokio::test]
async fn options_user_token_applies_auth_header() {
    let response = empty_response("200 OK");
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .expect("auth")
        .follow_redirects(false)
        .build()
        .expect("build");

    client
        .options_user_token("jane", Some("sports.api"))
        .await
        .expect("options user token");

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "OPTIONS");
    assert_eq!(req.path, "/zms/v1/user/jane/token");
    assert_eq!(req.query_value("services"), Some("sports.api"));
    assert_eq!(req.header_value("Athenz-Principal-Auth"), Some("token"));
}

#[tokio::test]
async fn get_service_principal_calls_principal_endpoint() {
    let body = r#"{"domain":"sports","service":"api","token":"signed-service-token"}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let principal = client
        .get_service_principal()
        .await
        .expect("service principal");
    assert_eq!(principal.domain, "sports");
    assert_eq!(principal.service, "api");
    assert_eq!(principal.token, "signed-service-token");

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/principal");
}

#[tokio::test]
async fn get_system_stats_calls_system_stats_endpoint() {
    let body = r#"{"subdomain":1,"role":2,"roleMember":3,"policy":4,"assertion":5,"entity":6,"service":7,"serviceHost":8,"publicKey":9,"group":10,"groupMember":11}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let stats = client.get_system_stats().await.expect("system stats");
    assert_eq!(stats.name, None);
    assert_eq!(stats.policy, 4);
    assert_eq!(stats.public_key, 9);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/sys/stats");
}

#[tokio::test]
async fn get_domain_list_applies_auth_header() {
    let body = r#"{"names":["a"]}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .expect("auth")
        .follow_redirects(false)
        .build()
        .expect("build");

    let options = DomainListOptions::default();
    let list = client
        .get_domain_list(&options)
        .await
        .expect("request")
        .expect("list");
    assert_eq!(list.names, vec!["a".to_string()]);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.header_value("Athenz-Principal-Auth"), Some("token"));
}

#[tokio::test]
async fn get_domain_list_applies_ntoken_signer_auth() {
    let body = r#"{"names":["a"]}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let signer = test_signer();
    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .ntoken_signer("Athenz-Principal-Auth", signer)
        .expect("auth")
        .follow_redirects(false)
        .build()
        .expect("build");

    let options = DomainListOptions::default();
    let list = client
        .get_domain_list(&options)
        .await
        .expect("request")
        .expect("list");
    assert_eq!(list.names, vec!["a".to_string()]);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    let header = req
        .header_value("Athenz-Principal-Auth")
        .expect("auth header");
    assert!(header.starts_with("v="));
}

#[tokio::test]
async fn get_domain_list_reports_status_on_empty_error_body() {
    let response = empty_response("500 Internal Server Error");
    let (base_url, _rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let options = DomainListOptions::default();
    let err = client.get_domain_list(&options).await.expect_err("error");
    let message = format!("{}", err);
    assert!(message.contains("500"));
}

fn test_signer() -> NTokenSigner {
    static TEST_RSA_PRIVATE_KEY: OnceLock<String> = OnceLock::new();
    let pem = TEST_RSA_PRIVATE_KEY.get_or_init(|| {
        let mut rng = thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("private key");
        key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("pem")
            .to_string()
    });
    NTokenSigner::new("sports", "api", "v1", pem.as_bytes()).expect("signer")
}
