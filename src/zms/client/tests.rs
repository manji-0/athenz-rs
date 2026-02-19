use crate::error::{Error, CONFIG_ERROR_REDIRECT_WITH_AUTH};
use crate::models::{
    DependentService, DomainMeta, Entity, GroupMeta, PolicyOptions, PrincipalState,
    ProviderResourceGroupRoles, Quota, ResourceDomainOwnership, ResourceGroupOwnership,
    ResourcePolicyOwnership, Tenancy, TenantResourceGroupRoles, TenantRoleAction,
};
use crate::zms::{DomainListOptions, SignedDomainsOptions, ZmsClient};
use serde_json::json;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

#[test]
fn get_domain_list_sets_query_and_modified_since() {
    let body = r#"{"names":["a","b"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let options = DomainListOptions {
        limit: Some(5),
        prefix: Some("core".to_string()),
        modified_since: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string()),
        ..Default::default()
    };

    let list = client
        .get_domain_list(&options)
        .expect("request")
        .expect("list");
    assert_eq!(list.names, vec!["a".to_string(), "b".to_string()]);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain");
    assert_eq!(
        req.headers.get("if-modified-since").map(String::as_str),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    assert_eq!(req.query.get("limit").map(String::as_str), Some("5"));
    assert_eq!(req.query.get("prefix").map(String::as_str), Some("core"));

    handle.join().expect("server");
}

#[test]
fn get_domain_list_returns_none_on_not_modified() {
    let response = "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, _rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let options = DomainListOptions::default();
    let list = client.get_domain_list(&options).expect("request");
    assert!(list.is_none());

    handle.join().expect("server");
}

#[test]
fn get_modified_domains_sets_query_and_etag() {
    let body = r#"{"domains":[{"domain":{"name":"sports","roles":[],"policies":{"contents":{"domain":"sports","policies":[]},"signature":"pol-sig","keyId":"0"},"services":[],"entities":[],"groups":[],"modified":"2026-02-01T00:00:00Z"},"signature":"dom-sig","keyId":"0"}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: etag-1\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let options = SignedDomainsOptions {
        domain: Some("sports".to_string()),
        meta_only: Some(true),
        meta_attr: Some("all".to_string()),
        master: Some(true),
        conditions: Some(true),
    };

    let response = client
        .get_modified_domains(&options, Some("etag-0"))
        .expect("request");
    assert_eq!(response.etag.as_deref(), Some("etag-1"));
    let domains = response.data.expect("domains");
    assert_eq!(domains.domains.len(), 1);
    assert_eq!(domains.domains[0].domain.name, "sports");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/sys/modified_domains");
    assert_eq!(req.query.get("domain").map(String::as_str), Some("sports"));
    assert_eq!(req.query.get("metaonly").map(String::as_str), Some("true"));
    assert_eq!(req.query.get("metaattr").map(String::as_str), Some("all"));
    assert_eq!(req.query.get("master").map(String::as_str), Some("true"));
    assert_eq!(
        req.query.get("conditions").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        req.headers.get("if-none-match").map(String::as_str),
        Some("etag-0")
    );

    handle.join().expect("server");
}

#[test]
fn get_modified_domains_returns_none_on_not_modified() {
    let response =
        "HTTP/1.1 304 Not Modified\r\nETag: etag-2\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let response = client
        .get_modified_domains(&SignedDomainsOptions::default(), Some("etag-2"))
        .expect("request");
    assert!(response.data.is_none());
    assert_eq!(response.etag.as_deref(), Some("etag-2"));

    let req = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("if-none-match").map(String::as_str),
        Some("etag-2")
    );

    handle.join().expect("server");
}

#[test]
fn get_signed_domain_sets_query_and_etag() {
    let body = r#"{"payload":"payload","protected":"protected","header":{"alg":"ES256","kid":"0"},"signature":"sig"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: etag-3\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let response = client
        .get_signed_domain("sports", Some(true), Some("etag-2"))
        .expect("request");
    assert_eq!(response.etag.as_deref(), Some("etag-3"));
    let data = response.data.expect("jws domain");
    assert_eq!(data.payload, "payload");
    assert_eq!(data.protected_header, "protected");
    assert_eq!(data.signature, "sig");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/signed");
    assert_eq!(
        req.query.get("signaturep1363format").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        req.headers.get("if-none-match").map(String::as_str),
        Some("etag-2")
    );

    handle.join().expect("server");
}

#[test]
fn get_signed_domain_returns_none_on_not_modified() {
    let response =
        "HTTP/1.1 304 Not Modified\r\nETag: etag-4\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let response = client
        .get_signed_domain("sports", None, Some("etag-4"))
        .expect("request");
    assert!(response.data.is_none());
    assert_eq!(response.etag.as_deref(), Some("etag-4"));

    let req = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("if-none-match").map(String::as_str),
        Some("etag-4")
    );

    handle.join().expect("server");
}

#[test]
fn get_info_calls_sys_info_endpoint() {
    let body = r#"{"buildJdkSpec":"17","implementationTitle":"zms"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let info = client.get_info().expect("info");
    assert_eq!(info.build_jdk_spec.as_deref(), Some("17"));
    assert_eq!(info.implementation_title.as_deref(), Some("zms"));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/sys/info");

    handle.join().expect("server");
}

#[test]
fn get_status_calls_status_endpoint() {
    let body = r#"{"code":200,"message":"ok"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let status = client.get_status().expect("status");
    assert_eq!(status.code, 200);
    assert_eq!(status.message, "ok");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/status");

    handle.join().expect("server");
}

#[test]
fn get_schema_calls_schema_endpoint() {
    let body = r#"{"name":"zms","types":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let schema = client.get_schema().expect("schema");
    assert_eq!(schema.0.get("name").and_then(|v| v.as_str()), Some("zms"));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/schema");

    handle.join().expect("server");
}

#[test]
fn get_user_authority_attributes_calls_endpoint() {
    let body = r#"{"attributes":{"employeeType":{"values":["full_time"]}}}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let attributes = client
        .get_user_authority_attributes()
        .expect("authority attributes");
    let employee_type = attributes
        .attributes
        .get("employeeType")
        .expect("employeeType attribute");
    assert_eq!(employee_type.values, vec!["full_time".to_string()]);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/authority/user/attribute");

    handle.join().expect("server");
}

#[test]
fn get_domain_stats_calls_domain_stats_endpoint() {
    let body = r#"{"name":"sports","subdomain":1,"role":2,"roleMember":3,"policy":4,"assertion":5,"entity":6,"service":7,"serviceHost":8,"publicKey":9,"group":10,"groupMember":11}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let stats = client.get_domain_stats("sports").expect("domain stats");
    assert_eq!(stats.name.as_deref(), Some("sports"));
    assert_eq!(stats.subdomain, 1);
    assert_eq!(stats.group_member, 11);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/stats");

    handle.join().expect("server");
}

#[test]
fn put_domain_system_meta_calls_domain_meta_system_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let meta = DomainMeta {
        product_id: Some("prod-1".to_string()),
        ..Default::default()
    };
    client
        .put_domain_system_meta("sports", "product-id", &meta, Some("set product id"))
        .expect("put domain system meta");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/domain/sports/meta/system/product-id");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("set product id")
    );
    let body_json: serde_json::Value =
        serde_json::from_slice(&req.body).expect("json body for put_domain_system_meta");
    assert_eq!(body_json, json!({ "productId": "prod-1" }));

    handle.join().expect("server");
}

#[test]
fn get_domain_meta_store_calls_metastore_endpoint() {
    let body = r#"{"validValues":["prod-1","prod-2"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let values = client
        .get_domain_meta_store("product-id", Some("user.jane"))
        .expect("meta store values");
    assert_eq!(
        values.valid_values,
        vec!["prod-1".to_string(), "prod-2".to_string()]
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/metastore");
    assert_eq!(
        req.query.get("attribute").map(String::as_str),
        Some("product-id")
    );
    assert_eq!(req.query.get("user").map(String::as_str), Some("user.jane"));

    handle.join().expect("server");
}

#[test]
fn get_domain_meta_store_without_user_omits_user_query() {
    let body = r#"{"validValues":["prod-1","prod-2"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let values = client
        .get_domain_meta_store("product-id", None)
        .expect("meta store values");
    assert_eq!(
        values.valid_values,
        vec!["prod-1".to_string(), "prod-2".to_string()]
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/metastore");
    assert_eq!(
        req.query.get("attribute").map(String::as_str),
        Some("product-id")
    );
    assert!(req.query.get("user").is_none());

    handle.join().expect("server");
}

#[test]
fn put_domain_ownership_calls_domain_ownership_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let ownership = ResourceDomainOwnership {
        meta_owner: Some("sports.meta_owner".to_string()),
        object_owner: Some("sports.object_owner".to_string()),
    };
    client
        .put_domain_ownership("sports", &ownership, Some("set domain ownership"))
        .expect("put domain ownership");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/domain/sports/ownership");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("set domain ownership")
    );
    let body_json: serde_json::Value =
        serde_json::from_slice(&req.body).expect("request body should be valid JSON");
    assert_eq!(
        body_json,
        json!({
            "metaOwner": "sports.meta_owner",
            "objectOwner": "sports.object_owner",
        })
    );

    handle.join().expect("server");
}

#[test]
fn get_quota_calls_domain_quota_endpoint() {
    let body = r#"{"name":"sports","subdomain":1,"role":2,"roleMember":3,"policy":4,"assertion":5,"entity":6,"service":7,"serviceHost":8,"publicKey":9,"group":10,"groupMember":11,"modified":"2026-02-10T00:00:00Z"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let quota = client.get_quota("sports").expect("quota");
    assert_eq!(quota.name, "sports");
    assert_eq!(quota.subdomain, 1);
    assert_eq!(quota.role_member, 3);
    assert_eq!(quota.service_host, 8);
    assert_eq!(quota.public_key, 9);
    assert_eq!(quota.group_member, 11);
    assert_eq!(quota.modified.as_deref(), Some("2026-02-10T00:00:00Z"));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/quota");

    handle.join().expect("server");
}

#[test]
fn put_quota_calls_domain_quota_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let quota = Quota {
        name: "sports".to_string(),
        subdomain: 1,
        role: 2,
        role_member: 3,
        policy: 4,
        assertion: 5,
        entity: 6,
        service: 7,
        service_host: 8,
        public_key: 9,
        group: 10,
        group_member: 11,
        modified: None,
    };
    client
        .put_quota("sports", &quota, Some("update domain quota"))
        .expect("put quota");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/domain/sports/quota");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("update domain quota")
    );

    handle.join().expect("server");
}

#[test]
fn delete_quota_calls_domain_quota_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .delete_quota("sports", Some("delete domain quota"))
        .expect("delete quota");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "DELETE");
    assert_eq!(req.path, "/zms/v1/domain/sports/quota");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("delete domain quota")
    );

    handle.join().expect("server");
}

#[test]
fn get_entity_calls_domain_entity_endpoint() {
    let body = r#"{"name":"sports.entity.config","value":{"enabled":true,"limit":100}}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let entity = client
        .get_entity("sports", "entity.config")
        .expect("get entity");
    assert_eq!(entity.name, "sports.entity.config");
    assert_eq!(
        entity.value.get("enabled").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        entity.value.get("limit").and_then(|v| v.as_i64()),
        Some(100)
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/entity/entity.config");

    handle.join().expect("server");
}

#[test]
fn put_entity_calls_domain_entity_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let entity = Entity {
        name: "sports.entity.config".to_string(),
        value: json!({
            "enabled": true,
            "limit": 100
        }),
    };
    client
        .put_entity(
            "sports",
            "entity.config",
            &entity,
            Some("upsert domain entity"),
            Some("sports-admin"),
        )
        .expect("put entity");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/domain/sports/entity/entity.config");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("upsert domain entity")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports-admin")
    );

    handle.join().expect("server");
}

#[test]
fn delete_entity_calls_domain_entity_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .delete_entity(
            "sports",
            "entity.config",
            Some("delete domain entity"),
            Some("sports-admin"),
        )
        .expect("delete entity");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "DELETE");
    assert_eq!(req.path, "/zms/v1/domain/sports/entity/entity.config");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("delete domain entity")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports-admin")
    );

    handle.join().expect("server");
}

#[test]
fn get_entity_list_calls_domain_entity_list_endpoint() {
    let body = r#"{"names":["entity.config","entity.flags"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let entities = client.get_entity_list("sports").expect("entity list");
    assert_eq!(
        entities.names,
        vec!["entity.config".to_string(), "entity.flags".to_string()]
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/entity");

    handle.join().expect("server");
}

#[test]
fn get_domain_data_check_calls_domain_check_endpoint() {
    let body = r#"{"danglingRoles":["sports:role.admin"],"danglingPolicies":[{"policyName":"sports:policy.readers","roleName":"sports:role.readers"}],"policyCount":4,"assertionCount":9,"roleWildCardCount":2,"providersWithoutTrust":["sports.provider"],"tenantsWithoutAssumeRole":["sports.tenant"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let check = client
        .get_domain_data_check("sports")
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

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/check");

    handle.join().expect("server");
}

#[test]
fn dependency_put_domain_dependency_calls_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let detail = DependentService {
        service: "sports.storage".to_string(),
    };
    client
        .put_domain_dependency(
            "sports",
            &detail,
            Some("register dependency"),
            Some("sports.owner"),
        )
        .expect("put domain dependency");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/dependency/domain/sports");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("register dependency")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );
    let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
    assert_eq!(body["service"], "sports.storage");

    handle.join().expect("server");
}

#[test]
fn dependency_delete_domain_dependency_calls_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .delete_domain_dependency(
            "sports",
            "sports.storage",
            Some("delete dependency"),
            Some("sports.owner"),
        )
        .expect("delete domain dependency");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "DELETE");
    assert_eq!(
        req.path,
        "/zms/v1/dependency/domain/sports/service/sports.storage"
    );
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("delete dependency")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn dependency_get_dependent_service_list_calls_endpoint() {
    let body = r#"{"names":["sports.storage","media.publisher"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let list = client
        .get_dependent_service_list("sports")
        .expect("dependent service list");
    assert_eq!(
        list.names,
        vec!["sports.storage".to_string(), "media.publisher".to_string()]
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/dependency/domain/sports");

    handle.join().expect("server");
}

#[test]
fn dependency_get_dependent_service_resource_group_list_calls_endpoint() {
    let body = r#"{"serviceAndResourceGroups":[{"service":"sports.storage","domain":"sports","resourceGroups":["core","db"]}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let list = client
        .get_dependent_service_resource_group_list("sports")
        .expect("dependent service resource groups");
    assert_eq!(list.service_and_resource_groups.len(), 1);
    assert_eq!(
        list.service_and_resource_groups[0].service,
        "sports.storage"
    );
    assert_eq!(list.service_and_resource_groups[0].domain, "sports");
    assert_eq!(
        list.service_and_resource_groups[0].resource_groups,
        Some(vec!["core".to_string(), "db".to_string()])
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/dependency/domain/sports/resourceGroup");

    handle.join().expect("server");
}

#[test]
fn dependency_get_dependent_domain_list_calls_endpoint() {
    let body = r#"{"names":["sports","media"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let list = client
        .get_dependent_domain_list("sports.storage")
        .expect("dependent domain list");
    assert_eq!(list.names, vec!["sports".to_string(), "media".to_string()]);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/dependency/service/sports.storage");

    handle.join().expect("server");
}

#[test]
fn access_get_access_calls_endpoint_with_query() {
    let body = r#"{"granted":true}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let access = client
        .get_access("read", "sports.resource", Some("sports"), Some("user.jane"))
        .expect("access");
    assert!(access.granted);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/access/read/sports.resource");
    assert_eq!(req.query.get("domain").map(String::as_str), Some("sports"));
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );

    handle.join().expect("server");
}

#[test]
fn access_get_access_with_principal_only_sets_principal_query_param() {
    let body = r#"{"granted":true}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let access = client
        .get_access("read", "sports.resource", None, Some("user.jane"))
        .expect("access");
    assert!(access.granted);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/access/read/sports.resource");
    assert_eq!(req.query.get("domain").map(String::as_str), None);
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );

    handle.join().expect("server");
}

#[test]
fn access_get_access_with_domain_only_sets_domain_query_param() {
    let body = r#"{"granted":true}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let access = client
        .get_access("read", "sports.resource", Some("sports"), None)
        .expect("access");
    assert!(access.granted);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/access/read/sports.resource");
    assert_eq!(req.query.get("domain").map(String::as_str), Some("sports"));
    assert_eq!(req.query.get("principal").map(String::as_str), None);

    handle.join().expect("server");
}

#[test]
fn access_get_access_without_optional_filters_omits_query_params() {
    let body = r#"{"granted":true}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let access = client
        .get_access("read", "sports.resource", None, None)
        .expect("access");
    assert!(access.granted);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/access/read/sports.resource");
    assert_eq!(req.query.get("domain").map(String::as_str), None);
    assert_eq!(req.query.get("principal").map(String::as_str), None);

    handle.join().expect("server");
}

#[test]
fn access_get_access_ext_calls_endpoint_with_query() {
    let body = r#"{"granted":false}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let access = client
        .get_access_ext("read", "sports.resource", Some("sports"), Some("user.jane"))
        .expect("access");
    assert!(!access.granted);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/access/read");
    assert_eq!(
        req.query.get("resource").map(String::as_str),
        Some("sports.resource")
    );
    assert_eq!(req.query.get("domain").map(String::as_str), Some("sports"));
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );

    handle.join().expect("server");
}

#[test]
fn access_get_access_ext_with_principal_only_sets_principal_query_param() {
    let body = r#"{"granted":true}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let access = client
        .get_access_ext("read", "sports.resource", None, Some("user.jane"))
        .expect("access");
    assert!(access.granted);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/access/read");
    assert_eq!(
        req.query.get("resource").map(String::as_str),
        Some("sports.resource")
    );
    assert_eq!(req.query.get("domain").map(String::as_str), None);
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );

    handle.join().expect("server");
}

#[test]
fn access_get_access_ext_with_domain_only_sets_domain_query_param() {
    let body = r#"{"granted":true}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let access = client
        .get_access_ext("read", "sports.resource", Some("sports"), None)
        .expect("access");
    assert!(access.granted);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/access/read");
    assert_eq!(
        req.query.get("resource").map(String::as_str),
        Some("sports.resource")
    );
    assert_eq!(req.query.get("domain").map(String::as_str), Some("sports"));
    assert_eq!(req.query.get("principal").map(String::as_str), None);

    handle.join().expect("server");
}

#[test]
fn access_get_access_ext_without_optional_filters_omits_query_params() {
    let body = r#"{"granted":true}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let access = client
        .get_access_ext("read", "sports.resource", None, None)
        .expect("access");
    assert!(access.granted);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/access/read");
    assert_eq!(
        req.query.get("resource").map(String::as_str),
        Some("sports.resource")
    );
    assert_eq!(req.query.get("domain").map(String::as_str), None);
    assert_eq!(req.query.get("principal").map(String::as_str), None);

    handle.join().expect("server");
}

#[test]
fn access_get_resource_access_list_calls_endpoint_with_query() {
    let body = r#"{"resources":[{"principal":"user.jane","assertions":[{"role":"sports:role.reader","resource":"sports.resource","action":"read"}]}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let list = client
        .get_resource_access_list("user.jane", Some("read"), Some("sports."))
        .expect("resource access list");
    assert_eq!(list.resources.len(), 1);
    assert_eq!(list.resources[0].principal, "user.jane");
    assert_eq!(list.resources[0].assertions.len(), 1);
    assert_eq!(list.resources[0].assertions[0].action, "read");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/resource");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );
    assert_eq!(req.query.get("action").map(String::as_str), Some("read"));
    assert_eq!(req.query.get("filter").map(String::as_str), Some("sports."));

    handle.join().expect("server");
}

#[test]
fn access_get_resource_access_list_with_action_only_sets_action_query_param() {
    let body = r#"{"resources":[{"principal":"user.jane","assertions":[{"role":"sports:role.reader","resource":"sports.resource","action":"read"}]}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let list = client
        .get_resource_access_list("user.jane", Some("read"), None)
        .expect("resource access list");
    assert_eq!(list.resources.len(), 1);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/resource");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );
    assert_eq!(req.query.get("action").map(String::as_str), Some("read"));
    assert_eq!(req.query.get("filter").map(String::as_str), None);

    handle.join().expect("server");
}

#[test]
fn access_get_resource_access_list_with_filter_only_sets_filter_query_param() {
    let body = r#"{"resources":[{"principal":"user.jane","assertions":[{"role":"sports:role.reader","resource":"sports.resource","action":"read"}]}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let list = client
        .get_resource_access_list("user.jane", None, Some("sports."))
        .expect("resource access list");
    assert_eq!(list.resources.len(), 1);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/resource");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );
    assert_eq!(req.query.get("action").map(String::as_str), None);
    assert_eq!(req.query.get("filter").map(String::as_str), Some("sports."));

    handle.join().expect("server");
}

#[test]
fn access_get_resource_access_list_without_optional_filters_omits_query_params() {
    let body = r#"{"resources":[{"principal":"user.jane","assertions":[{"role":"sports:role.reader","resource":"sports.resource","action":"read"}]}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let list = client
        .get_resource_access_list("user.jane", None, None)
        .expect("resource access list");
    assert_eq!(list.resources.len(), 1);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/resource");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );
    assert_eq!(req.query.get("action").map(String::as_str), None);
    assert_eq!(req.query.get("filter").map(String::as_str), None);

    handle.join().expect("server");
}

#[test]
fn access_get_access_applies_auth_header() {
    let body = r#"{"granted":true}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");

    client
        .get_access("read", "sports.resource", None, None)
        .expect("access");

    let req = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );

    handle.join().expect("server");
}

#[test]
fn user_get_user_list_calls_endpoint_with_domain_query() {
    let body = r#"{"names":["jane","alex"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let users = client
        .get_user_list(Some("user"))
        .expect("user list with domain");
    assert_eq!(users.names, vec!["jane".to_string(), "alex".to_string()]);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/user");
    assert_eq!(req.query.get("domain").map(String::as_str), Some("user"));

    handle.join().expect("server");
}

#[test]
fn user_get_user_list_without_domain_omits_query() {
    let body = r#"{"names":["jane"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let users = client.get_user_list(None).expect("user list");
    assert_eq!(users.names, vec!["jane".to_string()]);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/user");
    assert!(req.query.get("domain").is_none());

    handle.join().expect("server");
}

#[test]
fn user_delete_user_calls_endpoint_with_audit_headers() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .delete_user("jane", Some("cleanup user"), Some("sports.owner"))
        .expect("delete user");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "DELETE");
    assert_eq!(req.path, "/zms/v1/user/jane");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("cleanup user")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn user_delete_domain_member_calls_endpoint_with_audit_headers() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .delete_domain_member(
            "sports",
            "user.jane",
            Some("remove user memberships"),
            Some("sports.owner"),
        )
        .expect("delete domain member");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "DELETE");
    assert_eq!(req.path, "/zms/v1/domain/sports/member/user.jane");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("remove user memberships")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn template_get_server_template_list_calls_endpoint() {
    let body = r#"{"templateNames":["base","tenant"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let templates = client
        .get_server_template_list()
        .expect("server template list");
    assert_eq!(
        templates.template_names,
        vec!["base".to_string(), "tenant".to_string()]
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/template");

    handle.join().expect("server");
}

#[test]
fn template_get_template_calls_endpoint() {
    let body = r#"{"roles":[{"name":"sports:role.reader"}],"policies":[{"name":"sports:policy.reader","assertions":[{"role":"sports:role.reader","resource":"sports:*","action":"read"}]}],"groups":[{"name":"sports:group.ops"}],"services":[{"name":"sports.api"}],"metadata":{"templateName":"base","description":"base template","currentVersion":1,"latestVersion":2,"keywordsToReplace":"_service_","timestamp":"2026-02-10T00:00:00Z","autoUpdate":true}}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let template = client.get_template("base").expect("template");
    assert_eq!(template.roles.len(), 1);
    assert_eq!(template.roles[0].name, "sports:role.reader");
    assert_eq!(template.policies.len(), 1);
    assert_eq!(template.policies[0].name, "sports:policy.reader");
    assert_eq!(
        template
            .meta
            .as_ref()
            .and_then(|meta| meta.template_name.as_deref()),
        Some("base")
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/template/base");

    handle.join().expect("server");
}

#[test]
fn template_get_domain_template_details_calls_endpoint() {
    let body = r#"{"metaData":[{"templateName":"base","description":"base template","currentVersion":1,"latestVersion":2,"autoUpdate":true}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let details = client
        .get_domain_template_details("sports")
        .expect("domain template details");
    assert_eq!(details.meta_data.len(), 1);
    assert_eq!(details.meta_data[0].template_name.as_deref(), Some("base"));
    assert_eq!(details.meta_data[0].current_version, Some(1));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/templatedetails");

    handle.join().expect("server");
}

#[test]
fn template_get_server_template_details_list_calls_endpoint() {
    let body = r#"{"metaData":[{"templateName":"tenant"}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let details = client
        .get_server_template_details_list()
        .expect("server template details");
    assert_eq!(details.meta_data.len(), 1);
    assert_eq!(
        details.meta_data[0].template_name.as_deref(),
        Some("tenant")
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/templatedetails");

    handle.join().expect("server");
}

#[test]
fn tenancy_put_tenancy_calls_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let detail = Tenancy {
        domain: "sports".to_string(),
        service: "storage".to_string(),
        resource_groups: Some(vec!["core".to_string()]),
        create_admin_role: Some(true),
    };
    client
        .put_tenancy(
            "sports",
            "storage",
            &detail,
            Some("register tenant service"),
            Some("sports.owner"),
        )
        .expect("put tenancy");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/domain/sports/tenancy/storage");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("register tenant service")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn tenancy_delete_tenancy_calls_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .delete_tenancy(
            "sports",
            "storage",
            Some("delete tenant service"),
            Some("sports.owner"),
        )
        .expect("delete tenancy");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "DELETE");
    assert_eq!(req.path, "/zms/v1/domain/sports/tenancy/storage");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("delete tenant service")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn tenancy_put_tenant_calls_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let detail = Tenancy {
        domain: "sports.tenant".to_string(),
        service: "storage".to_string(),
        resource_groups: Some(vec!["core".to_string()]),
        create_admin_role: Some(true),
    };
    client
        .put_tenant(
            "sports",
            "storage",
            "sports.tenant",
            &detail,
            Some("register tenant domain"),
            Some("sports.owner"),
        )
        .expect("put tenant");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(
        req.path,
        "/zms/v1/domain/sports/service/storage/tenant/sports.tenant"
    );
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("register tenant domain")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn tenancy_delete_tenant_calls_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .delete_tenant(
            "sports",
            "storage",
            "sports.tenant",
            Some("delete tenant domain"),
            Some("sports.owner"),
        )
        .expect("delete tenant");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "DELETE");
    assert_eq!(
        req.path,
        "/zms/v1/domain/sports/service/storage/tenant/sports.tenant"
    );
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("delete tenant domain")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn tenancy_put_tenant_resource_group_roles_calls_endpoint() {
    let body = r#"{"domain":"sports","service":"storage","tenant":"sports.tenant","roles":[{"role":"reader","action":"read"}],"resourceGroup":"core"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let detail = TenantResourceGroupRoles {
        domain: "sports".to_string(),
        service: "storage".to_string(),
        tenant: "sports.tenant".to_string(),
        roles: vec![TenantRoleAction {
            role: "reader".to_string(),
            action: "read".to_string(),
        }],
        resource_group: "core".to_string(),
    };

    let result = client
        .put_tenant_resource_group_roles(
            "sports",
            "storage",
            "sports.tenant",
            "core",
            &detail,
            Some("upsert tenant roles"),
            Some("sports.owner"),
        )
        .expect("put tenant resource group roles");
    assert_eq!(result.domain, "sports");
    assert_eq!(result.service, "storage");
    assert_eq!(result.tenant, "sports.tenant");
    assert_eq!(result.roles.len(), 1);
    assert_eq!(result.roles[0].role, "reader");
    assert_eq!(result.roles[0].action, "read");
    assert_eq!(result.resource_group, "core");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(
        req.path,
        "/zms/v1/domain/sports/service/storage/tenant/sports.tenant/resourceGroup/core"
    );
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("upsert tenant roles")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn tenancy_get_tenant_resource_group_roles_calls_endpoint() {
    let body = r#"{"domain":"sports","service":"storage","tenant":"sports.tenant","roles":[{"role":"reader","action":"read"}],"resourceGroup":"core"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let result = client
        .get_tenant_resource_group_roles("sports", "storage", "sports.tenant", "core")
        .expect("get tenant resource group roles");
    assert_eq!(result.domain, "sports");
    assert_eq!(result.service, "storage");
    assert_eq!(result.tenant, "sports.tenant");
    assert_eq!(result.roles.len(), 1);
    assert_eq!(result.roles[0].role, "reader");
    assert_eq!(result.roles[0].action, "read");
    assert_eq!(result.resource_group, "core");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zms/v1/domain/sports/service/storage/tenant/sports.tenant/resourceGroup/core"
    );

    handle.join().expect("server");
}

#[test]
fn tenancy_delete_tenant_resource_group_roles_calls_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .delete_tenant_resource_group_roles(
            "sports",
            "storage",
            "sports.tenant",
            "core",
            Some("delete tenant roles"),
            Some("sports.owner"),
        )
        .expect("delete tenant resource group roles");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "DELETE");
    assert_eq!(
        req.path,
        "/zms/v1/domain/sports/service/storage/tenant/sports.tenant/resourceGroup/core"
    );
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("delete tenant roles")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn tenancy_put_provider_resource_group_roles_calls_endpoint() {
    let body = r#"{"domain":"sports","service":"storage","tenant":"sports.tenant","roles":[{"role":"reader","action":"read"}],"resourceGroup":"core","createAdminRole":true,"skipPrincipalMember":false}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let detail = ProviderResourceGroupRoles {
        domain: "sports".to_string(),
        service: "storage".to_string(),
        tenant: "sports.tenant".to_string(),
        roles: vec![TenantRoleAction {
            role: "reader".to_string(),
            action: "read".to_string(),
        }],
        resource_group: "core".to_string(),
        create_admin_role: Some(true),
        skip_principal_member: Some(false),
    };

    let result = client
        .put_provider_resource_group_roles(
            "sports.tenant",
            "sports",
            "storage",
            "core",
            &detail,
            Some("upsert provider roles"),
            Some("sports.owner"),
        )
        .expect("put provider resource group roles");
    assert_eq!(result.domain, "sports");
    assert_eq!(result.service, "storage");
    assert_eq!(result.tenant, "sports.tenant");
    assert_eq!(result.roles.len(), 1);
    assert_eq!(result.roles[0].role, "reader");
    assert_eq!(result.roles[0].action, "read");
    assert_eq!(result.resource_group, "core");
    assert_eq!(result.create_admin_role, Some(true));
    assert_eq!(result.skip_principal_member, Some(false));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(
        req.path,
        "/zms/v1/domain/sports.tenant/provDomain/sports/provService/storage/resourceGroup/core"
    );
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("upsert provider roles")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn tenancy_get_provider_resource_group_roles_calls_endpoint() {
    let body = r#"{"domain":"sports","service":"storage","tenant":"sports.tenant","roles":[{"role":"reader","action":"read"}],"resourceGroup":"core","createAdminRole":true,"skipPrincipalMember":false}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let result = client
        .get_provider_resource_group_roles("sports.tenant", "sports", "storage", "core")
        .expect("get provider resource group roles");
    assert_eq!(result.domain, "sports");
    assert_eq!(result.service, "storage");
    assert_eq!(result.tenant, "sports.tenant");
    assert_eq!(result.roles.len(), 1);
    assert_eq!(result.roles[0].role, "reader");
    assert_eq!(result.roles[0].action, "read");
    assert_eq!(result.resource_group, "core");
    assert_eq!(result.create_admin_role, Some(true));
    assert_eq!(result.skip_principal_member, Some(false));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zms/v1/domain/sports.tenant/provDomain/sports/provService/storage/resourceGroup/core"
    );

    handle.join().expect("server");
}

#[test]
fn tenancy_delete_provider_resource_group_roles_calls_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .delete_provider_resource_group_roles(
            "sports.tenant",
            "sports",
            "storage",
            "core",
            Some("delete provider roles"),
            Some("sports.owner"),
        )
        .expect("delete provider resource group roles");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "DELETE");
    assert_eq!(
        req.path,
        "/zms/v1/domain/sports.tenant/provDomain/sports/provService/storage/resourceGroup/core"
    );
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("delete provider roles")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn get_principal_groups_calls_group_endpoint() {
    let body = r#"{"memberName":"user.jane","memberGroups":[{"memberName":"user.jane","groupName":"devs","domainName":"sports","active":true}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let groups = client
        .get_principal_groups(Some("user.jane"), Some("sports"))
        .expect("principal groups");
    assert_eq!(groups.member_name, "user.jane");
    assert_eq!(groups.member_groups.len(), 1);
    assert_eq!(groups.member_groups[0].group_name.as_deref(), Some("devs"));
    assert_eq!(
        groups.member_groups[0].domain_name.as_deref(),
        Some("sports")
    );
    assert_eq!(groups.member_groups[0].active, Some(true));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/group");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );
    assert_eq!(req.query.get("domain").map(String::as_str), Some("sports"));

    handle.join().expect("server");
}

#[test]
fn get_principal_groups_without_filters_omits_query_params() {
    let body = r#"{"memberName":"user.jane","memberGroups":[{"memberName":"user.jane","groupName":"devs","domainName":"sports","active":true}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let groups = client
        .get_principal_groups(None, None)
        .expect("principal groups");
    assert_eq!(groups.member_name, "user.jane");
    assert_eq!(groups.member_groups.len(), 1);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/group");
    assert!(req.query.get("principal").is_none());
    assert!(req.query.get("domain").is_none());

    handle.join().expect("server");
}

#[test]
fn get_principal_groups_with_principal_only_sets_principal_query_param() {
    let body = r#"{"memberName":"user.jane","memberGroups":[{"memberName":"user.jane","groupName":"devs","domainName":"sports","active":true}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let groups = client
        .get_principal_groups(Some("user.jane"), None)
        .expect("principal groups");
    assert_eq!(groups.member_name, "user.jane");
    assert_eq!(groups.member_groups.len(), 1);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/group");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );
    assert!(req.query.get("domain").is_none());

    handle.join().expect("server");
}

#[test]
fn get_principal_groups_with_domain_only_sets_domain_query_param() {
    let body = r#"{"memberName":"user.jane","memberGroups":[{"memberName":"user.jane","groupName":"devs","domainName":"sports","active":true}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let groups = client
        .get_principal_groups(None, Some("sports"))
        .expect("principal groups");
    assert_eq!(groups.member_name, "user.jane");
    assert_eq!(groups.member_groups.len(), 1);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/group");
    assert!(req.query.get("principal").is_none());
    assert_eq!(req.query.get("domain").map(String::as_str), Some("sports"));

    handle.join().expect("server");
}

#[test]
fn get_roles_for_review_calls_review_role_endpoint() {
    let body = r#"{"list":[{"domainName":"sports","name":"sports:role.reader","memberExpiryDays":30,"memberReviewDays":90,"serviceExpiryDays":0,"serviceReviewDays":0,"groupExpiryDays":0,"groupReviewDays":0,"lastReviewedDate":"2024-01-01T00:00:00Z","created":"2020-01-01T00:00:00Z"}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let reviews = client
        .get_roles_for_review(Some("user.jane"))
        .expect("role reviews");
    assert_eq!(reviews.list.len(), 1);
    assert_eq!(reviews.list[0].domain_name, "sports");
    assert_eq!(reviews.list[0].name, "sports:role.reader");
    assert_eq!(reviews.list[0].member_review_days, 90);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/review/role");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );

    handle.join().expect("server");
}

#[test]
fn get_roles_for_review_without_principal_omits_query_param() {
    let body = r#"{"list":[{"domainName":"sports","name":"sports:role.reader","memberExpiryDays":30,"memberReviewDays":90,"serviceExpiryDays":0,"serviceReviewDays":0,"groupExpiryDays":0,"groupReviewDays":0,"created":"2020-01-01T00:00:00Z"}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let reviews = client.get_roles_for_review(None).expect("role reviews");
    assert_eq!(reviews.list.len(), 1);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/review/role");
    assert!(req.query.get("principal").is_none());

    handle.join().expect("server");
}

#[test]
fn get_groups_for_review_calls_review_group_endpoint() {
    let body = r#"{"list":[{"domainName":"sports","name":"devs","memberExpiryDays":30,"memberReviewDays":90,"serviceExpiryDays":0,"serviceReviewDays":0,"groupExpiryDays":0,"groupReviewDays":0,"lastReviewedDate":"2024-01-01T00:00:00Z","created":"2020-01-01T00:00:00Z"}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let reviews = client
        .get_groups_for_review(Some("user.jane"))
        .expect("group reviews");
    assert_eq!(reviews.list.len(), 1);
    assert_eq!(reviews.list[0].domain_name, "sports");
    assert_eq!(reviews.list[0].name, "devs");
    assert_eq!(reviews.list[0].member_review_days, 90);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/review/group");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );

    handle.join().expect("server");
}

#[test]
fn get_groups_for_review_without_principal_omits_query_param() {
    let body = r#"{"list":[{"domainName":"sports","name":"devs","memberExpiryDays":30,"memberReviewDays":90,"serviceExpiryDays":0,"serviceReviewDays":0,"groupExpiryDays":0,"groupReviewDays":0,"created":"2020-01-01T00:00:00Z"}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let reviews = client.get_groups_for_review(None).expect("group reviews");
    assert_eq!(reviews.list.len(), 1);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/review/group");
    assert!(req.query.get("principal").is_none());

    handle.join().expect("server");
}

#[test]
fn get_overdue_domain_role_members_calls_overdue_endpoint() {
    let body = r#"{"domainName":"sports","members":[{"memberName":"user.jane","memberRoles":[{"roleName":"sports:role.reader","domainName":"sports","memberName":"user.jane","active":true}]}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let members = client
        .get_overdue_domain_role_members("sports")
        .expect("overdue members");
    assert_eq!(members.domain_name, "sports");
    assert_eq!(members.members.len(), 1);
    assert_eq!(members.members[0].member_name, "user.jane");
    assert_eq!(members.members[0].member_roles.len(), 1);
    assert_eq!(
        members.members[0].member_roles[0].role_name,
        "sports:role.reader"
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/overdue");

    handle.join().expect("server");
}

#[test]
fn get_domain_role_members_calls_member_endpoint() {
    let body = r#"{"domainName":"sports","members":[{"memberName":"user.jane","memberRoles":[{"roleName":"sports:role.reader","domainName":"sports","memberName":"user.jane","active":true}]}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let members = client
        .get_domain_role_members("sports")
        .expect("role members");
    assert_eq!(members.domain_name, "sports");
    assert_eq!(members.members.len(), 1);
    assert_eq!(members.members[0].member_name, "user.jane");
    assert_eq!(members.members[0].member_roles.len(), 1);
    assert_eq!(
        members.members[0].member_roles[0].role_name,
        "sports:role.reader"
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/member");

    handle.join().expect("server");
}

#[test]
fn get_domain_group_members_calls_group_member_endpoint() {
    let body = r#"{"domainName":"sports","members":[{"memberName":"user.jane","memberGroups":[{"memberName":"user.jane","groupName":"devs","domainName":"sports","active":true}]}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let members = client
        .get_domain_group_members("sports")
        .expect("group members");
    assert_eq!(members.domain_name, "sports");
    assert_eq!(members.members.len(), 1);
    assert_eq!(members.members[0].member_name, "user.jane");
    assert_eq!(members.members[0].member_groups.len(), 1);
    assert_eq!(
        members.members[0].member_groups[0].group_name.as_deref(),
        Some("devs")
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/group/member");

    handle.join().expect("server");
}

#[test]
fn put_group_system_meta_calls_group_meta_system_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let meta = GroupMeta {
        self_serve: Some(true),
        ..Default::default()
    };
    client
        .put_group_system_meta(
            "sports",
            "devs",
            "self-serve",
            &meta,
            Some("set group self-serve"),
        )
        .expect("put group system meta");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(
        req.path,
        "/zms/v1/domain/sports/group/devs/meta/system/self-serve"
    );
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("set group self-serve")
    );
    let body_json: serde_json::Value =
        serde_json::from_slice(&req.body).expect("request body should be valid JSON");
    assert_eq!(body_json, json!({ "selfServe": true }));

    handle.join().expect("server");
}

#[test]
fn put_group_meta_calls_group_meta_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let meta = GroupMeta {
        self_serve: Some(true),
        review_enabled: Some(true),
        ..Default::default()
    };
    client
        .put_group_meta("sports", "devs", &meta, Some("update group meta"))
        .expect("put group meta");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/domain/sports/group/devs/meta");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("update group meta")
    );
    let body_json: serde_json::Value =
        serde_json::from_slice(&req.body).expect("request body should be valid JSON");
    assert_eq!(
        body_json,
        json!({ "selfServe": true, "reviewEnabled": true })
    );

    handle.join().expect("server");
}

#[test]
fn put_group_review_calls_group_review_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .put_group_review("sports", "devs", Some("mark group reviewed"))
        .expect("put group review");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/domain/sports/group/devs/review");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("mark group reviewed")
    );
    assert!(req.body.is_empty());

    handle.join().expect("server");
}

#[test]
fn put_group_ownership_calls_group_ownership_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let ownership = ResourceGroupOwnership {
        meta_owner: Some("sports.meta_owner".to_string()),
        members_owner: Some("sports.members_owner".to_string()),
        object_owner: Some("sports.object_owner".to_string()),
    };
    client
        .put_group_ownership("sports", "devs", &ownership, Some("set group ownership"))
        .expect("put group ownership");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/domain/sports/group/devs/ownership");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("set group ownership")
    );
    let body_json: serde_json::Value =
        serde_json::from_slice(&req.body).expect("request body should be valid JSON");
    assert_eq!(
        body_json,
        json!({
            "metaOwner": "sports.meta_owner",
            "membersOwner": "sports.members_owner",
            "objectOwner": "sports.object_owner",
        })
    );

    handle.join().expect("server");
}

#[test]
fn get_pending_members_calls_endpoint_with_query() {
    let body = r#"{"domainRoleMembersList":[{"domainName":"sports","members":[{"memberName":"user.jane","memberRoles":[{"roleName":"sports:role.reader","domainName":"sports","memberName":"user.jane","pendingState":"PENDING"}]}]}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let memberships = client
        .get_pending_members(Some("user.jane"), Some("sports"))
        .expect("pending role memberships");
    assert_eq!(memberships.domain_role_members_list.len(), 1);
    assert_eq!(
        memberships.domain_role_members_list[0].domain_name,
        "sports"
    );
    assert_eq!(memberships.domain_role_members_list[0].members.len(), 1);
    assert_eq!(
        memberships.domain_role_members_list[0].members[0].member_name,
        "user.jane"
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/pending_members");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );
    assert_eq!(req.query.get("domain").map(String::as_str), Some("sports"));

    handle.join().expect("server");
}

#[test]
fn get_pending_group_members_calls_endpoint_with_query() {
    let body = r#"{"domainGroupMembersList":[{"domainName":"sports","members":[{"memberName":"user.jane","memberGroups":[{"memberName":"user.jane","groupName":"devs","domainName":"sports","pendingState":"PENDING"}]}]}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let memberships = client
        .get_pending_group_members(Some("user.jane"), Some("sports"))
        .expect("pending group memberships");
    assert_eq!(memberships.domain_group_members_list.len(), 1);
    assert_eq!(
        memberships.domain_group_members_list[0].domain_name,
        "sports"
    );
    assert_eq!(memberships.domain_group_members_list[0].members.len(), 1);
    assert_eq!(
        memberships.domain_group_members_list[0].members[0].member_name,
        "user.jane"
    );

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/pending_group_members");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );
    assert_eq!(req.query.get("domain").map(String::as_str), Some("sports"));

    handle.join().expect("server");
}

#[test]
fn get_pending_members_with_principal_only_sets_principal_query_param() {
    let body = r#"{"domainRoleMembersList":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let memberships = client
        .get_pending_members(Some("user.jane"), None)
        .expect("pending role memberships");
    assert!(memberships.domain_role_members_list.is_empty());

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/pending_members");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );
    assert!(req.query.get("domain").is_none());

    handle.join().expect("server");
}

#[test]
fn get_pending_members_with_domain_only_sets_domain_query_param() {
    let body = r#"{"domainRoleMembersList":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let memberships = client
        .get_pending_members(None, Some("sports"))
        .expect("pending role memberships");
    assert!(memberships.domain_role_members_list.is_empty());

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/pending_members");
    assert!(req.query.get("principal").is_none());
    assert_eq!(req.query.get("domain").map(String::as_str), Some("sports"));

    handle.join().expect("server");
}

#[test]
fn get_pending_group_members_with_principal_only_sets_principal_query_param() {
    let body = r#"{"domainGroupMembersList":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let memberships = client
        .get_pending_group_members(Some("user.jane"), None)
        .expect("pending group memberships");
    assert!(memberships.domain_group_members_list.is_empty());

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/pending_group_members");
    assert_eq!(
        req.query.get("principal").map(String::as_str),
        Some("user.jane")
    );
    assert!(req.query.get("domain").is_none());

    handle.join().expect("server");
}

#[test]
fn get_pending_group_members_with_domain_only_sets_domain_query_param() {
    let body = r#"{"domainGroupMembersList":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let memberships = client
        .get_pending_group_members(None, Some("sports"))
        .expect("pending group memberships");
    assert!(memberships.domain_group_members_list.is_empty());

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/pending_group_members");
    assert!(req.query.get("principal").is_none());
    assert_eq!(req.query.get("domain").map(String::as_str), Some("sports"));

    handle.join().expect("server");
}

#[test]
fn get_pending_group_members_without_filters_omits_query_params() {
    let body = r#"{"domainGroupMembersList":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let memberships = client
        .get_pending_group_members(None, None)
        .expect("pending group memberships");
    assert!(memberships.domain_group_members_list.is_empty());

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/pending_group_members");
    assert!(req.query.get("principal").is_none());
    assert!(req.query.get("domain").is_none());

    handle.join().expect("server");
}

#[test]
fn get_pending_members_without_filters_omits_query_params() {
    let body = r#"{"domainRoleMembersList":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let memberships = client
        .get_pending_members(None, None)
        .expect("pending role memberships");
    assert!(memberships.domain_role_members_list.is_empty());

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/pending_members");
    assert!(req.query.get("principal").is_none());
    assert!(req.query.get("domain").is_none());

    handle.join().expect("server");
}

#[test]
fn get_pending_group_members_applies_auth_header() {
    let body = r#"{"domainGroupMembersList":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");

    client
        .get_pending_group_members(None, None)
        .expect("pending group memberships");

    let req = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );

    handle.join().expect("server");
}

#[test]
fn get_pending_members_applies_auth_header() {
    let body = r#"{"domainRoleMembersList":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");

    client
        .get_pending_members(None, None)
        .expect("pending role memberships");

    let req = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );

    handle.join().expect("server");
}

#[test]
fn put_principal_state_calls_principal_state_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
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
        .expect("put principal state");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/principal/sports.api/state");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("disable compromised principal")
    );

    handle.join().expect("server");
}

#[test]
fn get_user_token_calls_user_token_endpoint() {
    let body = r#"{"token":"signed-user-token","header":"Athenz-Principal-Auth"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let user_token = client
        .get_user_token("jane", Some("sports.api,media.api"), Some(true))
        .expect("user token");
    assert_eq!(user_token.token, "signed-user-token");
    assert_eq!(user_token.header.as_deref(), Some("Athenz-Principal-Auth"));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/user/jane/token");
    assert_eq!(
        req.query.get("services").map(String::as_str),
        Some("sports.api,media.api")
    );
    assert_eq!(req.query.get("header").map(String::as_str), Some("true"));

    handle.join().expect("server");
}

#[test]
fn options_user_token_calls_user_token_options_endpoint() {
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .options_user_token("jane", Some("sports.api"))
        .expect("options user token");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "OPTIONS");
    assert_eq!(req.path, "/zms/v1/user/jane/token");
    assert_eq!(
        req.query.get("services").map(String::as_str),
        Some("sports.api")
    );

    handle.join().expect("server");
}

#[test]
fn options_user_token_accepts_no_content_response() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .options_user_token("jane", Some("sports.api"))
        .expect("options user token");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "OPTIONS");
    assert_eq!(req.path, "/zms/v1/user/jane/token");
    assert_eq!(
        req.query.get("services").map(String::as_str),
        Some("sports.api")
    );

    handle.join().expect("server");
}

#[test]
fn options_user_token_applies_auth_header() {
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");

    client
        .options_user_token("jane", Some("sports.api"))
        .expect("options user token");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "OPTIONS");
    assert_eq!(req.path, "/zms/v1/user/jane/token");
    assert_eq!(
        req.query.get("services").map(String::as_str),
        Some("sports.api")
    );
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );

    handle.join().expect("server");
}

#[test]
fn get_service_principal_calls_principal_endpoint() {
    let body = r#"{"domain":"sports","service":"api","token":"signed-service-token"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let principal = client.get_service_principal().expect("service principal");
    assert_eq!(principal.domain, "sports");
    assert_eq!(principal.service, "api");
    assert_eq!(principal.token, "signed-service-token");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/principal");

    handle.join().expect("server");
}

#[test]
fn get_system_stats_calls_system_stats_endpoint() {
    let body = r#"{"subdomain":1,"role":2,"roleMember":3,"policy":4,"assertion":5,"entity":6,"service":7,"serviceHost":8,"publicKey":9,"group":10,"groupMember":11}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let stats = client.get_system_stats().expect("system stats");
    assert_eq!(stats.name, None);
    assert_eq!(stats.policy, 4);
    assert_eq!(stats.public_key, 9);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/sys/stats");

    handle.join().expect("server");
}

#[test]
fn get_policy_version_list_calls_expected_endpoint() {
    let body = r#"{"names":["0","v1"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let list = client
        .get_policy_version_list("sports", "readers")
        .expect("policy version list");
    assert_eq!(list.names, vec!["0", "v1"]);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/policy/readers/version");

    handle.join().expect("server");
}

#[test]
fn get_policy_version_calls_expected_endpoint() {
    let body = r#"{"name":"sports:policy.readers","version":"v1"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let policy = client
        .get_policy_version("sports", "readers", "v1")
        .expect("policy version");
    assert_eq!(policy.name, "sports:policy.readers");
    assert_eq!(policy.version.as_deref(), Some("v1"));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/policy/readers/version/v1");

    handle.join().expect("server");
}

#[test]
fn put_policy_version_calls_create_endpoint() {
    let body = r#"{"name":"sports:policy.readers","version":"v2"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");
    let options = PolicyOptions {
        version: "v2".to_string(),
        from_version: Some("v1".to_string()),
    };

    let policy = client
        .put_policy_version(
            "sports",
            "readers",
            &options,
            Some("create version"),
            Some(true),
            Some("sports.owner"),
        )
        .expect("put policy version")
        .expect("policy");
    assert_eq!(policy.name, "sports:policy.readers");
    assert_eq!(policy.version.as_deref(), Some("v2"));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(
        req.path,
        "/zms/v1/domain/sports/policy/readers/version/create"
    );
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("create version")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );
    assert_eq!(
        req.headers.get("athenz-return-object").map(String::as_str),
        Some("true")
    );

    handle.join().expect("server");
}

#[test]
fn set_active_policy_version_calls_active_endpoint() {
    let body = r#"{"name":"sports:policy.readers","version":"v2","active":true}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");
    let options = PolicyOptions {
        version: "v2".to_string(),
        from_version: None,
    };

    let policy = client
        .set_active_policy_version(
            "sports",
            "readers",
            &options,
            Some("activate version"),
            Some(true),
            Some("sports.owner"),
        )
        .expect("set active policy version")
        .expect("policy");
    assert_eq!(policy.name, "sports:policy.readers");
    assert_eq!(policy.version.as_deref(), Some("v2"));
    assert_eq!(policy.active, Some(true));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(
        req.path,
        "/zms/v1/domain/sports/policy/readers/version/active"
    );
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("activate version")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );
    assert_eq!(
        req.headers.get("athenz-return-object").map(String::as_str),
        Some("true")
    );

    handle.join().expect("server");
}

#[test]
fn delete_policy_version_calls_expected_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    client
        .delete_policy_version(
            "sports",
            "readers",
            "v2",
            Some("delete version"),
            Some("sports.owner"),
        )
        .expect("delete policy version");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "DELETE");
    assert_eq!(req.path, "/zms/v1/domain/sports/policy/readers/version/v2");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("delete version")
    );
    assert_eq!(
        req.headers.get("athenz-resource-owner").map(String::as_str),
        Some("sports.owner")
    );

    handle.join().expect("server");
}

#[test]
fn put_policy_ownership_calls_expected_endpoint() {
    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let ownership = ResourcePolicyOwnership {
        assertions_owner: Some("sports.assertions_owner".to_string()),
        object_owner: Some("sports.object_owner".to_string()),
    };
    client
        .put_policy_ownership(
            "sports",
            "readers",
            &ownership,
            Some("set policy ownership"),
        )
        .expect("put policy ownership");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/zms/v1/domain/sports/policy/readers/ownership");
    assert_eq!(
        req.headers.get("y-audit-ref").map(String::as_str),
        Some("set policy ownership")
    );

    handle.join().expect("server");
}

#[test]
fn auth_requires_redirects_disabled() {
    let err = match ZmsClient::builder("https://example.com/zms/v1")
        .expect("builder")
        .disable_redirect(false)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
    {
        Ok(_) => panic!("expected error"),
        Err(err) => err,
    };
    match err {
        Error::Crypto(message) => {
            assert_eq!(message, CONFIG_ERROR_REDIRECT_WITH_AUTH);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn build_url_trims_trailing_slash() {
    let client = ZmsClient::builder("https://example.com/zms/v1/")
        .expect("builder")
        .build()
        .expect("build");
    let url = client.build_url(&["domain"]).expect("url");
    assert_eq!(url.path(), "/zms/v1/domain");
}

#[test]
fn auth_allows_redirects_disabled() {
    ZmsClient::builder("https://example.com/zms/v1")
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");
}

struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    query: HashMap<String, String>,
    body: Vec<u8>,
}

fn serve_once(
    response: String,
) -> (
    String,
    mpsc::Receiver<CapturedRequest>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let req = read_request(&mut stream);
            let _ = tx.send(req);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (format!("http://{}", addr), rx, handle)
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).unwrap_or(0);
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(buf.len());
    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let full_path = parts.next().unwrap_or("");

    let mut path_parts = full_path.splitn(2, '?');
    let path = path_parts.next().unwrap_or("").to_string();
    let query_str = path_parts.next().unwrap_or("");
    let mut query = HashMap::new();
    for (k, v) in url::form_urlencoded::parse(query_str.as_bytes()) {
        query.insert(k.to_string(), v.to_string());
    }

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).unwrap_or(0);
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    if body.len() > content_length {
        body.truncate(content_length);
    }

    CapturedRequest {
        method,
        path,
        headers,
        query,
        body,
    }
}
