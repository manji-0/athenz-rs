use crate::error::{Error, CONFIG_ERROR_REDIRECT_WITH_AUTH};
use crate::models::{
    PrincipalState, ProviderResourceGroupRoles, Tenancy, TenantResourceGroupRoles, TenantRoleAction,
};
use crate::zms::{DomainListOptions, ZmsClient};
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

    CapturedRequest {
        method,
        path,
        headers,
        query,
    }
}
