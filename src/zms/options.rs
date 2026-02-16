#[derive(Debug, Clone, Default)]
pub struct DomainListOptions {
    pub limit: Option<i32>,
    pub skip: Option<String>,
    pub prefix: Option<String>,
    pub depth: Option<i32>,
    pub account: Option<String>,
    pub product_number: Option<i32>,
    pub role_member: Option<String>,
    pub role_name: Option<String>,
    pub subscription: Option<String>,
    pub project: Option<String>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
    pub business_service: Option<String>,
    pub product_id: Option<String>,
    pub modified_since: Option<String>,
}

impl DomainListOptions {
    pub(crate) fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(ref skip) = self.skip {
            pairs.push(("skip", skip.clone()));
        }
        if let Some(ref prefix) = self.prefix {
            pairs.push(("prefix", prefix.clone()));
        }
        if let Some(depth) = self.depth {
            pairs.push(("depth", depth.to_string()));
        }
        if let Some(ref account) = self.account {
            pairs.push(("account", account.clone()));
        }
        if let Some(product_number) = self.product_number {
            pairs.push(("ypmid", product_number.to_string()));
        }
        if let Some(ref role_member) = self.role_member {
            pairs.push(("member", role_member.clone()));
        }
        if let Some(ref role_name) = self.role_name {
            pairs.push(("role", role_name.clone()));
        }
        if let Some(ref subscription) = self.subscription {
            pairs.push(("azure", subscription.clone()));
        }
        if let Some(ref project) = self.project {
            pairs.push(("gcp", project.clone()));
        }
        if let Some(ref tag_key) = self.tag_key {
            pairs.push(("tagKey", tag_key.clone()));
        }
        if let Some(ref tag_value) = self.tag_value {
            pairs.push(("tagValue", tag_value.clone()));
        }
        if let Some(ref business_service) = self.business_service {
            pairs.push(("businessService", business_service.clone()));
        }
        if let Some(ref product_id) = self.product_id {
            pairs.push(("productId", product_id.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct RoleListOptions {
    pub limit: Option<i32>,
    pub skip: Option<String>,
}

impl RoleListOptions {
    pub(crate) fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(ref skip) = self.skip {
            pairs.push(("skip", skip.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct RolesQueryOptions {
    pub members: Option<bool>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
}

impl RolesQueryOptions {
    pub(crate) fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(members) = self.members {
            pairs.push(("members", members.to_string()));
        }
        if let Some(ref tag_key) = self.tag_key {
            pairs.push(("tagKey", tag_key.clone()));
        }
        if let Some(ref tag_value) = self.tag_value {
            pairs.push(("tagValue", tag_value.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct RoleGetOptions {
    pub audit_log: Option<bool>,
    pub expand: Option<bool>,
    pub pending: Option<bool>,
}

impl RoleGetOptions {
    pub(crate) fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(audit_log) = self.audit_log {
            pairs.push(("auditLog", audit_log.to_string()));
        }
        if let Some(expand) = self.expand {
            pairs.push(("expand", expand.to_string()));
        }
        if let Some(pending) = self.pending {
            pairs.push(("pending", pending.to_string()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct PolicyListOptions {
    pub limit: Option<i32>,
    pub skip: Option<String>,
}

impl PolicyListOptions {
    pub(crate) fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(ref skip) = self.skip {
            pairs.push(("skip", skip.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct PoliciesQueryOptions {
    pub assertions: Option<bool>,
    pub include_non_active: Option<bool>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
}

impl PoliciesQueryOptions {
    pub(crate) fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(assertions) = self.assertions {
            pairs.push(("assertions", assertions.to_string()));
        }
        if let Some(include_non_active) = self.include_non_active {
            pairs.push(("includeNonActive", include_non_active.to_string()));
        }
        if let Some(ref tag_key) = self.tag_key {
            pairs.push(("tagKey", tag_key.clone()));
        }
        if let Some(ref tag_value) = self.tag_value {
            pairs.push(("tagValue", tag_value.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServiceListOptions {
    pub limit: Option<i32>,
    pub skip: Option<String>,
}

impl ServiceListOptions {
    pub(crate) fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(ref skip) = self.skip {
            pairs.push(("skip", skip.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServiceIdentitiesQueryOptions {
    pub public_keys: Option<bool>,
    pub hosts: Option<bool>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
}

impl ServiceIdentitiesQueryOptions {
    pub(crate) fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(public_keys) = self.public_keys {
            pairs.push(("publickeys", public_keys.to_string()));
        }
        if let Some(hosts) = self.hosts {
            pairs.push(("hosts", hosts.to_string()));
        }
        if let Some(ref tag_key) = self.tag_key {
            pairs.push(("tagKey", tag_key.clone()));
        }
        if let Some(ref tag_value) = self.tag_value {
            pairs.push(("tagValue", tag_value.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct GroupsQueryOptions {
    pub members: Option<bool>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
}

impl GroupsQueryOptions {
    pub(crate) fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(members) = self.members {
            pairs.push(("members", members.to_string()));
        }
        if let Some(ref tag_key) = self.tag_key {
            pairs.push(("tagKey", tag_key.clone()));
        }
        if let Some(ref tag_value) = self.tag_value {
            pairs.push(("tagValue", tag_value.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct GroupGetOptions {
    pub audit_log: Option<bool>,
    pub pending: Option<bool>,
}

impl GroupGetOptions {
    pub(crate) fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(audit_log) = self.audit_log {
            pairs.push(("auditLog", audit_log.to_string()));
        }
        if let Some(pending) = self.pending {
            pairs.push(("pending", pending.to_string()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct SignedDomainsOptions {
    pub domain: Option<String>,
    pub meta_only: Option<bool>,
    pub meta_attr: Option<String>,
    pub master: Option<bool>,
    pub conditions: Option<bool>,
}

impl SignedDomainsOptions {
    pub(crate) fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(ref domain) = self.domain {
            pairs.push(("domain", domain.clone()));
        }
        if let Some(meta_only) = self.meta_only {
            pairs.push(("metaonly", meta_only.to_string()));
        }
        if let Some(ref meta_attr) = self.meta_attr {
            pairs.push(("metaattr", meta_attr.clone()));
        }
        if let Some(master) = self.master {
            pairs.push(("master", master.to_string()));
        }
        if let Some(conditions) = self.conditions {
            pairs.push(("conditions", conditions.to_string()));
        }
        pairs
    }
}
