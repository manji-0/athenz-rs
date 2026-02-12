pub(in crate::policy::validator) fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut parts = Vec::new();
            for key in keys {
                let key_json = serde_json::to_string(key).unwrap_or_else(|_| format!("\"{key}\""));
                let val = canonical_json(&map[key]);
                parts.push(format!("{key_json}:{val}"));
            }
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(list) => {
            let mut parts = Vec::new();
            for item in list {
                parts.push(canonical_json(item));
            }
            format!("[{}]", parts.join(","))
        }
        serde_json::Value::String(val) => {
            serde_json::to_string(val).unwrap_or_else(|_| format!("\"{val}\""))
        }
        serde_json::Value::Number(val) => val.to_string(),
        serde_json::Value::Bool(val) => val.to_string(),
        serde_json::Value::Null => "null".to_string(),
    }
}
