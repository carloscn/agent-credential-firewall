//! Default-deny response projection.
//!
//! Only fields named by the profile's `response.fields` survive. Arrays are
//! traversed element by element, so `result.id` keeps the `id` of every
//! element of `result`.

use acf_config::FieldPath;
use serde_json::{Map, Value};

/// Returns a copy of `value` containing only the allowlisted `fields`.
/// The result is always an object; nothing allowlisted gives `{}`.
#[must_use]
pub fn project(value: &Value, fields: &[FieldPath]) -> Value {
    let paths: Vec<Vec<&str>> = fields.iter().map(|f| f.segments().collect()).collect();
    let refs: Vec<&[&str]> = paths.iter().map(Vec::as_slice).collect();
    match project_paths(value, &refs) {
        Some(projected @ Value::Object(_)) => projected,
        _ => Value::Object(Map::new()),
    }
}

fn project_paths(value: &Value, paths: &[&[&str]]) -> Option<Value> {
    if paths.iter().any(|p| p.is_empty()) {
        return Some(value.clone());
    }
    match value {
        Value::Object(object) => {
            let mut out = Map::new();
            for (key, child) in object {
                let sub: Vec<&[&str]> = paths
                    .iter()
                    .filter(|p| p.first() == Some(&key.as_str()))
                    .map(|p| &p[1..])
                    .collect();
                if !sub.is_empty()
                    && let Some(projected) = project_paths(child, &sub)
                {
                    out.insert(key.clone(), projected);
                }
            }
            Some(Value::Object(out))
        }
        Value::Array(items) => Some(Value::Array(
            items
                .iter()
                .filter_map(|item| project_paths(item, paths))
                .collect(),
        )),
        // A scalar cannot contain the remaining path.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fields(names: &[&str]) -> Vec<FieldPath> {
        names.iter().map(|n| FieldPath::new(n).unwrap()).collect()
    }

    #[test]
    fn keeps_only_allowlisted_fields() {
        let upstream = json!({
            "success": true,
            "errors": [],
            "result": [
                { "id": "r1", "name": "api.example.com", "secret_meta": "x" },
                { "id": "r2", "name": "www.example.com", "secret_meta": "y" }
            ],
            "debug": { "authorization": "Bearer leaked" }
        });
        assert_eq!(
            project(
                &upstream,
                &fields(&["success", "errors", "result.id", "result.name"])
            ),
            json!({
                "success": true,
                "errors": [],
                "result": [
                    { "id": "r1", "name": "api.example.com" },
                    { "id": "r2", "name": "www.example.com" }
                ]
            })
        );
    }

    #[test]
    fn empty_allowlist_or_non_object_gives_empty_object() {
        assert_eq!(project(&json!({ "a": 1 }), &[]), json!({}));
        assert_eq!(project(&json!("text"), &fields(&["a"])), json!({}));
        assert_eq!(
            project(&json!({ "a": "scalar" }), &fields(&["a.b"])),
            json!({})
        );
    }
}
