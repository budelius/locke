//! Config flattening — nested JSON to SCREAMING_SNAKE_CASE key-value pairs.

use std::collections::BTreeMap;

use crate::errors::LockeError;

pub fn flatten_config(
    config: &serde_json::Value,
) -> Result<BTreeMap<String, String>, LockeError> {
    let obj = config
        .as_object()
        .ok_or_else(|| LockeError::InvalidConfig("expected JSON object".into()))?;

    let mut result = BTreeMap::new();
    let mut sources: BTreeMap<String, String> = BTreeMap::new();

    flatten_recursive(obj, "", "", &mut result, &mut sources)?;

    Ok(result) // BTreeMap is already sorted
}

fn flatten_recursive(
    obj: &serde_json::Map<String, serde_json::Value>,
    prefix: &str,
    path: &str,
    result: &mut BTreeMap<String, String>,
    sources: &mut BTreeMap<String, String>,
) -> Result<(), LockeError> {
    for (key, value) in obj {
        let flat_key = if prefix.is_empty() {
            key.to_uppercase()
        } else {
            format!("{}_{}", prefix, key).to_uppercase()
        };

        let source_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{}.{}", path, key)
        };

        if let Some(nested) = value.as_object() {
            flatten_recursive(nested, &flat_key, &source_path, result, sources)?;
        } else {
            if let Some(existing_path) = sources.get(&flat_key) {
                return Err(LockeError::Collision {
                    key: flat_key,
                    path_a: existing_path.clone(),
                    path_b: source_path,
                });
            }
            let str_value = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => if *b { "True" } else { "False" }.to_string(),
                serde_json::Value::Null => "null".to_string(),
                _ => value.to_string(),
            };
            result.insert(flat_key.clone(), str_value);
            sources.insert(flat_key, source_path);
        }
    }
    Ok(())
}
