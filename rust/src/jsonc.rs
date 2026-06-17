//! JSONC parsing — JSON with comments and trailing commas.
//!
//! Supports `//` line comments, `/* ... */` block comments, and trailing
//! commas before `}`/`]`. Comment markers and commas inside string literals
//! are preserved verbatim (a naive regex would corrupt values like
//! `"mongodb://host"` or `"/* literal */"`).
//!
//! Every JSON config file Locke reads (plaintext inputs and the checked-in
//! encrypted files) is parsed through here, so authors may annotate them with
//! comments. Encrypted payloads are always written as plain JSON; decrypted
//! plaintext is parsed strictly since it is machine-generated, never authored.

use serde_json::Value;

use crate::errors::LockeError;

/// Parse JSONC text (comments + trailing commas) into a [`serde_json::Value`].
pub fn parse_jsonc(text: &str) -> Result<Value, LockeError> {
    let cleaned = strip_jsonc(text);
    Ok(serde_json::from_str(&cleaned)?)
}

/// Return `text` with comments and trailing commas removed. The result is
/// valid JSON parseable by `serde_json`.
pub fn strip_jsonc(text: &str) -> String {
    strip_trailing_commas(&strip_comments(text))
}

fn strip_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_string = false;
    while i < n {
        let ch = chars[i];
        if in_string {
            out.push(ch);
            if ch == '\\' && i + 1 < n {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if ch == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            i += 1;
            continue;
        }
        if ch == '/' && i + 1 < n && chars[i + 1] == '/' {
            i += 2;
            while i < n && chars[i] != '\n' && chars[i] != '\r' {
                i += 1;
            }
            continue;
        }
        if ch == '/' && i + 1 < n && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < n && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2; // consume the closing */
            continue;
        }
        out.push(ch);
        i += 1;
    }
    out
}

fn strip_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_string = false;
    while i < n {
        let ch = chars[i];
        if in_string {
            out.push(ch);
            if ch == '\\' && i + 1 < n {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if ch == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            i += 1;
            continue;
        }
        if ch == ',' {
            let mut j = i + 1;
            while j < n
                && (chars[j] == ' ' || chars[j] == '\t' || chars[j] == '\r' || chars[j] == '\n')
            {
                j += 1;
            }
            if j < n && (chars[j] == '}' || chars[j] == ']') {
                i += 1; // drop the trailing comma
                continue;
            }
        }
        out.push(ch);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn load_vectors() -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("test-vectors")
            .join("jsonc.json");
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_str(&contents).unwrap()
    }

    #[test]
    fn jsonc_vectors() {
        let data = load_vectors();
        for vec in data["vectors"].as_array().unwrap() {
            let name = vec["name"].as_str().unwrap();
            let input = vec["input"].as_str().unwrap();
            let expected = &vec["expected"];
            let got =
                parse_jsonc(input).unwrap_or_else(|e| panic!("vector {name}: parse failed: {e}"));
            assert_eq!(&got, expected, "vector {name}");
        }
    }

    #[test]
    fn plain_json_passthrough() {
        assert_eq!(
            parse_jsonc("{\"a\": 1}").unwrap(),
            serde_json::json!({"a": 1})
        );
    }
}
