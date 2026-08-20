// Copyright 2026 Salesforce, Inc. All rights reserved.

pub fn validate_and_extract_content(body: &[u8]) -> (bool, Option<String>, Option<String>) {
    if body.is_empty() {
        return (false, None, Some("Response body is empty".to_string()));
    }
    
    let json_val = match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(val) => val,
        Err(err) => return (false, None, Some(format!("Invalid JSON: {}", err))),
    };

    let choices = match json_val.get("choices").and_then(|c| c.as_array()) {
        Some(c) => c,
        None => return (false, None, Some("Missing or invalid 'choices' field".to_string())),
    };

    let choice0 = match choices.get(0) {
        Some(c) => c,
        None => return (false, None, Some("'choices' array is empty".to_string())),
    };

    let message = match choice0.get("message").and_then(|m| m.as_object()) {
        Some(m) => m,
        None => return (false, None, Some("Missing or invalid 'message' field".to_string())),
    };

    let content = match message.get("content") {
        Some(c) => c,
        None => return (false, None, Some("Missing 'content' field".to_string())),
    };

    let content_str = match content {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };

    (true, Some(content_str), None)
}
