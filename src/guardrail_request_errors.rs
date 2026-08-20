// Copyright 2026 Salesforce, Inc. All rights reserved.

use pdk::hl::{Flow, Response};

pub fn validation_error(reason: &str) -> Flow<()> {
    let response_body = serde_json::json!({
        "outcome": "error",
        "reason": format!("Validation error: {reason}")
    });
    let body_string = response_body.to_string();
    let blocked_response = Response::new(400)
        .with_headers(vec![("Content-Type".to_string(), "application/json".to_string())])
        .with_body(body_string.into_bytes());
    
    Flow::Break(blocked_response)
}

pub fn error_response(reason: &str) -> Flow<()> {
    let response_body = serde_json::json!({
        "outcome": "error",
        "reason": format!("Guardrail error: {reason}")
    });
    let body_string = response_body.to_string();
    let blocked_response = Response::new(500)
        .with_headers(vec![("Content-Type".to_string(), "application/json".to_string())])
        .with_body(body_string.into_bytes());
    
    Flow::Break(blocked_response)
}
