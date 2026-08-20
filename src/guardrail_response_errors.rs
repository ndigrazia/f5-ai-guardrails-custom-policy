// Copyright 2026 Salesforce, Inc. All rights reserved.

use pdk::hl::HeadersBodyHandler;

pub fn send_response_guardrail_error(
    handler: &dyn HeadersBodyHandler,
    is_flagged: bool,
    error_message: Option<String>,
    violations: Option<Vec<String>>,
) {
    
      if is_flagged {
                handler.set_header("Content-Type", "application/json");
                handler.set_header(":status", "403");

                let error_body = serde_json::json!({
                    "outcome": "blocked",
                    "reason": error_message.unwrap_or_else(|| "Input text violated safety policies.".to_string()),
                    "violations": violations.unwrap_or_default()
                });
                let error_bytes = error_body.to_string().into_bytes();
                handler.set_header("Content-Length", &error_bytes.len().to_string());
                let _ = handler.set_body(&error_bytes);
            } else {
                handler.set_header("Content-Type", "application/json");
                handler.set_header(":status", "500");

                let error_body = serde_json::json!({
                    "outcome": "error",
                    "reason": format!("Guardrail error: {}", error_message.unwrap_or_else(|| "Unknown error".to_string()))
                });
                let error_bytes = error_body.to_string().into_bytes();
                handler.set_header("Content-Length", &error_bytes.len().to_string());
                let _ = handler.set_body(&error_bytes);
            }
}

pub fn send_response_validate_content_error(
    handler: &dyn HeadersBodyHandler,
    error_message: Option<String>
) {
    handler.set_header("Content-Type", "application/json");
    handler.set_header(":status", "500");

    let error_body = serde_json::json!({
        "outcome": "error",
        "reason": format!("Guardrail error: {}", error_message.unwrap_or_else(|| "Unknown error".to_string()))
    });
    let error_bytes = error_body.to_string().into_bytes();
    handler.set_header("Content-Length", &error_bytes.len().to_string());
    let _ = handler.set_body(&error_bytes);
}