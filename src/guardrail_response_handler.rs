// Copyright 2026 Salesforce, Inc. All rights reserved.
use anyhow::Result;
use pdk::hl::*;
use pdk::logger;
use crate::types::GuardrailResponse;

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

    if content_str.is_empty() {
        return (false, None, Some("Content is an empty string".to_string()));
    }

    (true, Some(content_str), None)
}

pub fn handle_guardrail_response(
    response: Result<HttpClientResponse, HttpClientError>,
    continue_on_f_5_failure: bool,
) -> (bool, bool, Option<String>, Option<Vec<String>>) {
    let res = match response {
        Ok(res) => res,
        Err(err) => {
            logger::error!("External request to guardrail service failed: {:?}", err);
            return if continue_on_f_5_failure {
                (true, false, None, None)
            } else {
                (false, false, Some("External request failed".to_string()), None)
            };
        }
    };

    logger::info!("External request succeeded with status: {}", res.status_code());
    
    let guardrail_response: GuardrailResponse = match serde_json::from_slice(res.body()) {
        Ok(v) => v,
        Err(err) => {
            logger::error!("Failed to parse guardrail response as JSON: {:?}", err);
            return if continue_on_f_5_failure {
                (true, false, None, None)
            } else {
                (false, false, Some("Malformed service response".to_string()), None)
            };
        }
    };

    let result = match guardrail_response.result {
        Some(r) => r,
        None => {
            logger::error!("Guardrail response missing result field.");
            return if continue_on_f_5_failure {
                (true, false, None, None)
            } else {
                (false, false, Some("Missing result field".to_string()), None)
            };
        }
    };

    let outcome = match result.outcome {
        Some(o) => o,
        None => {
            logger::error!("Guardrail response missing outcome field.");
            return if continue_on_f_5_failure {
                (true, false, None, None)
            } else {
                (false, false, Some("Missing outcome field".to_string()), None)
            };
        }
    };

    match outcome.as_str() {
        "allow" => {
            logger::info!("Guardrail check passed: request allowed.");
            (true, false, None, None)
        }
        "flagged" => {
            let violations = result.violations.unwrap_or_default();
            logger::warn!("Guardrail check failed: request flagged with violations: {:?}", violations);
            (false, true, Some("Request blocked by safety policy.".to_string()), Some(violations))
        }
        unexpected => {
            logger::error!("Guardrail returned unexpected outcome value: '{}'", unexpected);
            if continue_on_f_5_failure {
                logger::info!("Error ignored: continue_on_f_5_failure is true.");
                (true, false, None, None)
            } else {
                (false, false, Some("Unexpected outcome value".to_string()), None)
            }
        }
    }
}
