// Copyright 2026 Salesforce, Inc. All rights reserved.

use anyhow::Result;
use pdk::hl::*;
use pdk::logger;

use crate::errors::error_response;
use crate::types::GuardrailResponse;

pub async fn validate_and_extract_input(headers_state: RequestHeadersState) -> Result<String, String> {
    if !headers_state.contains_body() {
        return Err("Request body is missing".to_string());
    }

    let body_state = headers_state.into_body_state().await;
    let body_bytes = body_state.handler().body();
    logger::info!("Request body: {}", String::from_utf8_lossy(&body_bytes));

    let json_val: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("Invalid JSON: {err}"));
        }
    };

    // 1. Check if the body is an object
    let body_obj = match json_val.as_object() {
        Some(obj) => obj,
        None => {
            return Err("Request body must be a JSON object".to_string());
        }
    };

    // 2. Check if messages exists and is an array
    let messages_val = match body_obj.get("messages") {
        Some(m) => m,
        None => {
            return Err("Missing 'messages' field".to_string());
        }
    };
    let messages_arr = match messages_val.as_array() {
        Some(arr) => arr,
        None => {
            return Err("'messages' field must be an array".to_string());
        }
    };

    // 3. Check if messages contains at least one element
    if messages_arr.is_empty() {
        return Err("'messages' array must contain at least one element".to_string());
    }

    // 4. Check if the last element of messages contains a content field
    let last_element = messages_arr.last().unwrap();
    let last_obj = match last_element.as_object() {
        Some(obj) => obj,
        None => {
            return Err("Elements of 'messages' must be objects".to_string());
        }
    };
    let content_val = match last_obj.get("content") {
        Some(c) => c,
        None => {
            return Err("The last message must contain a 'content' field".to_string());
        }
    };

    // 5. Check if the content field is a string
    let input_text = match content_val.as_str() {
        Some(s) => s.to_string(),
        None => {
            return Err("'content' field in the last message must be a string".to_string());
        }
    };

    // 6. Check if model exists and is a string
    let model_val = match body_obj.get("model") {
        Some(m) => m,
        None => {
            return Err("Missing 'model' field".to_string());
        }
    };
    if !model_val.is_string() {
        return Err("'model' field must be a string".to_string());
    }

    Ok(input_text)
}

pub fn process_guardrail_response(response: Result<HttpClientResponse, HttpClientError>) -> Flow<()> {
    match response {
        Ok(res) => {
            logger::info!("External request succeeded with status: {}", res.status_code());
            let body_bytes = res.body();
            
            // Safely parse the JSON response
            let guardrail_res: Result<GuardrailResponse, _> = serde_json::from_slice(body_bytes);
            match guardrail_res {
                Ok(guardrail_response) => {
                    if let Some(result) = guardrail_response.result {
                        if let Some(outcome) = result.outcome {
                            match outcome.as_str() {
                                "allow" => {
                                    logger::info!("Guardrail check passed: request allowed.");
                                    Flow::Continue(())
                                }
                                "flagged" => {
                                    let violations = result.violations.unwrap_or_default();
                                    logger::warn!("Guardrail check failed: request flagged with violations: {:?}", violations);
                                    
                                    let response_body = serde_json::json!({
                                        "outcome": "blocked",
                                        "reason": "Request blocked by safety policy.",
                                        "violations": violations
                                    });
                                    let body_string = response_body.to_string();
                                    let blocked_response = Response::new(403)
                                        .with_headers(vec![("Content-Type".to_string(), "application/json".to_string())])
                                        .with_body(body_string.into_bytes());
                                    
                                    Flow::Break(blocked_response)
                                }
                                unexpected => {
                                    logger::error!("Guardrail returned unexpected outcome value: '{}'", unexpected);
                                    error_response(&format!("Unexpected outcome value: '{unexpected}'"))
                                }
                            }
                        } else {
                            logger::error!("Guardrail response missing outcome field.");
                            error_response("Missing outcome field")
                        }
                    } else {
                        logger::error!("Guardrail response missing result field.");
                        error_response("Missing result field")
                    }
                }
                Err(err) => {
                    logger::error!("Failed to parse guardrail response as JSON: {:?}", err);
                    error_response(&format!("Malformed service response: {err:?}"))
                }
            }
        }
        Err(err) => {
            logger::error!("External request to guardrail service failed: {:?}", err);
            error_response(&format!("External request failed: {err:?}"))
        }
    }
}
