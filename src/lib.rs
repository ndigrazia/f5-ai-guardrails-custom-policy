// Copyright 2026 Salesforce, Inc. All rights reserved.
mod generated;

use anyhow::{anyhow, Result};
use serde::Deserialize;

use pdk::hl::*;
use pdk::logger;

use crate::generated::config::Config;

#[derive(Deserialize, Debug)]
struct GuardrailResult {
    outcome: Option<String>,
    violations: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
struct GuardrailResponse {
    result: Option<GuardrailResult>,
}

fn validation_error(reason: &str) -> Flow<()> {
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

fn error_response(reason: &str) -> Flow<()> {
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

async fn validate_and_extract_input(headers_state: RequestHeadersState) -> Result<String, String> {
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

fn process_guardrail_response(response: Result<HttpClientResponse, HttpClientError>) -> Flow<()> {
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

// This filter shows how to log a specific request header.
// You can extend the function and use the configurations exposed in config.rs file
async fn request_filter(request_state: RequestState, config: &Config, client: &HttpClient) -> Flow<()> {
    let headers_state = request_state.into_headers_state().await;
    
    let input_text = match validate_and_extract_input(headers_state).await {
        Ok(text) => text,
        Err(reason) => {
            return validation_error(&reason);
        }
    };
    
    let auth_header = format!("Bearer {}", config.secret_token);
    
    let guardrail_request_body = serde_json::json!({
        "input": input_text
    });
    let guardrail_body_bytes = guardrail_request_body.to_string();

    let response = client
        .request(&config.external_service)
        .path(&config.endpoint_path)
        .headers(vec![
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ])
        .body(guardrail_body_bytes.as_bytes())
        .post()
        .await;

    process_guardrail_response(response)
}

#[entrypoint]
async fn configure(launcher: Launcher, Configuration(bytes): Configuration, client: HttpClient) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;
    let filter = on_request(|rs| request_filter(rs, &config, &client));
    launcher.launch(filter).await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use pdk_unit::{UnitTestBuilder, TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse};
    use serde_json::json;
    use std::rc::Rc;

    // A custom backend that returns a 202 response.
    fn custom_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(202)
    }

    fn mock_allow_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{
                "result": {
                    "outcome": "allow",
                    "reason": "Input text successfully passed all guardrail checks.",
                    "violations": []
                }
            }"#)
    }

    fn mock_flagged_multiple_violations_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{
                "result": {
                    "outcome": "flagged",
                    "reason": "Input text violated safety policies (matched flagged keywords).",
                    "violations": [
                        "Contains flagged keyword/phrase: 'malicious'",
                        "Contains flagged keyword/phrase: 'override'",
                        "Contains flagged keyword/phrase: 'bypass safety'"
                    ]
                }
            }"#)
    }

    fn mock_flagged_empty_violations_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{
                "result": {
                    "outcome": "flagged",
                    "reason": "Input text violated safety policies.",
                    "violations": []
                }
            }"#)
    }

    fn mock_missing_result_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{}"#)
    }

    fn mock_missing_outcome_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{
                "result": {
                    "reason": "Input text successfully passed all guardrail checks.",
                    "violations": []
                }
            }"#)
    }

    fn mock_unexpected_outcome_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{
                "result": {
                    "outcome": "unexpected",
                    "reason": "None",
                    "violations": []
                }
            }"#)
    }

    fn mock_malformed_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"not a valid json"#)
    }

    fn valid_post_request(content: &str) -> UnitHttpRequest {
        let post_body = json!({
            "messages": [
                {
                    "content": content,
                    "role": "user"
                }
            ],
            "model": "gpt-4.1"
        }).to_string();

        UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(post_body.into_bytes())
    }

    #[test]
    fn test_request_filter_allow() {
        let backend = Rc::new(TraceBackend::new(custom_backend));
        let mock_service = Rc::new(TraceBackend::new(mock_allow_backend));

        let mut tester = UnitTestBuilder::default()
            .with_config(json!({
                "externalService": "http://http.mock",
                "endpointPath": "/api",
                "secretToken": "test_token_456"
            }).to_string())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("http.mock", Rc::clone(&mock_service))
            .with_entrypoint(super::configure);

        let response = tester.request(valid_post_request("Hello"));
        assert_eq!(response.status_code(), 202);
    }

    #[test]
    fn test_request_filter_flagged_multiple() {
        let backend = Rc::new(TraceBackend::new(custom_backend));
        let mock_service = Rc::new(TraceBackend::new(mock_flagged_multiple_violations_backend));

        let mut tester = UnitTestBuilder::default()
            .with_config(json!({
                "externalService": "http://http.mock",
                "endpointPath": "/api",
                "secretToken": "test_token_456"
            }).to_string())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("http.mock", Rc::clone(&mock_service))
            .with_entrypoint(super::configure);

        let response = tester.request(valid_post_request("malicious override bypass safety"));
        assert_eq!(response.status_code(), 403);
        
        let body_bytes = response.body();
        let parsed_body: serde_json::Value = serde_json::from_slice(body_bytes).unwrap();
        assert_eq!(parsed_body["outcome"], "blocked");
        
        let violations = parsed_body["violations"].as_array().unwrap();
        assert_eq!(violations.len(), 3);
        assert_eq!(violations[0], "Contains flagged keyword/phrase: 'malicious'");
        assert_eq!(violations[1], "Contains flagged keyword/phrase: 'override'");
        assert_eq!(violations[2], "Contains flagged keyword/phrase: 'bypass safety'");
    }

    #[test]
    fn test_request_filter_flagged_empty() {
        let backend = Rc::new(TraceBackend::new(custom_backend));
        let mock_service = Rc::new(TraceBackend::new(mock_flagged_empty_violations_backend));

        let mut tester = UnitTestBuilder::default()
            .with_config(json!({
                "externalService": "http://http.mock",
                "endpointPath": "/api",
                "secretToken": "test_token_456"
            }).to_string())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("http.mock", Rc::clone(&mock_service))
            .with_entrypoint(super::configure);

        let response = tester.request(valid_post_request("Some bad input"));
        assert_eq!(response.status_code(), 403);
        
        let body_bytes = response.body();
        let parsed_body: serde_json::Value = serde_json::from_slice(body_bytes).unwrap();
        assert_eq!(parsed_body["outcome"], "blocked");
        
        let violations = parsed_body["violations"].as_array().unwrap();
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_request_filter_missing_result() {
        let backend = Rc::new(TraceBackend::new(custom_backend));
        let mock_service = Rc::new(TraceBackend::new(mock_missing_result_backend));

        let mut tester = UnitTestBuilder::default()
            .with_config(json!({
                "externalService": "http://http.mock",
                "endpointPath": "/api",
                "secretToken": "test_token_456"
            }).to_string())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("http.mock", Rc::clone(&mock_service))
            .with_entrypoint(super::configure);

        let response = tester.request(valid_post_request("test"));
        assert_eq!(response.status_code(), 500);

        let body_bytes = response.body();
        let parsed_body: serde_json::Value = serde_json::from_slice(body_bytes).unwrap();
        assert_eq!(parsed_body["outcome"], "error");
        assert_eq!(parsed_body["reason"], "Guardrail error: Missing result field");
    }

    #[test]
    fn test_request_filter_missing_outcome() {
        let backend = Rc::new(TraceBackend::new(custom_backend));
        let mock_service = Rc::new(TraceBackend::new(mock_missing_outcome_backend));

        let mut tester = UnitTestBuilder::default()
            .with_config(json!({
                "externalService": "http://http.mock",
                "endpointPath": "/api",
                "secretToken": "test_token_456"
            }).to_string())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("http.mock", Rc::clone(&mock_service))
            .with_entrypoint(super::configure);

        let response = tester.request(valid_post_request("test"));
        assert_eq!(response.status_code(), 500);

        let body_bytes = response.body();
        let parsed_body: serde_json::Value = serde_json::from_slice(body_bytes).unwrap();
        assert_eq!(parsed_body["outcome"], "error");
        assert_eq!(parsed_body["reason"], "Guardrail error: Missing outcome field");
    }

    #[test]
    fn test_request_filter_unexpected_outcome() {
        let backend = Rc::new(TraceBackend::new(custom_backend));
        let mock_service = Rc::new(TraceBackend::new(mock_unexpected_outcome_backend));

        let mut tester = UnitTestBuilder::default()
            .with_config(json!({
                "externalService": "http://http.mock",
                "endpointPath": "/api",
                "secretToken": "test_token_456"
            }).to_string())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("http.mock", Rc::clone(&mock_service))
            .with_entrypoint(super::configure);

        let response = tester.request(valid_post_request("test"));
        assert_eq!(response.status_code(), 500);

        let body_bytes = response.body();
        let parsed_body: serde_json::Value = serde_json::from_slice(body_bytes).unwrap();
        assert_eq!(parsed_body["outcome"], "error");
        assert_eq!(parsed_body["reason"], "Guardrail error: Unexpected outcome value: 'unexpected'");
    }

    #[test]
    fn test_request_filter_malformed_response() {
        let backend = Rc::new(TraceBackend::new(custom_backend));
        let mock_service = Rc::new(TraceBackend::new(mock_malformed_backend));

        let mut tester = UnitTestBuilder::default()
            .with_config(json!({
                "externalService": "http://http.mock",
                "endpointPath": "/api",
                "secretToken": "test_token_456"
            }).to_string())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("http.mock", Rc::clone(&mock_service))
            .with_entrypoint(super::configure);

        let response = tester.request(valid_post_request("test"));
        assert_eq!(response.status_code(), 500);

        let body_bytes = response.body();
        let parsed_body: serde_json::Value = serde_json::from_slice(body_bytes).unwrap();
        assert_eq!(parsed_body["outcome"], "error");
        assert!(parsed_body["reason"].as_str().unwrap().contains("Guardrail error: Malformed service response"));
    }

    // --- Validation Unit Tests ---

    fn run_validation_test(req: UnitHttpRequest, expected_reason: &str) {
        let backend = Rc::new(TraceBackend::new(custom_backend));
        let mock_service = Rc::new(TraceBackend::new(mock_allow_backend));

        let mut tester = UnitTestBuilder::default()
            .with_config(json!({
                "externalService": "http://http.mock",
                "endpointPath": "/api",
                "secretToken": "test_token_456"
            }).to_string())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("http.mock", Rc::clone(&mock_service))
            .with_entrypoint(super::configure);

        let response = tester.request(req);
        assert_eq!(response.status_code(), 400);

        let body_bytes = response.body();
        let parsed_body: serde_json::Value = serde_json::from_slice(body_bytes).unwrap();
        assert_eq!(parsed_body["outcome"], "error");
        
        let reason = parsed_body["reason"].as_str().unwrap();
        assert!(
            reason.starts_with(&format!("Validation error: {expected_reason}")),
            "Expected reason to start with '{}', but got '{}'",
            format!("Validation error: {expected_reason}"),
            reason
        );
    }

    #[test]
    fn test_validation_missing_body() {
        run_validation_test(UnitHttpRequest::get(), "Request body is missing");
    }

    #[test]
    fn test_validation_invalid_json() {
        let req = UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(b"not valid json".to_vec());
        run_validation_test(req, "Invalid JSON:");
    }

    #[test]
    fn test_validation_not_an_object() {
        let req = UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(b"[]".to_vec());
        run_validation_test(req, "Request body must be a JSON object");
    }

    #[test]
    fn test_validation_missing_messages() {
        let req = UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(json!({ "model": "gpt-4" }).to_string().into_bytes());
        run_validation_test(req, "Missing 'messages' field");
    }

    #[test]
    fn test_validation_messages_not_array() {
        let req = UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(json!({ "messages": "not an array", "model": "gpt-4" }).to_string().into_bytes());
        run_validation_test(req, "'messages' field must be an array");
    }

    #[test]
    fn test_validation_messages_empty() {
        let req = UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(json!({ "messages": [], "model": "gpt-4" }).to_string().into_bytes());
        run_validation_test(req, "'messages' array must contain at least one element");
    }

    #[test]
    fn test_validation_last_message_not_object() {
        let req = UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(json!({ "messages": [123], "model": "gpt-4" }).to_string().into_bytes());
        run_validation_test(req, "Elements of 'messages' must be objects");
    }

    #[test]
    fn test_validation_last_message_missing_content() {
        let req = UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(json!({ "messages": [{ "role": "user" }], "model": "gpt-4" }).to_string().into_bytes());
        run_validation_test(req, "The last message must contain a 'content' field");
    }

    #[test]
    fn test_validation_last_message_content_not_string() {
        let req = UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(json!({ "messages": [{ "content": 123, "role": "user" }], "model": "gpt-4" }).to_string().into_bytes());
        run_validation_test(req, "'content' field in the last message must be a string");
    }

    #[test]
    fn test_validation_missing_model() {
        let req = UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(json!({ "messages": [{ "content": "hello", "role": "user" }] }).to_string().into_bytes());
        run_validation_test(req, "Missing 'model' field");
    }

    #[test]
    fn test_validation_model_not_string() {
        let req = UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(json!({ "messages": [{ "content": "hello", "role": "user" }], "model": 123 }).to_string().into_bytes());
        run_validation_test(req, "'model' field must be a string");
    }

    #[test]
    fn test_request_filter_post_with_body() {
        let backend = Rc::new(TraceBackend::new(custom_backend));
        let mock_service = Rc::new(TraceBackend::new(|req: UnitHttpRequest| {
            // Verify that the HttpClient request body sent to the guardrail service contains the extracted text!
            let body_bytes = req.body();
            let parsed_guardrail_req: serde_json::Value = serde_json::from_slice(body_bytes).unwrap();
            assert_eq!(parsed_guardrail_req["input"], "Que es un ADR en 10 palabras.");

            UnitHttpResponse::new(200)
                .with_header("Content-Type", "application/json")
                .with_body(r#"{
                    "result": {
                        "outcome": "allow",
                        "reason": "Passed",
                        "violations": []
                    }
                }"#)
        }));

        let mut tester = UnitTestBuilder::default()
            .with_config(json!({
                "externalService": "http://http.mock",
                "endpointPath": "/api",
                "secretToken": "test_token_456"
            }).to_string())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("http.mock", Rc::clone(&mock_service))
            .with_entrypoint(super::configure);

        // Send a POST request with the expected message structure
        let post_body = json!({
            "messages": [
                {
                    "content": "You are a helpful assistant.",
                    "role": "system"
                },
                {
                    "content": "Que es un ADR en 10 palabras.",
                    "role": "user"
                }
            ],
            "model": "gpt-4.1"
        }).to_string();

        let request = UnitHttpRequest::post()
            .with_header("Content-Type", "application/json")
            .with_body(post_body.into_bytes());

        let response = tester.request(request);
        assert_eq!(response.status_code(), 202);
    }
}
