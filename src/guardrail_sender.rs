// Copyright 2026 Salesforce, Inc. All rights reserved.

use pdk::hl::*;
use crate::generated::config::Config;

pub async fn send_guardrail_request(
    client: &HttpClient,
    config: &Config,
    input_text: &str,
) -> Result<HttpClientResponse, HttpClientError> {
    let auth_header = format!("Bearer {}", config.secret_token);
    
    let guardrail_request_body = serde_json::json!({
        "input": input_text
    });
    let guardrail_body_bytes = guardrail_request_body.to_string();

    client
        .request(&config.external_service)
        .path(&config.endpoint_path)
        .headers(vec![
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ])
        .body(guardrail_body_bytes.as_bytes())
        .post()
        .await
}
