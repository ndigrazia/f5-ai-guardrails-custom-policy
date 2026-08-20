// Copyright 2026 Salesforce, Inc. All rights reserved.

mod common;

use httpmock::MockServer;
use pdk_test::{pdk_test, TestComposite};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, FlexConfig, Flex, PolicyConfig};
use pdk_test::services::httpmock::{HttpMockConfig, HttpMock};

use common::*;

// Flex port for the internal test network
const FLEX_PORT: Port = 8081;

// This integration test shows how to build a test to compose a local-flex instance
// with a MockServer backend
#[pdk_test]
async fn hello() -> anyhow::Result<()> {

    // Configure an HttpMock service
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let policy_config = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(serde_json::json!({
            "externalService": "backend",
            "endpointPath": "/anything/echo",
            "secretToken": "desiredValue"
        }))
        .build();

    let api_config = ApiConfig::builder()
        .name("myApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(FLEX_PORT)
        .policies([policy_config])
        .build();

    // Configure a Flex service
    let flex_config = FlexConfig::builder()
        .version("1.10.0")
        .hostname("local-flex")
        .with_api(api_config)
        .config_mounts([
            (POLICY_DIR, "policy"),
            (COMMON_CONFIG_DIR, "common"),
        ])
        .build();

    // Compose the services
    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    // Get a handle to the Flex service
    let flex: Flex = composite.service()?;

    // Get an external URL to point the Flex service
    let flex_url = flex.external_url(FLEX_PORT).unwrap();

    // Get a handle to the HttpMock service
    let httpmock: HttpMock = composite.service()?;

    // Create a MockServer
    let mock_server = MockServer::connect_async(httpmock.socket()).await;

    // Mock the external guardrail service /anything/echo
    mock_server.mock_async(|when, then| {
        when.path_contains("/anything/echo");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(r#"{
                "result": {
                    "outcome": "allow",
                    "reason": "Passed",
                    "violations": []
                }
            }"#);
    }).await;

    // Mock a /hello request
    mock_server.mock_async(|when, then| {
        when.path_contains("/hello");
        then.status(202)
            .header("Content-Type", "application/json")
            .body(r#"{
                "choices": [
                    {
                        "message": {
                            "content": "Passed",
                            "role": "assistant"
                        }
                    }
                ]
            }"#);
    }).await;

    // Perform an actual request sending the expected request structure as a JSON body
    let client = reqwest::Client::new();
    let response = client.post(format!("{flex_url}/anything/echo/hello"))
        .header("Content-Type", "application/json")
        .body(serde_json::json!({
            "messages": [
                {
                    "content": "Que es un ADR en 10 palabras.",
                    "role": "user"
                }
            ],
            "model": "gpt-4.1"
        }).to_string())
        .send()
        .await?;

    // Assert on the response
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get("x-check_passed").unwrap().to_str().unwrap(), "true");

    Ok(())
}
