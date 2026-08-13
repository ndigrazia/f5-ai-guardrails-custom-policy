// Copyright 2026 Salesforce, Inc. All rights reserved.

use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct GuardrailResult {
    pub outcome: Option<String>,
    pub violations: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
pub struct GuardrailResponse {
    pub result: Option<GuardrailResult>,
}
