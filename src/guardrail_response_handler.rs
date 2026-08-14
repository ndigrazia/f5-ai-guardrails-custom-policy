// Copyright 2026 Salesforce, Inc. All rights reserved.

use pdk::logger;

pub fn process_response_body(body_bytes: &[u8]) {
    logger::info!("Response body to be processed: {}", String::from_utf8_lossy(body_bytes));
}
