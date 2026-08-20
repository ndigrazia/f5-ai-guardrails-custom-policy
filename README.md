# F5 AI Guardrails Custom Policy

A custom policy for [MuleSoft Flex Gateway](https://docs.mulesoft.com/gateway/) built with the [Policy Development Kit (PDK)](https://docs.mulesoft.com/pdk/latest/). 

This policy acts as an AI safety and guardrail gateway. It intercepts incoming client requests destined for an LLM/AI model, validates the payload structure, extracts the user prompt, sends it to an external guardrail scanning service, and decides whether to block or allow the request based on the guardrail outcome.

---

## Features

- **Robust Input Validation**: Ensures client requests follow a valid JSON format, containing a non-empty `messages` array and a `model` specification.
- **Smart Input Extraction**: Dynamically parses the last user message from the `messages` array to extract the prompt/content.
- **External Scanning**: Relays the extracted prompt via HTTP to an external security/guardrail scanning service with custom endpoints and authentication.
- **Enforced Security (Fail-Closed)**: Rejects dangerous requests with a `403 Forbidden` response detailing the safety violations, while gracefully routing compliant prompts upstream with a `202`/`200` status.
- **Response Logging**: Safely intercepts and extracts response bodies asynchronously to log target backend responses.
- **Bodyless Response Guard**: Throws a `500 Internal Server Error` exception if the target downstream response does not contain a body, preventing bypasses or communication issues.
- **Configurable Fail-Safe Mode**: Exposes a customizable fallback option (`continueOnF5Failure`) that lets operators select between secure fail-closed (default) and robust fail-open behaviors during scanning service outages.
- **Detailed Error Propagation**: Standardizes bad request formats into `400 Bad Request` and integration/runtime errors into `500 Internal Server Error` responses.

---

## Project Structure

The project has been refactored into a clean, modular structure:

```
.
├── definition/gcl.yaml                     # Policy schema definition (properties & defaults)
├── src/
│   ├── lib.rs                              # Entrypoint & main request filter execution
│   ├── guardrail_request_handler.rs       # Request-side validation and scanning logic
│   ├── guardrail_response_handler.rs      # Response-side validation and extraction logic
│   ├── guardrail_sender.rs                # Outbound guardrail scanning request client sender
│   ├── guardrail_request_errors.rs        # Standardized request JSON error formatting (400, 500)
│   ├── guardrail_response_errors.rs       # Standardized response JSON error formatting (403, 500)
│   ├── types.rs                            # Strongly typed structures for guardrail JSON responses
│   └── generated/
│       └── config.rs                       # Auto-generated Rust struct representing gcl.yaml properties
├── tests/
│   ├── requests.rs                         # Integration tests running with real Flex Gateway in Docker
│   └── common/mod.rs                       # Shared test helpers
├── playground/                             # Docker-compose playground setup for manual local testing
│   ├── docker-compose.yaml
│   └── config/
│       ├── api.yaml                        # Configuration for applying the custom policy locally
│       └── logging.yaml
├── Cargo.toml                              # Dependency definitions
└── Makefile                                # Task automation runner
```

---

## Configuration Properties

Configure the policy inside your API Instance spec or Anypoint Exchange Manager. The schema is declared in `definition/gcl.yaml`:

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| **`externalService`** | `string` | *Required* | The name of the external HTTP Service (gateway destination address) representing the guardrail scanner. |
| **`endpointPath`** | `string` | `/backend/v1/scans` | The endpoint path of the guardrail scanning API. |
| **`secretToken`** | `string` | `my_secret_token_123` | Sensitive authorization/bearer token used to authenticate against the guardrail service. |
| **`continueOnF5Failure`** | `boolean` | `false` (*Required*) | If `true`, request will fail-open and proceed upstream even if the external guardrail scanning service is unreachable, timed out, or returns an error. If `false`, rejects the request with a `500` error response (fail-closed). |
| **`evaluateResponseWithF5`** | `boolean` | `true` (*Required*) | If `true`, the target downstream response will be evaluated using the F5 AI Guardrails service. If `false`, response body evaluation and exceptions are bypassed. |

---

## Payload and Response Formats

### 1. Expected Client Request (LLM Payload)
The policy expects a standard chat-completion-like JSON POST request:
```json
{
  "messages": [
    { "role": "system", "content": "You are a helpful assistant." },
    { "role": "user", "content": "Hello, how do I build a secure API?" }
  ],
  "model": "gpt-4.1"
}
```

### 2. Payload Sent to Guardrail Service
The policy extracts the content from the last user message and sends it to the guardrail endpoint:
```json
{
  "input": "Hello, how do I build a secure API?"
}
```
*HTTP Header sent:* `Authorization: Bearer <secretToken>`

### 3. Expected Guardrail Response
The scanning service must return a JSON response with an `outcome` indicator:
- **Allow Outcome:**
  ```json
  {
    "result": {
      "outcome": "allow",
      "reason": "Text is safe.",
      "violations": []
    }
  }
  ```
- **Flagged Outcome:**
  ```json
  {
    "result": {
      "outcome": "flagged",
      "reason": "Contains forbidden patterns.",
      "violations": ["Matched flagged phrase: 'how to bypass safety'"]
    }
  }
  ```

### 4. Policy Actions & Responses
- **Allowed:** The proxy-wasm filter returns `Flow::Continue(())` letting the request route to your upstream LLM API.
- **Blocked (403 Forbidden):** Returns a clean JSON block response:
  ```json
  {
    "outcome": "blocked",
    "reason": "Request blocked by safety policy.",
    "violations": ["Matched flagged phrase: 'how to bypass safety'"]
  }
  ```
- **Validation Error (400 Bad Request):** If the input payload format is incorrect:
  ```json
  {
    "outcome": "error",
    "reason": "Validation error: Missing 'messages' field"
  }
  ```
- **Guardrail Service Error (500 Internal Server Error):** If the external call fails, times out, or returns a malformed response:
  ```json
  {
    "outcome": "error",
    "reason": "Guardrail error: External request failed: ..."
  }
  ```

---

## Make Command Reference

Automate development, compilation, testing, and deployment tasks using the provided `Makefile`.

### Setup
Installs PDK internal dependencies and setup the build environment.
```bash
make setup
```

### Build Wasm Binary
Compiles the policy into a WebAssembly binary targets `wasm32-wasip1`. This automatically runs `make build-asset-files` to sync configuration changes made to `definition/gcl.yaml` into Rust source configurations.
```bash
make build
```

### Run Tests
Executes the comprehensive suite of unit tests.
```bash
make test
# Or run with cargo directly:
cargo test --lib
```

### Play & Debug (Playground)
Spins up a local containerized Flex Gateway instance and a sample mock backend. Edit the mock config in `playground/config/api.yaml` to experiment.
```bash
make run
```

---

## proxy-wasm Runtime Constraints

Since this policy compiles to WebAssembly and runs single-threaded inside the proxy-wasm architecture of MuleSoft Flex Gateway, observe the following rules:
- **No Blocking I/O**: Do not block the executing thread; utilize PDK's non-blocking `async`/`await` HTTP clients.
- **No Multithreading**: Avoid thread synchronization primitives like `Arc`, `Mutex`, or `RwLock`.
- **Case-Insensitive Headers**: Always normalize and compare header keys in lowercase.
- **Fail-Safe Design**: Ensure that external connection issues, timeouts, or unexpected service codes default to blocking (fail-closed) to prevent security holes.
