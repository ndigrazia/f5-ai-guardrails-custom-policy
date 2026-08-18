use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "continueOnF5Failure")]
    pub continue_on_f_5_failure: bool,
    #[serde(alias = "endpointPath")]
    pub endpoint_path: String,
    #[serde(alias = "evaluateResponseWithF5")]
    pub evaluate_response_with_f_5: bool,
    #[serde(
        alias = "externalService",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub external_service: pdk::hl::Service,
    #[serde(alias = "secretToken")]
    pub secret_token: String,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(abi.get_configuration()), err
            )
        })?;
    abi.service_create(config.external_service)?;
    abi.setup()?;
    Ok(())
}
