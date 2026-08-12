use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "endpointPath")]
    pub endpoint_path: Option<String>,
    #[serde(
        alias = "externalService",
        default,
        deserialize_with = "pdk::serde::deserialize_service_opt"
    )]
    pub external_service: Option<pdk::hl::Service>,
    #[serde(alias = "stringProperty")]
    pub string_property: String,
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
    if config.external_service.is_some() {
        let service = config.external_service.unwrap();
        abi.service_create(service)?;
    }
    abi.setup()?;
    Ok(())
}
