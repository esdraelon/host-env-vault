use host_env_vault::ports::{SsmError, SsmPort};

pub struct AwsSsm {
    client: aws_sdk_ssm::Client,
    rt: tokio::runtime::Runtime,
}

impl AwsSsm {
    pub fn from_env() -> Result<Self, SsmError> {
        let rt = tokio::runtime::Runtime::new().map_err(|_| SsmError::Unavailable)?;
        let client = rt.block_on(async {
            let config = aws_config::load_from_env().await;
            aws_sdk_ssm::Client::new(&config)
        });
        Ok(Self { client, rt })
    }
}

impl SsmPort for AwsSsm {
    fn get_parameter(&self, name: &str) -> Result<String, SsmError> {
        use aws_sdk_ssm::error::ProvideErrorMetadata;
        self.rt.block_on(async {
            let response = self
                .client
                .get_parameter()
                .name(name)
                .with_decryption(true)
                .send()
                .await;
            match response {
                Ok(output) => output
                    .parameter()
                    .and_then(|parameter| parameter.value())
                    .map(|value| value.to_owned())
                    .ok_or_else(|| SsmError::NotFound(name.to_owned())),
                Err(err) => {
                    if err.code() == Some("ParameterNotFound") {
                        Err(SsmError::NotFound(name.to_owned()))
                    } else {
                        Err(SsmError::Unavailable)
                    }
                }
            }
        })
    }
}
