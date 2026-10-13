use host_env_vault::ports::{S3Error, S3Port};

pub struct AwsS3 {
    client: aws_sdk_s3::Client,
    bucket: String,
    rt: tokio::runtime::Runtime,
}

impl AwsS3 {
    pub fn from_env(bucket: String) -> Result<Self, S3Error> {
        let rt = tokio::runtime::Runtime::new().map_err(|_| S3Error::Unavailable)?;
        let client = rt.block_on(async {
            let config = aws_config::load_from_env().await;
            aws_sdk_s3::Client::new(&config)
        });
        Ok(Self { client, bucket, rt })
    }
}

impl S3Port for AwsS3 {
    fn get_object(&self, key: &str) -> Result<Vec<u8>, S3Error> {
        use aws_sdk_s3::error::ProvideErrorMetadata;
        self.rt.block_on(async {
            let response = self
                .client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .send()
                .await;
            match response {
                Ok(output) => {
                    let bytes = output
                        .body
                        .collect()
                        .await
                        .map_err(|_| S3Error::Unavailable)?;
                    Ok(bytes.into_bytes().to_vec())
                }
                Err(err) => {
                    if err.code() == Some("NoSuchKey") {
                        Err(S3Error::NotFound(key.to_owned()))
                    } else {
                        Err(S3Error::Unavailable)
                    }
                }
            }
        })
    }
}
