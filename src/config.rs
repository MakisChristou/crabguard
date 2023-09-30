use crate::utils;

#[derive(Clone)]
pub struct Config {
    pub key_bytes: Vec<u8>,
    pub aws_region_name: String,
    pub aws_endpoint: String,
    pub aws_bucket_name: String,
}

impl Config {
    pub fn from_env() -> Config {
        let key_bytes = utils::get_key_from_env_or_generate_new();
        let aws_region_name = utils::get_aws_region_name_from_env();
        let aws_endpoint = utils::get_aws_endpoint_from_env();
        let aws_bucket_name = utils::get_aws_bucket_name_from_env();

        Config {
            key_bytes,
            aws_region_name,
            aws_endpoint,
            aws_bucket_name,
        }
    }
}
