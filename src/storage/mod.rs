use async_trait::async_trait;
use std::collections::HashSet;

pub mod local;
pub mod s3;

#[async_trait]
pub trait Storage {
    async fn upload(&self, plaintext_filename: &str, data: &[u8]) -> eyre::Result<()>;
    async fn download(&self, plaintext_filename: &str) -> eyre::Result<Vec<u8>>;
    async fn delete(&self, plaintext_filename: &str) -> eyre::Result<()>;
    async fn batch_delete(&self, filenames: HashSet<String>) -> eyre::Result<()>;
}
