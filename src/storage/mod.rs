use async_trait::async_trait;

pub mod local;
pub mod s3;

#[async_trait]
pub trait Storage {
    async fn upload(&self, filename: &str, data: &[u8]) -> Result<(), String>;
    async fn download(&self, filename: &str) -> Result<Vec<u8>, String>;
    async fn delete(&self, filename: &str) -> Result<(), String>;
    async fn list(&self) -> Result<Vec<String>, String>;
}
