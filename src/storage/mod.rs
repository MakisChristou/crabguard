use std::collections::HashSet;

use async_trait::async_trait;

pub mod local;
pub mod s3;

#[async_trait]
pub trait Storage {
    async fn upload(&self, plaintext_filename: &str, data: &[u8]) -> Result<(), String>;
    async fn download(&self, plaintext_filename: &str) -> Result<Vec<u8>, String>;
    async fn delete(&self, plaintext_filename: &str) -> Result<(), String>;
    async fn batch_delete(&self, filenames: HashSet<String>) -> Result<(), String>;
    async fn list(&self) -> Result<Vec<String>, String>;
    async fn size_of(&self, encrypted_filenames: HashSet<String>) -> Result<i64, String>;
}
