pub mod local;
pub mod s3;

pub trait Storage {
    fn upload(&self, filename: &str, data: &[u8]) -> Result<(), String>;
    fn download(&self, filename: &str) -> Result<Vec<u8>, String>;
    fn delete(&self, filename: &str) -> Result<(), String>;
    fn list(&self) -> Result<Vec<String>, String>;
}
