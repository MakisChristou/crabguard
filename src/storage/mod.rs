pub mod local;
pub mod s3;

pub trait Storage {
    fn upload(&self, path: &str, data: &[u8]) -> Result<(), String>;
    fn download(&self, path: &str) -> Result<Vec<u8>, String>;
    fn delete(&self, path: &str) -> Result<(), String>;
    fn list(&self) -> Result<Vec<String>, String>;
}
