use std::{collections::HashSet, fs};

use super::Storage;
use async_trait::async_trait;

#[derive(Clone)]
pub struct LocalStorage {
    path: String,
}

#[allow(dead_code)]
impl LocalStorage {
    pub fn new(path: &str) -> Self {
        LocalStorage {
            path: path.to_owned(),
        }
    }
}

#[async_trait]
impl Storage for LocalStorage {
    async fn upload(&self, filename: &str, data: &[u8]) -> Result<(), String> {
        match fs::write(format!("{}/{}", &self.path, filename), data) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!(
                "Could not upload file {} to {} with error: {}",
                filename, self.path, e
            )),
        }
    }

    async fn download(&self, filename: &str) -> Result<Vec<u8>, String> {
        match fs::read(format!("{}/{}", self.path, filename)) {
            Ok(data) => Ok(data),
            Err(e) => Err(format!(
                "Could not download file {} with error: {}",
                filename, e
            )),
        }
    }

    async fn delete(&self, filename: &str) -> Result<(), String> {
        match fs::remove_file(format!("{}/{}", self.path, filename)) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!(
                "Could not delete file {} with error: {}",
                filename, e
            )),
        }
    }

    async fn batch_delete(&self, _filenames: HashSet<String>) -> Result<(), String> {
        todo!()
    }
}
