use std::fs;

use super::Storage;

pub struct LocalStorage {
    path: String,
}

impl LocalStorage {
    pub fn new(path: &str) -> Self {
        LocalStorage {
            path: path.to_owned(),
        }
    }
}

impl Storage for LocalStorage {
    fn upload(&self, filename: &str, data: &[u8]) -> Result<(), String> {
        match fs::write(format!("{}/{}", &self.path, filename), data) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!(
                "Could not upload file {} to {} with error: {}",
                filename, self.path, e
            )),
        }
    }

    fn download(&self, filename: &str) -> Result<Vec<u8>, String> {
        match fs::read(format!("{}/{}", self.path, filename)) {
            Ok(data) => Ok(data),
            Err(e) => Err(format!(
                "Could not download file {} with error: {}",
                format!("{}/{}", self.path, filename),
                e
            )),
        }
    }

    fn delete(&self, filename: &str) -> Result<(), String> {
        match fs::remove_file(format!("{}/{}", self.path, filename)) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!(
                "Could not delete file {} with error: {}",
                format!("{}/{}", self.path, filename),
                e
            )),
        }
    }

    fn list(&self) -> Result<Vec<String>, String> {
        match fs::read_dir(&self.path) {
            Ok(file_names) => {
                let res: Vec<String> = file_names
                    .filter_map(Result::ok)
                    .filter(|entry| entry.path().is_file())
                    .map(|entry| entry.file_name().to_str().unwrap().to_owned())
                    .collect();
                Ok(res)
            }
            Err(e) => Err(format!(
                "Could not list files {} with error: {}",
                self.path, e
            )),
        }
    }
}
