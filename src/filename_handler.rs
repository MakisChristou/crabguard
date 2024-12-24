use ring::{aead::NONCE_LEN, error::Unspecified};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};

use crate::{
    crypto::{self, CounterNonceSequence},
    storage::Storage,
    utils::HASHMAP_NAME,
};

#[derive(Serialize, Deserialize, Debug)]
struct Data {
    filenames: HashMap<String, Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileNameEntry {
    pub name_blob: Vec<u8>,
    pub size: usize,
}

impl FileNameEntry {
    pub fn new(name_blob: Vec<u8>, size: usize) -> Self {
        FileNameEntry { name_blob, size }
    }
}

pub struct FileNameHandler {
    storage: Rc<dyn Storage>,
    filenames: HashMap<String, FileNameEntry>,
}

impl FileNameHandler {
    pub async fn new(storage: Rc<dyn Storage>) -> Self {
        let filenames = FileNameHandler::get_filenames_from_storage(Rc::clone(&storage)).await;
        FileNameHandler { storage, filenames }
    }

    pub async fn add_name_to_hashmap(
        &mut self,
        plaintext_filename: &str,
        key_bytes: Vec<u8>,
        data_len: usize,
    ) -> eyre::Result<()> {
        let hashed_filename = hex::encode(Sha256::digest(plaintext_filename)).to_string();

        let name_blob =
            crypto::encrypt_blob(plaintext_filename.try_into().unwrap(), key_bytes.clone())?;

        self.filenames
            .insert(hashed_filename, FileNameEntry::new(name_blob, data_len));

        let encoded: Vec<u8> = bincode::serialize(&self.filenames).unwrap();
        self.storage.upload(HASHMAP_NAME, &encoded).await.unwrap();

        Ok(())
    }

    pub async fn remove_names_from_hashmap(
        &mut self,
        hashed_filenames: HashSet<String>,
    ) -> eyre::Result<()> {
        for hashed_filename in hashed_filenames {
            self.filenames.remove(&hashed_filename);
        }

        let encoded: Vec<u8> = bincode::serialize(&self.filenames).unwrap();
        self.storage.upload(HASHMAP_NAME, &encoded).await.unwrap();

        Ok(())
    }

    pub fn get_unique_filenames(&self, key_bytes: Vec<u8>) -> HashSet<String> {
        let files: Vec<String> = self.get_all_file_names();
        let filtered_files: Vec<_> = files.iter().filter(|&file| file != HASHMAP_NAME).collect();
        let mut file_names = HashSet::new();

        for filename in filtered_files {
            if let Some(entry) = self.filenames.get(filename) {
                let encrypted_name: Vec<u8> = entry.name_blob[NONCE_LEN..].try_into().unwrap();

                match crypto::decrypt_blob(encrypted_name, key_bytes.clone()) {
                    Ok(decrypted_name) => {
                        let s = String::from_utf8(decrypted_name).unwrap();
                        let mut parts = s.rsplitn(2, '_');

                        let _number = parts.next().unwrap_or_default().to_string();
                        let filename = parts.next().unwrap_or(&s).to_string();

                        file_names.insert(filename);
                    }
                    Err(_) => {
                        panic!("Could not decrypt a filename")
                    }
                }
            }
        }
        file_names
    }

    pub fn get_all_filenames_of(
        &self,
        plaintext_filename: &str,
        key_bytes: Vec<u8>,
    ) -> HashSet<String> {
        let files: Vec<String> = self.get_all_file_names();
        let filtered_files: Vec<_> = files.iter().filter(|&file| file != HASHMAP_NAME).collect();
        let mut file_names = HashSet::new();

        for filename in filtered_files {
            if let Some(entry) = self.filenames.get(filename) {
                let encrypted_name: Vec<u8> = entry.name_blob[NONCE_LEN..].try_into().unwrap();

                let decrypted_name =
                    crypto::decrypt_blob(encrypted_name, key_bytes.clone()).unwrap();

                let s = String::from_utf8(decrypted_name).unwrap();

                if s.starts_with(plaintext_filename) {
                    file_names.insert(filename.to_string());
                }
            }
        }
        file_names
    }

    fn get_all_file_names(&self) -> Vec<String> {
        self.filenames.keys().cloned().collect()
    }

    pub fn get(&self, key: &String) -> Option<&FileNameEntry> {
        self.filenames.get(key)
    }

    async fn get_filenames_from_storage(
        storage: Rc<dyn Storage>,
    ) -> HashMap<String, FileNameEntry> {
        match storage.download(HASHMAP_NAME).await {
            Ok(encoded) => bincode::deserialize(&encoded).unwrap(),
            Err(_) => {
                let empty_hashmap =
                    bincode::serialize(&HashMap::<String, FileNameEntry>::new()).unwrap();
                storage.upload(HASHMAP_NAME, &empty_hashmap).await.unwrap();
                HashMap::<String, FileNameEntry>::new()
            }
        }
    }
}
