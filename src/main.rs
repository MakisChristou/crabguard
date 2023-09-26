use ring::aead::NONCE_LEN;
use ring::error::Unspecified;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::args::{Cli, Commands};
use storage::local::LocalStorage;
use storage::Storage;
use utils::CounterNonceSequence;
use utils::HASHMAP_NAME;

mod args;
mod storage;
mod utils;

#[derive(Serialize, Deserialize, Debug)]
struct Data {
    filenames: HashMap<String, Vec<u8>>,
}

fn main() -> Result<(), Unspecified> {
    let key_bytes = utils::get_key_from_env_or_generate_new();

    let local_directory = utils::get_local_dir_from_env();

    utils::create_dir_if_not_exist(local_directory.clone());

    let local_storage = LocalStorage::new(&local_directory);

    let mut filenames: HashMap<String, Vec<u8>> =
        utils::get_filenames_from_storage(local_storage.clone());

    let cli = Cli::parse_arguments();

    match &cli.command {
        Some(Commands::Upload { file_path }) => {
            let data = fs::read(file_path).unwrap();

            let nonce_sequence = CounterNonceSequence::new_random();
            let starting_value = nonce_sequence.0.to_vec();

            let cypher_text_with_tag =
                utils::encrypt(data.clone(), key_bytes.clone(), nonce_sequence)?;

            let path = Path::new(file_path);
            if let Some(file_name) = path.file_name() {
                // Prepend the nonce on the ciphertext
                let mut data_to_store = starting_value;
                data_to_store.extend_from_slice(&cypher_text_with_tag);

                let plaintext_filename = file_name.to_str().unwrap();
                let hashed_filename =
                    format!("{}", hex::encode(Sha256::digest(&plaintext_filename)));

                local_storage
                    .upload(&hashed_filename, &data_to_store)
                    .unwrap();

                // Update the HashMap
                let starting_value = &Sha256::digest(&plaintext_filename)[..NONCE_LEN];
                let nonce_array: [u8; NONCE_LEN] = starting_value.try_into().unwrap();
                let nonce_sequence = CounterNonceSequence::new(nonce_array);
                let encrypted_name = utils::encrypt(
                    plaintext_filename.try_into().unwrap(),
                    key_bytes,
                    nonce_sequence,
                )
                .unwrap();

                // Update the HashMap in RAM
                let mut name_blob: Vec<u8> = Vec::new();
                name_blob.extend_from_slice(&starting_value);
                name_blob.extend_from_slice(&encrypted_name);
                filenames.insert(hashed_filename, name_blob);

                let encoded: Vec<u8> = bincode::serialize(&filenames).unwrap();
                local_storage.upload(HASHMAP_NAME, &encoded).unwrap();
            } else {
                panic!("Path given does not contain filename");
            }
        }
        Some(Commands::Download { file_name }) => {
            let path = Path::new(file_name);
            if let Some(file_name) = path.file_name() {
                let file_contents = local_storage
                    .download(&format!(
                        "{}",
                        hex::encode(Sha256::digest(file_name.to_str().unwrap()))
                    ))
                    .unwrap();

                // Extract nonce from first 12 bytes of file
                let starting_value = &file_contents[..NONCE_LEN];
                let nonce_array: [u8; NONCE_LEN] = starting_value.try_into().unwrap();
                let nonce_sequence = CounterNonceSequence::new(nonce_array);

                // Extract actual cyphertext
                let cypher_text_with_tag = &file_contents[NONCE_LEN..];

                let decrypted_data =
                    utils::decrypt(cypher_text_with_tag.to_vec(), key_bytes, nonce_sequence)?;

                fs::write(file_name, decrypted_data).unwrap();
            } else {
                panic!("Path given does not contain filename");
            }
        }
        Some(Commands::Delete { file_name }) => {
            let path = Path::new(file_name);
            if let Some(file_name) = path.file_name() {
                local_storage
                    .delete(&format!(
                        "{}",
                        hex::encode(Sha256::digest(file_name.to_str().unwrap()))
                    ))
                    .unwrap();
            } else {
                panic!("Path given does not contain filename");
            }
        }
        Some(Commands::List {}) => {
            let files = local_storage.list().unwrap();
            let filtered_files: Vec<_> =
                files.iter().filter(|&file| file != HASHMAP_NAME).collect();

            for filename in filtered_files {
                let name_blob = filenames.get(filename).unwrap();

                let starting_value: Vec<u8> = name_blob[..NONCE_LEN].try_into().unwrap();
                let nonce_array: [u8; NONCE_LEN] = starting_value.try_into().unwrap();
                let nonce_sequence = CounterNonceSequence::new(nonce_array);

                let encrypted_name: Vec<u8> = name_blob[NONCE_LEN..].try_into().unwrap();

                let decrypted_name = utils::decrypt(
                    encrypted_name.try_into().unwrap(),
                    key_bytes.clone(),
                    nonce_sequence,
                )
                .unwrap();

                println!("{}", String::from_utf8(decrypted_name).unwrap());
            }
        }

        None => {
            println!("Welcome to 🦀🔒 crabguard!");
            println!("Please give a valid command");
        }
    }

    Ok(())
}
