use dotenv::dotenv;
use ring::aead::NONCE_LEN;
use ring::error::Unspecified;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::File;
use std::hash::Hash;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use storage::local::LocalStorage;
use storage::Storage;
use utils::CounterNonceSequence;

use crate::args::{Cli, Commands};

mod args;
mod storage;
mod utils;

#[derive(Serialize, Deserialize, Debug)]
struct Data {
    filenames: HashMap<String, Vec<u8>>,
}

fn store_filenames_on_disk(filenames: HashMap<String, Vec<u8>>) {
    // Serialize the hashmap using bincode
    let encoded: Vec<u8> = bincode::serialize(&filenames).unwrap();

    let mut file = File::create("filenames.bin").unwrap();
    file.write_all(&encoded).unwrap();
}

fn retrieve_filenames_from_disk() -> HashMap<String, Vec<u8>> {
    // Try to open the file
    let mut file = match File::open("filenames.bin") {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return HashMap::new(),
        Err(e) => panic!("Error opening file: {:?}", e),
    };

    // Read the file contents
    let mut encoded = Vec::new();
    file.read_to_end(&mut encoded).unwrap();

    // Deserialize the data into a HashMap
    let filenames: HashMap<String, Vec<u8>> = bincode::deserialize(&encoded).unwrap();
    filenames
}

fn main() -> Result<(), Unspecified> {
    dotenv().ok();
    let key_bytes = match env::var("AES_KEY") {
        Ok(value) => hex::decode(value).expect("Decoding failed"),
        Err(_) => {
            let key = utils::create_random_aes_key();
            utils::write_key_to_env_file(&key);
            key
        }
    };

    let mut filenames = retrieve_filenames_from_disk();

    let local_directory = match env::var("LOCAL_DIR") {
        Ok(value) => value,
        Err(_) => String::from("crabguard_files"),
    };

    fs::create_dir_all(&local_directory).unwrap();
    let local_storage = LocalStorage::new(&local_directory);

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
                let mut name_blob: Vec<u8> = utils::usize_to_u8_2(encrypted_name.len()).to_vec();
                name_blob.extend_from_slice(&encrypted_name);
                name_blob.extend_from_slice(starting_value);
                filenames.insert(hashed_filename, name_blob);

                // Store it on disk serialized
                store_filenames_on_disk(filenames);

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
                    .delete(&format!("{}.enc", file_name.to_str().unwrap()))
                    .unwrap();
            } else {
                panic!("Path given does not contain filename");
            }
        }
        Some(Commands::List {}) => {
            let files = local_storage.list().unwrap();
            for filename in files {
                println!("{}", filename);
            }
        }

        None => {
            println!("Welcome to 🦀🔒 crabguard!");
            println!("Please give a valid command");
        }
    }

    Ok(())
}
