use ring::aead::NONCE_LEN;
use ring::error::Unspecified;
use rusoto_core::Region;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Instant;
use storage::s3::S3Storage;

use crate::args::{Cli, Commands};
use storage::Storage;
use utils::CounterNonceSequence;
use utils::HASHMAP_NAME;

mod args;
mod storage;
mod utils;

const CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Serialize, Deserialize, Debug)]
struct Data {
    filenames: HashMap<String, Vec<u8>>,
}

async fn encrypt_and_upload_data_file(
    data: &Vec<u8>,
    plaintext_filename: &str,
    key_bytes: Vec<u8>,
    storage: &impl Storage,
) -> Result<(), Unspecified> {
    let nonce_sequence = CounterNonceSequence::new_random();
    let starting_value = nonce_sequence.0.to_vec();

    let cypher_text_with_tag = utils::encrypt(data.to_owned(), key_bytes.clone(), nonce_sequence)?;

    // Prepend the nonce on the ciphertext
    let mut data_to_store = starting_value;
    data_to_store.extend_from_slice(&cypher_text_with_tag);

    let hashed_filename = hex::encode(Sha256::digest(plaintext_filename)).to_string();

    storage
        .upload(&hashed_filename, &data_to_store)
        .await
        .unwrap();

    Ok(())
}

async fn add_name_to_hashmap(
    plaintext_filename: &str,
    filenames: &mut HashMap<String, Vec<u8>>,
    key_bytes: Vec<u8>,
    storage: &impl Storage,
) -> Result<(), Unspecified> {
    let hashed_filename = hex::encode(Sha256::digest(plaintext_filename)).to_string();

    // Update the HashMap
    let starting_value = &Sha256::digest(plaintext_filename)[..NONCE_LEN];

    let nonce_array: [u8; NONCE_LEN] = starting_value.try_into().unwrap();
    let nonce_sequence = CounterNonceSequence::new(nonce_array);
    let encrypted_name = utils::encrypt(
        plaintext_filename.try_into().unwrap(),
        key_bytes.clone(),
        nonce_sequence,
    )?;
    // Update the HashMap in RAM
    let mut name_blob: Vec<u8> = Vec::new();
    name_blob.extend_from_slice(starting_value);
    name_blob.extend_from_slice(&encrypted_name);
    filenames.insert(hashed_filename, name_blob);

    let encoded: Vec<u8> = bincode::serialize(&filenames).unwrap();
    storage.upload(HASHMAP_NAME, &encoded).await.unwrap();

    Ok(())
}

async fn remove_name_from_hashmap(
    hashed_filename: &str,
    filenames: &mut HashMap<String, Vec<u8>>,
    storage: &impl Storage,
) -> Result<(), Unspecified> {
    filenames.remove(hashed_filename);

    let encoded: Vec<u8> = bincode::serialize(&filenames).unwrap();
    storage.upload(HASHMAP_NAME, &encoded).await.unwrap();

    Ok(())
}

async fn download_and_decrypt_file(
    plaintext_filename: &str,
    key_bytes: Vec<u8>,
    storage: &impl Storage,
) -> Result<Vec<u8>, Unspecified> {
    let file_contents = storage
        .download(&hex::encode(Sha256::digest(plaintext_filename)).to_string())
        .await
        .map_err(|_| Unspecified)?;

    // Extract nonce from first 12 bytes of file
    let starting_value = &file_contents[..NONCE_LEN];
    let nonce_array: [u8; NONCE_LEN] = starting_value.try_into().unwrap();
    let nonce_sequence = CounterNonceSequence::new(nonce_array);

    // Extract actual cyphertext
    let cypher_text_with_tag = &file_contents[NONCE_LEN..];

    let decrypted_data = utils::decrypt(cypher_text_with_tag.to_vec(), key_bytes, nonce_sequence)?;

    Ok(decrypted_data)
}

async fn get_total_file_size(
    filenames: &HashMap<String, Vec<u8>>,
    files: &Vec<String>,
    plaintext_filename: &str,
    key_bytes: Vec<u8>,
    storage: &impl Storage,
) -> Result<i64, Unspecified> {
    let filenames = get_all_filenames_of(plaintext_filename, filenames, files, key_bytes);
    let mut total_size = 0;

    for filename in filenames {
        let file_size = storage
            .size_of(&hex::encode(Sha256::digest(filename)).to_string())
            .await
            .map_err(|_| Unspecified)?;

        total_size += file_size;
    }

    Ok(total_size)
}

fn get_unique_filenames(
    filenames: &HashMap<String, Vec<u8>>,
    files: &Vec<String>,
    key_bytes: Vec<u8>,
) -> HashSet<String> {
    let filtered_files: Vec<_> = files.iter().filter(|&file| file != HASHMAP_NAME).collect();
    let mut file_names = HashSet::new();

    for filename in filtered_files {
        if let Some(name_blob) = filenames.get(filename) {
            let starting_value: Vec<u8> = name_blob[..NONCE_LEN].try_into().unwrap();
            let nonce_array: [u8; NONCE_LEN] = starting_value.try_into().unwrap();
            let nonce_sequence = CounterNonceSequence::new(nonce_array);

            let encrypted_name: Vec<u8> = name_blob[NONCE_LEN..].try_into().unwrap();

            match utils::decrypt(encrypted_name, key_bytes.clone(), nonce_sequence) {
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

fn get_all_filenames_of(
    plaintext_filename: &str,
    filenames: &HashMap<String, Vec<u8>>,
    files: &Vec<String>,
    key_bytes: Vec<u8>,
) -> HashSet<String> {
    let filtered_files: Vec<_> = files.iter().filter(|&file| file != HASHMAP_NAME).collect();
    let mut file_names = HashSet::new();

    for filename in filtered_files {
        if let Some(name_blob) = filenames.get(filename) {
            let starting_value: Vec<u8> = name_blob[..NONCE_LEN].try_into().unwrap();
            let nonce_array: [u8; NONCE_LEN] = starting_value.try_into().unwrap();
            let nonce_sequence = CounterNonceSequence::new(nonce_array);

            let encrypted_name: Vec<u8> = name_blob[NONCE_LEN..].try_into().unwrap();

            let decrypted_name =
                utils::decrypt(encrypted_name, key_bytes.clone(), nonce_sequence).unwrap();

            let s = String::from_utf8(decrypted_name).unwrap();

            if s.starts_with(plaintext_filename) {
                file_names.insert(filename.to_string());
            }
        }
    }
    file_names
}

#[tokio::main]
async fn main() -> Result<(), Unspecified> {
    // Enviroment Variables
    let key_bytes = utils::get_key_from_env_or_generate_new();
    let aws_region_name = utils::get_aws_region_name_from_env();
    let aws_endpoint = utils::get_aws_endpoint_from_env();
    let aws_bucket_name = utils::get_aws_bucket_name_from_env();

    let region = Region::Custom {
        name: aws_region_name,
        endpoint: aws_endpoint,
    };

    let backblaze_storage = S3Storage::new(region, &aws_bucket_name);

    let mut filenames: HashMap<String, Vec<u8>> =
        utils::get_filenames_from_storage(backblaze_storage.clone()).await;

    match &Cli::parse_arguments().command {
        Some(Commands::Upload { file_path }) => {
            let data = fs::read(file_path).unwrap();
            let path = Path::new(file_path);

            if let Some(file_name) = path.file_name() {
                let plaintext_filename = file_name.to_str().unwrap();
                let num_chunks = (data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;

                // Initialize the progress bar
                let pb = utils::create_progress_bar(num_chunks as u64);
                let start_time = Instant::now();

                for chunk in 0..num_chunks {
                    let start = chunk * CHUNK_SIZE;
                    let end = std::cmp::min(start + CHUNK_SIZE, data.len());
                    let chunk_data = &data[start..end].to_vec();

                    encrypt_and_upload_data_file(
                        chunk_data,
                        &format!("{}_{}", plaintext_filename, chunk),
                        key_bytes.clone(),
                        &backblaze_storage,
                    )
                    .await?;

                    add_name_to_hashmap(
                        &format!("{}_{}", plaintext_filename, chunk),
                        &mut filenames,
                        key_bytes.clone(),
                        &backblaze_storage,
                    )
                    .await?;

                    utils::update_progress_bar(&pb, &start_time);
                }

                pb.finish_with_message("upload complete");
            } else {
                panic!("Path given does not contain filename");
            }
        }
        Some(Commands::Download { file_name }) => {
            let path = Path::new(file_name);

            if let Some(file_name) = path.file_name() {
                let plaintext_filename = file_name.to_str().unwrap();

                let mut complete_plaintext: Vec<u8> = Vec::new();
                let mut current_chunk = 0;

                let files = backblaze_storage.list().await.unwrap();
                let total_size = get_total_file_size(
                    &filenames,
                    &files,
                    plaintext_filename,
                    key_bytes.clone(),
                    &backblaze_storage,
                )
                .await;

                let num_chunks = total_size.unwrap() / CHUNK_SIZE as i64;

                // Initialize the progress bar
                let pb = utils::create_progress_bar(num_chunks as u64);
                let start_time = Instant::now();

                loop {
                    match download_and_decrypt_file(
                        &format!("{}_{}", plaintext_filename, current_chunk),
                        key_bytes.clone(),
                        &backblaze_storage,
                    )
                    .await
                    {
                        Ok(mut decrypted_data) => {
                            complete_plaintext.append(&mut decrypted_data);
                            utils::update_progress_bar(&pb, &start_time);
                        }
                        Err(e) => {
                            if current_chunk != 0 {
                                fs::write(file_name, complete_plaintext.clone()).unwrap();
                                break;
                            } else {
                                panic!("{}", e);
                            }
                        }
                    }

                    current_chunk += 1;
                }
            } else {
                panic!("Path given does not contain filename");
            }
        }
        Some(Commands::Delete { file_name }) => {
            let path = Path::new(file_name);
            if let Some(file_name) = path.file_name() {
                let plaintext_filename = file_name.to_str().unwrap();
                let files = backblaze_storage.list().await.unwrap();
                let associated_filenames =
                    get_all_filenames_of(plaintext_filename, &filenames, &files, key_bytes);

                for filename in associated_filenames {
                    backblaze_storage
                        .delete(&filename.to_owned())
                        .await
                        .unwrap();

                    remove_name_from_hashmap(&filename, &mut filenames, &backblaze_storage).await?;
                }
            } else {
                panic!("Path given does not contain filename");
            }
        }
        Some(Commands::List {}) => {
            let files = backblaze_storage.list().await.unwrap();

            let unique_file_names = get_unique_filenames(&filenames, &files, key_bytes);

            if unique_file_names.is_empty() {
                println!("Bucket is empty!");
            } else {
                for filename in unique_file_names {
                    println!("{}", filename);
                }
            }
        }

        None => {
            println!("Welcome to 🦀🔒 crabguard!");
            println!("Please give a valid command");
        }
    }

    Ok(())
}
