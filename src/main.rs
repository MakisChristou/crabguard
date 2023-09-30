use config::Config;
use ring::aead::NONCE_LEN;
use ring::error::Unspecified;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::time::Instant;
use storage::s3::S3Storage;

use crate::args::{Cli, Commands};
use crypto::CounterNonceSequence;
use storage::Storage;
use utils::HASHMAP_NAME;

mod args;
mod config;
mod crypto;
mod storage;
mod utils;

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB chunks

#[derive(Serialize, Deserialize, Debug)]
struct Data {
    filenames: HashMap<String, Vec<u8>>,
}

async fn encrypt_and_upload_data_chunk(
    data: &Vec<u8>,
    plaintext_filename: &str,
    key_bytes: Vec<u8>,
    storage: &impl Storage,
) -> Result<(), Unspecified> {
    let nonce_sequence = CounterNonceSequence::new_random();
    let starting_value = nonce_sequence.0.to_vec();

    let cypher_text_with_tag = crypto::encrypt(data.to_owned(), key_bytes.clone(), nonce_sequence)?;

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
    let encrypted_name = crypto::encrypt(
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

async fn remove_names_from_hashmap(
    hashed_filenames: HashSet<String>,
    filenames: &mut HashMap<String, Vec<u8>>,
    storage: &impl Storage,
) -> Result<(), Unspecified> {
    for hashed_filename in hashed_filenames {
        filenames.remove(&hashed_filename);
    }

    let encoded: Vec<u8> = bincode::serialize(&filenames).unwrap();
    storage.upload(HASHMAP_NAME, &encoded).await.unwrap();

    Ok(())
}

async fn download_and_decrypt_chunk(
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

    let decrypted_data = crypto::decrypt(cypher_text_with_tag.to_vec(), key_bytes, nonce_sequence)?;

    Ok(decrypted_data)
}

fn get_unique_filenames(
    filenames: &HashMap<String, Vec<u8>>,
    files: &[String],
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

            match crypto::decrypt(encrypted_name, key_bytes.clone(), nonce_sequence) {
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
    files: &[String],
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
                crypto::decrypt(encrypted_name, key_bytes.clone(), nonce_sequence).unwrap();

            let s = String::from_utf8(decrypted_name).unwrap();

            if s.starts_with(plaintext_filename) {
                file_names.insert(filename.to_string());
            }
        }
    }
    file_names
}

async fn handle_upload(
    file_path: &str,
    config: Config,
    storage: &impl Storage,
    filenames: &mut HashMap<String, Vec<u8>>,
) -> Result<(), Unspecified> {
    let path = Path::new(file_path);
    let mut file = File::open(file_path).unwrap();

    if let Some(file_name) = path.file_name() {
        let plaintext_filename = file_name.to_str().unwrap();

        let file_len = file.metadata().unwrap().len() as usize;
        let num_chunks = (file_len + CHUNK_SIZE - 1) / CHUNK_SIZE;

        // Get the number of chunks assosiated with this file that were previously uploaded
        let files = storage.list().await.unwrap();
        let associated_filenames = get_all_filenames_of(
            plaintext_filename,
            filenames,
            &files,
            config.key_bytes.clone(),
        );

        let remote_chunks = associated_filenames.len();

        if remote_chunks == num_chunks {
            println!("File {} already uploaded!", plaintext_filename);
            let answer = utils::prompt_yes_no("Do you want to replace it? [y|n]").unwrap();

            if answer {
                handle_delete(plaintext_filename, storage, filenames, config.clone()).await?;
            } else {
                return Ok(());
            }
        }

        // Initialize the progress bar
        let pb = utils::create_progress_bar(num_chunks as u64);
        let start_time = Instant::now();

        // Move progress bar and file pointer accordingly
        pb.inc((remote_chunks * CHUNK_SIZE) as u64);
        file.seek(SeekFrom::Start((remote_chunks * CHUNK_SIZE) as u64)).unwrap();

        let mut chunks_sent_so_far = 0;

        for chunk in remote_chunks..num_chunks {
            let mut chunk_data = vec![0; CHUNK_SIZE];
            let bytes_read = file.read(&mut chunk_data).unwrap();
            chunk_data.truncate(bytes_read); // Handle last chunk

            encrypt_and_upload_data_chunk(
                &chunk_data,
                &format!("{}_{}", plaintext_filename, chunk),
                config.key_bytes.clone(),
                storage,
            )
            .await?;

            add_name_to_hashmap(
                &format!("{}_{}", plaintext_filename, chunk),
                filenames,
                config.key_bytes.clone(),
                storage,
            )
            .await?;

            chunks_sent_so_far += 1;
            utils::update_progress_bar(&pb, chunks_sent_so_far, &start_time);
        }

        pb.finish_with_message("upload complete");
    } else {
        panic!("Path given does not contain filename");
    }

    Ok(())
}

async fn handle_download(
    file_name: &str,
    config: Config,
    storage: &impl Storage,
    filenames: &mut HashMap<String, Vec<u8>>,
) -> Result<(), Unspecified> {
    let path = Path::new(file_name);

    if let Some(file_name) = path.file_name() {
        let plaintext_filename = file_name.to_str().unwrap();

        let mut complete_plaintext: Vec<u8> = Vec::new();
        let mut current_chunk = 0;

        let files = storage.list().await.unwrap();
        let associated_filenames = get_all_filenames_of(
            plaintext_filename,
            filenames,
            &files,
            config.key_bytes.clone(),
        );

        let total_size = storage.size_of(associated_filenames).await;
        let num_chunks = total_size.unwrap() / CHUNK_SIZE as i64;

        // Initialize the progress bar
        let pb = utils::create_progress_bar(num_chunks.try_into().unwrap());
        let start_time = Instant::now();

        loop {
            match download_and_decrypt_chunk(
                &format!("{}_{}", plaintext_filename, current_chunk),
                config.key_bytes.clone(),
                storage,
            )
            .await
            {
                Ok(mut decrypted_data) => {
                    complete_plaintext.append(&mut decrypted_data);
                    utils::update_progress_bar(&pb, current_chunk, &start_time);
                }
                Err(e) => {
                    if current_chunk != 0 {
                        fs::write(file_name, complete_plaintext.clone()).unwrap();
                        return Ok(());
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

async fn handle_delete(
    file_name: &str,
    storage: &impl Storage,
    filenames: &mut HashMap<String, Vec<u8>>,
    config: Config,
) -> Result<(), Unspecified> {
    let path = Path::new(file_name);
    if let Some(file_name) = path.file_name() {
        let plaintext_filename = file_name.to_str().unwrap();
        let files = storage.list().await.unwrap();
        let associated_filenames =
            get_all_filenames_of(plaintext_filename, filenames, &files, config.key_bytes);

        storage
            .batch_delete(associated_filenames.clone())
            .await
            .unwrap();
        remove_names_from_hashmap(associated_filenames, filenames, storage).await?;
    } else {
        panic!("Path given does not contain filename");
    }
    Ok(())
}

async fn handle_list(
    storage: &impl Storage,
    filenames: &HashMap<String, Vec<u8>>,
    config: Config,
) -> Result<(), Unspecified> {
    let files = storage.list().await.unwrap();

    let unique_file_names = get_unique_filenames(filenames, &files, config.key_bytes);

    if unique_file_names.is_empty() {
        println!("Bucket is empty!");
    } else {
        for filename in unique_file_names {
            println!("{}", filename);
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Unspecified> {
    let config = Config::from_env();
    let backblaze_storage = S3Storage::from_config(config.clone());

    let mut filenames: HashMap<String, Vec<u8>> =
        utils::get_filenames_from_storage(&backblaze_storage).await;

    match &Cli::parse_arguments().command {
        Some(Commands::Upload { file_path }) => {
            handle_upload(file_path, config, &backblaze_storage, &mut filenames).await?;
        }
        Some(Commands::Download { file_name }) => {
            handle_download(file_name, config, &backblaze_storage, &mut filenames).await?
        }
        Some(Commands::Delete { file_name }) => {
            handle_delete(file_name, &backblaze_storage, &mut filenames, config).await?
        }
        Some(Commands::List {}) => {
            handle_list(&backblaze_storage, &filenames, config).await?;
        }
        None => {
            println!("Welcome to 🦀🔒 crabguard!");
            println!("Please give a valid command");
        }
    }

    Ok(())
}
