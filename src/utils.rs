use dotenv::dotenv;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;

use crate::crypto;
use crate::storage::Storage;
use crate::CHUNK_SIZE;

pub const HASHMAP_NAME: &str = "filenames.bin";

pub fn write_key_to_env_file(key: &Vec<u8>) {
    let filename = ".env";

    // Open the file in append mode, or create it if it doesn't exist.
    let mut file = OpenOptions::new()
        .create(true) // Create the file if it doesn't exist.
        .append(true) // Append to the file if it exists.
        .open(filename)
        .unwrap();

    println!("No AES_KEY found, generating new one ...");
    println!("Storing new key to .env file ...");
    writeln!(file, "\nAES_KEY={}", hex::encode(key)).unwrap();
}

pub fn get_key_from_env_or_generate_new() -> Vec<u8> {
    dotenv().ok();
    match env::var("AES_KEY") {
        Ok(value) => hex::decode(value).expect("Decoding failed"),
        Err(_) => {
            let key = crypto::create_random_aes_key();
            write_key_to_env_file(&key);
            key
        }
    }
}

pub fn get_local_dir_from_env() -> String {
    dotenv().ok();
    match env::var("LOCAL_DIR") {
        Ok(value) => value,
        Err(_) => String::from("crabguard_files"),
    }
}

pub fn get_aws_region_name_from_env() -> String {
    dotenv().ok();
    match env::var("AWS_REGION_NAME") {
        Ok(value) => value,
        Err(_) => panic!("Please set an AWS_REGION_NAME in your .env file"),
    }
}

pub fn get_aws_endpoint_from_env() -> String {
    dotenv().ok();
    match env::var("AWS_ENDPOINT") {
        Ok(value) => value,
        Err(_) => panic!("Please set an AWS_ENDPOINT in your .env file"),
    }
}

pub fn get_aws_bucket_name_from_env() -> String {
    dotenv().ok();
    match env::var("AWS_BUCKET_NAME") {
        Ok(value) => value,
        Err(_) => panic!("Please set an AWS_BUCKET_NAME in your .env file"),
    }
}

pub fn create_dir_if_not_exist(local_directory: String) {
    let path = std::path::Path::new(&local_directory);
    if !path.exists() {
        if let Err(e) = fs::create_dir_all(path) {
            panic!("Failed to create directory: {:?}", e);
        }
    }
}

pub async fn get_filenames_from_storage(storage: &impl Storage) -> HashMap<String, Vec<u8>> {
    match storage.download(HASHMAP_NAME).await {
        Ok(encoded) => bincode::deserialize(&encoded).unwrap(),
        Err(_) => {
            let empty_hashmap = bincode::serialize(&HashMap::<String, Vec<u8>>::new()).unwrap();
            storage.upload(HASHMAP_NAME, &empty_hashmap).await.unwrap();
            HashMap::<String, Vec<u8>>::new()
        }
    }
}

pub fn create_progress_bar(num_chunks: u64) -> ProgressBar {
    let pb = ProgressBar::new(num_chunks * CHUNK_SIZE as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}").unwrap()
        .progress_chars("#>-"));
    pb
}

pub fn create_mysterious_bar() -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {bytes} bytes processed {msg}")
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈"),
    );
    pb
}

pub fn update_progress_bar(pb: &ProgressBar, current_chunk: usize, start_time: &Instant) {
    pb.inc(CHUNK_SIZE as u64);
    let elapsed_time = start_time.elapsed().as_secs_f64();
    let speed = ((CHUNK_SIZE * current_chunk) as f64 / elapsed_time) / 1000.0; // KB/s
    pb.set_message(format!("{:.2} KB/s", speed));
}
