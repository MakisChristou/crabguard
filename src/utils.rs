use dotenv::dotenv;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::time::Instant;

use crate::crypto;
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

pub fn _get_local_dir_from_env() -> String {
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

pub fn _create_dir_if_not_exist(local_directory: String) {
    let path = std::path::Path::new(&local_directory);
    if !path.exists() {
        if let Err(e) = fs::create_dir_all(path) {
            panic!("Failed to create directory: {:?}", e);
        }
    }
}

pub fn create_progress_bar(total_chunks: u64) -> ProgressBar {
    let pb = ProgressBar::new(total_chunks * CHUNK_SIZE as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}").unwrap()
        .progress_chars("#>-"));
    pb
}

pub fn update_progress_bar(pb: &ProgressBar, current_chunk: usize, start_time: &Instant) {
    pb.inc(CHUNK_SIZE as u64);
    let elapsed_time = start_time.elapsed().as_secs_f64();
    let speed = ((CHUNK_SIZE * current_chunk) as f64 / elapsed_time) / 1000.0; // KB/s
    pb.set_message(format!("{:.2} KB/s", speed));
}

pub fn prompt_yes_no(prompt: &str) -> io::Result<bool> {
    loop {
        print!("{} ", prompt);
        io::stdout().flush()?; // Make sure the prompt is immediately displayed

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please enter 'y' or 'n'."),
        }
    }
}
