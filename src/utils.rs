use std::fs::OpenOptions;
use std::io::Write;

use ring::{
    aead::AES_256_GCM,
    rand::{SecureRandom, SystemRandom},
};

pub fn create_random_aes_key() -> Vec<u8> {
    let rand = SystemRandom::new();
    let mut key_bytes = vec![0; AES_256_GCM.key_len()];
    rand.fill(&mut key_bytes).unwrap();
    key_bytes
}

pub fn write_key_to_env_file(key: &Vec<u8>) {
    let filename = ".env";

    // Open the file in append mode, or create it if it doesn't exist.
    let mut file = OpenOptions::new()
        .create(true) // Create the file if it doesn't exist.
        .append(true) // Append to the file if it exists.
        .open(filename)
        .unwrap();

    // Write some content to the file.
    writeln!(file, "AES_KEY={}", hex::encode(key)).unwrap();
}
