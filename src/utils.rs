use dotenv::dotenv;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use rand::Rng;
use ring::aead::Aad;
use ring::aead::BoundKey;
use ring::aead::Nonce;
use ring::aead::NonceSequence;
use ring::aead::OpeningKey;
use ring::aead::SealingKey;
use ring::aead::UnboundKey;
use ring::aead::AES_256_GCM;
use ring::aead::NONCE_LEN;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;

use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

use crate::storage::Storage;
use crate::CHUNK_SIZE;

pub const HASHMAP_NAME: &str = "filenames.bin";

pub struct CounterNonceSequence(pub [u8; NONCE_LEN]);

impl CounterNonceSequence {
    pub fn new(start: [u8; 12]) -> Self {
        CounterNonceSequence(start)
    }
    // Create a new CounterNonceSequence with a random 12-byte value
    pub fn new_random() -> Self {
        let mut random_value = [0u8; NONCE_LEN];
        rand::thread_rng().fill(&mut random_value);
        CounterNonceSequence(random_value)
    }
}

impl NonceSequence for CounterNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        // Use the entire 12-byte value for the nonce
        let nonce = Nonce::try_assume_unique_for_key(&self.0)?;

        // Update the nonce for the next use (e.g., increment or generate a new random value)
        rand::thread_rng().fill(&mut self.0);

        Ok(nonce)
    }
}

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

pub fn encrypt(
    data: Vec<u8>,
    key_bytes: Vec<u8>,
    nonce_sequence: CounterNonceSequence,
) -> Result<Vec<u8>, Unspecified> {
    // Create a new AEAD key without a designated role or nonce sequence
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)?;

    // Create a new AEAD key for encrypting and signing ("sealing"), bound to a nonce sequence
    // The SealingKey can be used multiple times, each time a new nonce will be used
    let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);

    // Create a mutable copy of the data that will be encrypted in place
    let mut in_out = data.clone();

    // Encrypt the data with AEAD using the AES_256_GCM algorithm
    let tag = sealing_key.seal_in_place_separate_tag(Aad::empty(), &mut in_out)?;

    // Decrypt the data by passing in the associated data and the cypher text with the authentication tag appended
    let cypher_text_with_tag = [&in_out, tag.as_ref()].concat();

    Ok(cypher_text_with_tag)
}

pub fn decrypt(
    mut cypher_text_with_tag: Vec<u8>,
    key_bytes: Vec<u8>,
    nonce_sequence: CounterNonceSequence,
) -> Result<Vec<u8>, Unspecified> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)?;
    let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
    let decrypted_data = opening_key.open_in_place(Aad::empty(), &mut cypher_text_with_tag)?;
    Ok(decrypted_data.to_vec())
}

pub fn get_key_from_env_or_generate_new() -> Vec<u8> {
    dotenv().ok();
    match env::var("AES_KEY") {
        Ok(value) => hex::decode(value).expect("Decoding failed"),
        Err(_) => {
            let key = create_random_aes_key();
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

pub fn create_dir_if_not_exist(local_directory: String) {
    let path = std::path::Path::new(&local_directory);
    if !path.exists() {
        if let Err(e) = fs::create_dir_all(path) {
            panic!("Failed to create directory: {:?}", e);
        }
    }
}

pub async fn get_filenames_from_storage(storage: impl Storage) -> HashMap<String, Vec<u8>> {
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
    let pb = ProgressBar::new(num_chunks);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}").unwrap()
        .progress_chars("#>-"));
    pb
}

pub fn update_progress_bar(pb: &ProgressBar, start_time: &Instant) {
    pb.inc(1);
    let elapsed_time = start_time.elapsed().as_secs_f64();
    let speed = (CHUNK_SIZE as f64 / 1024.0) / elapsed_time; // KB/s
    pb.set_message(format!("{:.2} KB/s", speed));
}

#[cfg(test)]
mod test {
    use super::{create_random_aes_key, decrypt, encrypt, CounterNonceSequence};

    #[test]
    fn should_encrypt_decrypt_correctly() {
        let plaintext = b"Hello World!".to_vec();

        let key_bytes = create_random_aes_key();
        let starting_value: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let nonce_sequence = CounterNonceSequence::new(starting_value);

        let cypher_text_with_tag =
            encrypt(plaintext.clone(), key_bytes.clone(), nonce_sequence).unwrap();

        let nonce_sequence = CounterNonceSequence::new(starting_value);
        let decrypted_ciphertext =
            decrypt(cypher_text_with_tag, key_bytes, nonce_sequence).unwrap();

        assert_eq!(decrypted_ciphertext, plaintext);
    }

    #[test]
    fn should_panic_when_ciphertext_is_invalid() {
        let plaintext = b"Hello World!".to_vec();

        let key_bytes = create_random_aes_key();
        let starting_value: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let nonce_sequence = CounterNonceSequence::new(starting_value);

        let mut cypher_text_with_tag =
            encrypt(plaintext.clone(), key_bytes.clone(), nonce_sequence).unwrap();

        // Flip some bits
        cypher_text_with_tag[0] = cypher_text_with_tag[0] ^ cypher_text_with_tag[0];

        let nonce_sequence = CounterNonceSequence::new(starting_value);
        match decrypt(cypher_text_with_tag, key_bytes, nonce_sequence) {
            Ok(decrypted_ciphertext) => {
                assert!(false)
            }
            Err(e) => {
                assert!(true)
            }
        };
    }
}
