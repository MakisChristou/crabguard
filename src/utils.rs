use std::fs::OpenOptions;
use std::io::Write;
use ring::aead::NONCE_LEN;
use ring::aead::Nonce;
use ring::aead::NonceSequence;
use ring::aead::OpeningKey;
use ring::aead::SealingKey;
use ring::aead::UnboundKey;
use ring::aead::AES_256_GCM;
use ring::aead::Aad;
use ring::aead::BoundKey;

use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

pub struct CounterNonceSequence(pub u32);

impl NonceSequence for CounterNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);

        self.0 += 1; // advance the counter
        Nonce::try_assume_unique_for_key(&nonce_bytes)
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
