use eyre::eyre;
use eyre::Result;
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
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

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

fn encrypt(
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

fn decrypt(
    mut cypher_text_with_tag: Vec<u8>,
    key_bytes: Vec<u8>,
    nonce_sequence: CounterNonceSequence,
) -> Result<Vec<u8>, Unspecified> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)?;
    let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
    let decrypted_data = opening_key.open_in_place(Aad::empty(), &mut cypher_text_with_tag)?;
    Ok(decrypted_data.to_vec())
}

pub fn create_random_aes_key() -> Vec<u8> {
    let rand = SystemRandom::new();
    let mut key_bytes = vec![0; AES_256_GCM.key_len()];
    rand.fill(&mut key_bytes).unwrap();
    key_bytes
}

pub fn encrypt_blob(plaintext: Vec<u8>, key_bytes: Vec<u8>) -> Result<Vec<u8>> {
    let nonce_sequence = CounterNonceSequence::new_random();
    let starting_value = nonce_sequence.0.to_vec();

    let cypher_text_with_tag =
        encrypt(plaintext, key_bytes, nonce_sequence).map_err(|_| eyre!("Unspecified"))?;

    // Prepend the nonce on the ciphertext
    let mut ciphertext = starting_value;
    ciphertext.extend_from_slice(&cypher_text_with_tag);

    Ok(ciphertext)
}

pub fn decrypt_blob(ciphertext: Vec<u8>, key_bytes: Vec<u8>) -> Result<Vec<u8>> {
    // Extract nonce from first 12 bytes of file
    let starting_value = &ciphertext[..NONCE_LEN];
    let nonce_array: [u8; NONCE_LEN] = starting_value.try_into().unwrap();
    let nonce_sequence = CounterNonceSequence::new(nonce_array);

    // Extract actual cyphertext
    let cypher_text_with_tag = &ciphertext[NONCE_LEN..];

    let plaintext = decrypt(cypher_text_with_tag.to_vec(), key_bytes, nonce_sequence)
        .map_err(|_| eyre!("Unspecified"))?;

    Ok(plaintext)
}

pub fn encrypt_string(plaintext: String, key_bytes: Vec<u8>) -> Result<String> {
    todo!()
}

pub fn decrypt_string(ciphertext: String, key_bytes: Vec<u8>) -> Result<String> {
    todo!()
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
            Ok(_) => {
                assert!(false)
            }
            Err(_) => {
                assert!(true)
            }
        };
    }
}
