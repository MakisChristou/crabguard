use std::str::FromStr;

use bip39::Mnemonic;
use sha2::{Sha256, Digest};

use rand::rngs::OsRng;
use rand::RngCore;

pub fn generate_mnemonic() -> Mnemonic {
    let mut entropy = [0u8; 16];
    OsRng.fill_bytes(&mut entropy);
    Mnemonic::from_entropy(&entropy).expect("Failed to generate mnemonic")
}

pub fn generate_aes_key_from_mnemonic(mnemonic: String) -> Vec<u8> {
    let mnemonic = bip39::Mnemonic::from_str(&mnemonic).unwrap();
    let seed = mnemonic.to_seed("");
    let mut hasher = Sha256::new();
    hasher.update(&seed);
    let result = hasher.finalize();
    result.to_vec()
}
