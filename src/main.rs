use std::fs;
use clap::Parser;
use ring::error::Unspecified;
use dotenv::dotenv;
use std::env;

use crate::args::Args;


mod args;
mod utils;


fn main() -> Result<(), Unspecified> {
    let args = Args::parse();

    dotenv().ok();
    let key_bytes = match env::var("AES_KEY") {
        Ok(value) => hex::decode(value).expect("Decoding failed"),
        Err(_) => {
            let key = utils::create_random_aes_key();
            utils::write_key_to_env_file(&key);
            key
        }
    };

    let data = fs::read(args.target).unwrap();

    let nonce_sequence = utils::CounterNonceSequence(1);
    let cypher_text_with_tag = utils::encrypt(data.clone(), key_bytes.clone(), nonce_sequence)?;

    let nonce_sequence = utils::CounterNonceSequence(1);
    let decrypted_data = utils::decrypt(cypher_text_with_tag, key_bytes, nonce_sequence)?;

    assert_eq!(data, decrypted_data);
    Ok(())
}
