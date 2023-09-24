use dotenv::dotenv;
use ring::error::Unspecified;
use std::env;
use std::fs;

use crate::args::{Cli, Commands};

mod args;
mod storage;
mod utils;

fn main() -> Result<(), Unspecified> {
    dotenv().ok();
    let key_bytes = match env::var("AES_KEY") {
        Ok(value) => hex::decode(value).expect("Decoding failed"),
        Err(_) => {
            let key = utils::create_random_aes_key();
            utils::write_key_to_env_file(&key);
            key
        }
    };

    let cli = Cli::parse_arguments();

    match &cli.command {
        Some(Commands::Encrypt { source, output }) => {
            let data = fs::read(source).unwrap();

            let nonce_sequence = utils::CounterNonceSequence(1);
            let cypher_text_with_tag =
                utils::encrypt(data.clone(), key_bytes.clone(), nonce_sequence)?;

            let _ = fs::write(output, cypher_text_with_tag);
        }
        Some(Commands::Decrypt { source, output }) => {
            let cypher_text_with_tag = fs::read(source).unwrap();

            let nonce_sequence = utils::CounterNonceSequence(1);
            let decrypted_data = utils::decrypt(cypher_text_with_tag, key_bytes, nonce_sequence)?;

            let _ = fs::write(output, decrypted_data);
        }
        None => {
            println!("Welcome to 🦀🔒 crabguard!");
            println!("Please give a valid command");
        }
    }

    Ok(())
}
