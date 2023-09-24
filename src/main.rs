use dotenv::dotenv;
use ring::error::Unspecified;
use std::env;
use std::fs;
use std::path::Path;
use storage::local::LocalStorage;
use storage::Storage;

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

    let local_storage = LocalStorage::new("crabguard_files");

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
        Some(Commands::Upload { file_path }) => {
            let data = fs::read(file_path).unwrap();

            let path = Path::new(file_path);
            if let Some(file_name) = path.file_name() {
                local_storage
                    .upload(&file_name.to_str().unwrap(), &data)
                    .unwrap();
            } else {
                panic!("Path given does not contain filename");
            }
        }
        Some(Commands::Download { file_name }) => {
            let path = Path::new(file_name);
            if let Some(file_name) = path.file_name() {
                let file_contents = local_storage.download(file_name.to_str().unwrap()).unwrap();
                fs::write(file_name, file_contents).unwrap();
            } else {
                panic!("Path given does not contain filename");
            }
        }
        Some(Commands::Delete { file_name }) => {
            let path = Path::new(file_name);
            if let Some(file_name) = path.file_name() {
                local_storage.delete(file_name.to_str().unwrap()).unwrap();
            } else {
                panic!("Path given does not contain filename");
            }
        }
        Some(Commands::List {}) => {
            let files = local_storage.list().unwrap();
            for filename in files {
                println!("{}", filename);
            }
        }

        None => {
            println!("Welcome to 🦀🔒 crabguard!");
            println!("Please give a valid command");
        }
    }

    Ok(())
}
