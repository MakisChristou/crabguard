use bip39::{generate_aes_key_from_mnemonic, generate_mnemonic};
use config::Config;
use filename_handler::FileNameHandler;
use ring::error::Unspecified;
use std::rc::Rc;
use storage::s3::S3Storage;

use crate::args::{Cli, Commands};
use crate::command_handler::CommandHandler;

mod args;
mod bip39;
mod command_handler;
mod config;
mod crypto;
mod filename_handler;
mod storage;
mod utils;

const MAX_RETRIES: usize = 3;
const CHUNK_SIZE: usize = 1024 * 1024;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let config = Config::from_env();
    let backblaze_storage = S3Storage::from_config(config.clone());
    let filename_handler = FileNameHandler::new(Rc::new(backblaze_storage.clone())).await;

    let mut command_handler =
        CommandHandler::new(Rc::new(backblaze_storage), filename_handler, config);

    match &Cli::parse_arguments().command {
        Some(Commands::Upload { file_path }) => {
            command_handler.handle_upload(file_path).await?;
        }
        Some(Commands::Download { file_name }) => {
            command_handler.handle_download(file_name).await?
        }
        Some(Commands::Delete { file_name }) => command_handler.handle_delete(file_name).await?,
        Some(Commands::List {}) => {
            command_handler.handle_list().await?;
        }
        Some(Commands::Mnemonic {}) => {
            let mnemonic = generate_mnemonic();
            println!("Mnemonic: {}", mnemonic);
        }
        Some(Commands::Keygen { mnemonic }) => {
            let aes_key = generate_aes_key_from_mnemonic(mnemonic.clone());
            println!("AES Key: {}", hex::encode(aes_key))
        }
        None => {
            println!("Welcome to 🦀🔒 crabguard!");
            println!("Please give a valid command");
        }
    }

    Ok(())
}
