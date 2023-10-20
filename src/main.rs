use config::Config;
use filename_handler::FileNameHandler;
use ring::error::Unspecified;
use std::rc::Rc;
use storage::s3::S3Storage;

use crate::args::{Cli, Commands};
use crate::command_handler::CommandHandler;

mod args;
mod command_handler;
mod config;
mod crypto;
mod filename_handler;
mod storage;
mod utils;

const MAX_RETRIES: usize = 3;
const CHUNK_SIZE: usize = 1024 * 1024;

#[tokio::main]
async fn main() -> Result<(), Unspecified> {
    let config = Config::from_env();
    let backblaze_storage = S3Storage::from_config(config.clone());
    let mut filename_handler = FileNameHandler::new(Rc::new(backblaze_storage.clone())).await;

    match &Cli::parse_arguments().command {
        Some(Commands::Upload { file_path }) => {
            CommandHandler::handle_upload(
                file_path,
                config,
                &backblaze_storage,
                &mut filename_handler,
            )
            .await?;
        }
        Some(Commands::Download { file_name }) => {
            CommandHandler::handle_download(
                file_name,
                config,
                &backblaze_storage,
                &filename_handler,
            )
            .await?
        }
        Some(Commands::Delete { file_name }) => {
            CommandHandler::handle_delete(
                file_name,
                &backblaze_storage,
                &mut filename_handler,
                config,
            )
            .await?
        }
        Some(Commands::List {}) => {
            CommandHandler::handle_list(&filename_handler, config).await?;
        }
        None => {
            println!("Welcome to 🦀🔒 crabguard!");
            println!("Please give a valid command");
        }
    }

    Ok(())
}
