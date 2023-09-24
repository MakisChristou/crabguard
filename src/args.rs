use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Upload a file to storage
    Upload { file_path: String },

    /// Download a file from storage
    Download { file_name: String },

    /// Delete a file from storage
    Delete { file_name: String },

    /// List all storage files
    List {},
}

impl Cli {
    pub fn parse_arguments() -> Self {
        Cli::parse()
    }
}
