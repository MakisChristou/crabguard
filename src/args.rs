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
    /// Encrypt a file
    Encrypt { source: String, output: String },

    /// Decrypt a file
    Decrypt { source: String, output: String },
}

impl Cli {
    pub fn parse_arguments() -> Self {
        Cli::parse()
    }
}
