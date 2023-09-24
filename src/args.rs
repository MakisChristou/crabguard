use clap::Parser;

/// A prime k-tuple finder based on the rug Rust crate.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Specific file to encrypt
    #[arg(short, long)]
    pub target: String,
}
