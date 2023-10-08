extern crate core;

use clap::{Parser, Subcommand};
use rust_util::XResult;

use crate::cmd_decrypt::CmdDecrypt;
use crate::cmd_encrypt::CmdEncrypt;
use crate::cmd_info::CmdInfo;

mod util;
mod util_ecdh;
mod util_x25519;
mod compress;
mod config;
mod spec;
mod crypto_aes;
mod crypto_rsa;
mod wrap_key;
mod file;
mod card;
mod cmd_info;
mod cmd_decrypt;
mod cmd_encrypt;

#[derive(Debug, Parser)]
#[command(name = "tiny-encrypt-rs")]
#[command(about = "A tiny encrypt client in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Encrypt file(s)
    #[command(arg_required_else_help = true, short_flag = 'e')]
    Encrypt(CmdEncrypt),
    /// Decrypt file(s)
    #[command(arg_required_else_help = true, short_flag = 'd')]
    Decrypt(CmdDecrypt),
    /// Show file info
    #[command(arg_required_else_help = true, short_flag = 'I')]
    Info(CmdInfo),
}

fn main() -> XResult<()> {
    let args = Cli::parse();
    match args.command {
        Commands::Encrypt(cmd_encrypt) => cmd_encrypt::encrypt(cmd_encrypt),
        Commands::Decrypt(cmd_decrypt) => cmd_decrypt::decrypt(cmd_decrypt),
        Commands::Info(cmd_info) => cmd_info::info(cmd_info),
    }
}