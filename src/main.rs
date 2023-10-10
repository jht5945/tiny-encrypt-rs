extern crate core;

use clap::{Parser, Subcommand};
use rust_util::XResult;
use crate::cmd_config::CmdConfig;

use crate::cmd_decrypt::CmdDecrypt;
use crate::cmd_encrypt::CmdEncrypt;
use crate::cmd_info::CmdInfo;
use crate::cmd_version::CmdVersion;

mod util;
mod util_piv;
mod util_ecdh;
mod util_p384;
mod util_x25519;
mod compress;
mod config;
mod spec;
mod crypto_aes;
mod crypto_rsa;
mod wrap_key;
mod file;
mod card;
mod cmd_version;
mod cmd_config;
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
    /// Show version
    #[command(short_flag = 'v')]
    Version(CmdVersion),
    /// Show Config
    #[command(short_flag = 'c')]
    Config(CmdConfig),
}

fn main() -> XResult<()> {
    let args = Cli::parse();
    match args.command {
        Commands::Encrypt(cmd_encrypt) => cmd_encrypt::encrypt(cmd_encrypt),
        Commands::Decrypt(cmd_decrypt) => cmd_decrypt::decrypt(cmd_decrypt),
        Commands::Info(cmd_info) => cmd_info::info(cmd_info),
        Commands::Version(cmd_version) => cmd_version::version(cmd_version),
        Commands::Config(cmd_config) => cmd_config::config(cmd_config),
    }
}