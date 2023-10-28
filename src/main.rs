extern crate core;

use clap::{Parser, Subcommand};
use rust_util::XResult;

use tiny_encrypt::{CmdConfig, CmdDecrypt, CmdDirectDecrypt, CmdEncrypt, CmdInfo, CmdVersion};

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
    /// Direct decrypt file(s)
    #[command(arg_required_else_help = true)]
    DirectDecrypt(CmdDirectDecrypt),
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
        Commands::Encrypt(cmd_encrypt) => tiny_encrypt::encrypt(cmd_encrypt),
        Commands::Decrypt(cmd_decrypt) => tiny_encrypt::decrypt(cmd_decrypt),
        Commands::DirectDecrypt(cmd_direct_decrypt) => tiny_encrypt::direct_decrypt(cmd_direct_decrypt),
        Commands::Info(cmd_info) => tiny_encrypt::info(cmd_info),
        Commands::Version(cmd_version) => tiny_encrypt::version(cmd_version),
        Commands::Config(cmd_config) => tiny_encrypt::config(cmd_config),
    }
}