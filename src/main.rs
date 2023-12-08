extern crate core;

use clap::{Parser, Subcommand};
use rust_util::XResult;

use tiny_encrypt::{CmdConfig, CmdDirectDecrypt, CmdEncrypt, CmdInfo, CmdVersion};
#[cfg(feature = "decrypt")]
use tiny_encrypt::CmdDecrypt;
#[cfg(feature = "decrypt")]
use tiny_encrypt::CmdExecEnv;
#[cfg(feature = "macos")]
use tiny_encrypt::CmdKeychainKey;

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
    #[cfg(feature = "decrypt")]
    /// Decrypt file(s)
    #[command(arg_required_else_help = true, short_flag = 'd')]
    Decrypt(CmdDecrypt),
    /// Direct decrypt file(s)
    #[command(arg_required_else_help = true)]
    DirectDecrypt(CmdDirectDecrypt),
    /// Show file info
    #[command(arg_required_else_help = true, short_flag = 'I')]
    Info(CmdInfo),
    #[cfg(feature = "macos")]
    /// Keychain Key [pending implementation]
    #[command(arg_required_else_help = true, short_flag = 'k')]
    KeychainKey(CmdKeychainKey),
    #[cfg(feature = "decrypt")]
    /// Execute env
    #[command(arg_required_else_help = true, short_flag = 'X')]
    ExecEnv(CmdExecEnv),
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
        #[cfg(feature = "decrypt")]
        Commands::Decrypt(cmd_decrypt) => tiny_encrypt::decrypt(cmd_decrypt),
        Commands::DirectDecrypt(cmd_direct_decrypt) => tiny_encrypt::direct_decrypt(cmd_direct_decrypt),
        Commands::Info(cmd_info) => tiny_encrypt::info(cmd_info),
        #[cfg(feature = "macos")]
        Commands::KeychainKey(cmd_keychain_key) => tiny_encrypt::keychain_key(cmd_keychain_key),
        #[cfg(feature = "decrypt")]
        Commands::ExecEnv(cmd_exec_env) => tiny_encrypt::exec_env(cmd_exec_env),
        Commands::Version(cmd_version) => tiny_encrypt::version(cmd_version),
        Commands::Config(cmd_config) => tiny_encrypt::config(cmd_config),
    }
}