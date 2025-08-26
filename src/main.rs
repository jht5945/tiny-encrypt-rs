extern crate core;

use clap::{Parser, Subcommand};
use rust_util::XResult;

#[cfg(feature = "decrypt")]
use tiny_encrypt::CmdDecrypt;
#[cfg(feature = "decrypt")]
use tiny_encrypt::CmdExecEnv;
#[cfg(feature = "macos")]
use tiny_encrypt::CmdInitKeychain;
#[cfg(feature = "smartcard")]
use tiny_encrypt::CmdInitPiv;
use tiny_encrypt::{init_tiny_encrypt_log, CmdConfig, CmdDirectDecrypt, CmdEncrypt, CmdInfo, CmdSimpleDecrypt, CmdSimpleEncrypt, CmdVersion};

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
    /// Simple encrypt message
    #[command(arg_required_else_help = true)]
    SimpleEncrypt(CmdSimpleEncrypt),
    #[cfg(feature = "decrypt")]
    /// Simple decrypt message
    #[command(arg_required_else_help = true)]
    SimpleDecrypt(CmdSimpleDecrypt),
    #[cfg(feature = "decrypt")]
    /// Decrypt file(s)
    #[command(arg_required_else_help = true, short_flag = 'd')]
    Decrypt(CmdDecrypt),
    /// Direct decrypt file(s)
    #[command(arg_required_else_help = true)]
    DirectDecrypt(CmdDirectDecrypt),
    /// Show tiny encrypt file info
    #[command(arg_required_else_help = true, short_flag = 'I')]
    Info(CmdInfo),
    #[cfg(feature = "macos")]
    /// Init Keychain (Secure Enclave or Static)
    #[command(arg_required_else_help = true, short_flag = 'K')]
    InitKeychain(CmdInitKeychain),
    #[cfg(feature = "smartcard")]
    /// Init PIV
    #[command(arg_required_else_help = true, short_flag = 'P')]
    InitPiv(CmdInitPiv),
    #[cfg(feature = "decrypt")]
    /// Execute environment
    #[command(arg_required_else_help = true, short_flag = 'X')]
    ExecEnv(CmdExecEnv),
    /// Show version
    #[command(short_flag = 'v')]
    Version(CmdVersion),
    /// Show configuration
    #[command(short_flag = 'c')]
    Config(CmdConfig),
}

fn main() -> XResult<()> {
    init_tiny_encrypt_log();

    let args = Cli::parse();
    match args.command {
        Commands::Encrypt(cmd_encrypt) => tiny_encrypt::encrypt(cmd_encrypt),
        Commands::SimpleEncrypt(cmd_simple_encrypt) => tiny_encrypt::simple_encrypt(cmd_simple_encrypt),
        #[cfg(feature = "decrypt")]
        Commands::SimpleDecrypt(cmd_simple_decrypt) => tiny_encrypt::simple_decrypt(cmd_simple_decrypt),
        #[cfg(feature = "decrypt")]
        Commands::Decrypt(cmd_decrypt) => tiny_encrypt::decrypt(cmd_decrypt),
        Commands::DirectDecrypt(cmd_direct_decrypt) => tiny_encrypt::direct_decrypt(cmd_direct_decrypt),
        Commands::Info(cmd_info) => tiny_encrypt::info(cmd_info),
        #[cfg(feature = "macos")]
        Commands::InitKeychain(cmd_keychain_key) => tiny_encrypt::init_keychain(cmd_keychain_key),
        #[cfg(feature = "smartcard")]
        Commands::InitPiv(cmd_init_piv) => tiny_encrypt::init_piv(cmd_init_piv),
        #[cfg(feature = "decrypt")]
        Commands::ExecEnv(cmd_exec_env) => tiny_encrypt::exec_env(cmd_exec_env),
        Commands::Version(cmd_version) => tiny_encrypt::version(cmd_version),
        Commands::Config(cmd_config) => tiny_encrypt::config(cmd_config),
    }
}