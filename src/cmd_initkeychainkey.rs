use clap::Args;
use rust_util::XResult;

#[derive(Debug, Args)]
pub struct CmdKeychainKey {
    /// Keychain name, or default
    #[arg(long, short = 'c')]
    pub keychain_name: Option<String>,
    /// Service name, or tiny-encrypt
    #[arg(long, short = 's')]
    pub server_name: Option<String>,
    /// Key type, or default x25519
    #[arg(long, short = 't')]
    pub key_type: Option<String>,
    /// Key name
    #[arg(long, short = 'n')]
    pub key_name: String,
}

#[allow(dead_code)]
const DEFAULT_SERVICE_NAME: &str = "tiny-encrypt";

#[allow(dead_code)]
pub enum KeyType {
    P256,
    P384,
    X25519,
}

// TODO Under developing
// keychain://keychain_name?sn=service_name&kt=kp-p256&kn=key_name&fp=fingerprint
// keychain_name -> default
// service_name -> tiny-encrypt
// kt=kp-p256|kp-p384|kp-x25519 -> keypair P256, P385 or X25519
// key_name -> key name in keychain
// fingerprint -> hex(SHA256(public_key)[0..4])
pub fn keychain_key(_cmd_keychain_key: CmdKeychainKey) -> XResult<()> {
    println!();
    Ok(())
}