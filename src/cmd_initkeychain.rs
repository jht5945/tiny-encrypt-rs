use clap::Args;
use rust_util::{debugging, information, opt_result, simple_error, success, warning, XResult};

use crate::config::TinyEncryptConfigEnvelop;
use crate::spec::TinyEncryptEnvelopType;
#[cfg(feature = "secure-enclave")]
use crate::util_keychainkey;
use crate::util_keychainstatic;
use crate::util_keychainstatic::{KeychainKey, X25519StaticSecret};

#[derive(Debug, Args)]
pub struct CmdInitKeychain {
    /// Secure Enclave
    #[arg(long, short = 'S')]
    pub secure_enclave: bool,
    /// Expose secure enclave private key data
    #[arg(long, short = 'E')]
    pub expose_secure_enclave_private_key: bool,
    // /// Keychain name, or default
    // #[arg(long, short = 'c')]
    // pub keychain_name: Option<String>,
    /// Service name, or default: tiny-encrypt
    #[arg(long, short = 's')]
    pub server_name: Option<String>,
    /// Key name
    #[arg(long, short = 'n')]
    pub key_name: String,
}

const DEFAULT_SERVICE_NAME: &str = "tiny-encrypt";

pub fn init_keychain(cmd_init_keychain: CmdInitKeychain) -> XResult<()> {
    if cmd_init_keychain.secure_enclave {
        #[cfg(feature = "secure-enclave")]
        return keychain_key_se(cmd_init_keychain);
        #[cfg(not(feature = "secure-enclave"))]
        return simple_error!("Feature secure-enclave is not built");
    } else {
        keychain_key_static(cmd_init_keychain)
    }
}

#[cfg(feature = "secure-enclave")]
pub fn keychain_key_se(cmd_init_keychain: CmdInitKeychain) -> XResult<()> {
    if !util_keychainkey::is_support_se() {
        return simple_error!("Secure enclave is not supported.");
    }

    let service_name = cmd_init_keychain.server_name.as_deref().unwrap_or(DEFAULT_SERVICE_NAME);
    let key_name = &cmd_init_keychain.key_name;

    let (public_key_hex, private_key_base64) = util_keychainkey::generate_se_p256_keypair()?;
    let public_key_compressed_hex = public_key_hex.chars()
        .skip(2).take(public_key_hex.len() / 2 - 1).collect::<String>();
    let saved_arg0 = if cmd_init_keychain.expose_secure_enclave_private_key {
        private_key_base64
    } else {
        let keychain_key = KeychainKey::from_default_keychain(service_name, key_name);
        keychain_key.set_password(private_key_base64.as_bytes())?;
        keychain_key.to_str()
    };

    let config_envelop = TinyEncryptConfigEnvelop {
        r#type: TinyEncryptEnvelopType::KeyP256,
        sid: Some(cmd_init_keychain.key_name.clone()),
        kid: format!("keychain:02{}", &public_key_compressed_hex),
        desc: Some("Keychain Secure Enclave".to_string()),
        args: Some(vec![saved_arg0]),
        public_part: public_key_hex,
    };

    information!("Config envelop:\n{}", serde_json::to_string_pretty(&config_envelop).unwrap());

    Ok(())
}

pub fn keychain_key_static(cmd_init_keychain: CmdInitKeychain) -> XResult<()> {
    let service_name = cmd_init_keychain.server_name.as_deref().unwrap_or(DEFAULT_SERVICE_NAME);
    let key_name = &cmd_init_keychain.key_name;
    let keychain_key = KeychainKey::from_default_keychain(service_name, key_name);

    let public_key = match keychain_key.get_password()? {
        Some(static_x25519) => {
            warning!("Key already exists: {}.{}", service_name, key_name);
            let x25519_static_secret = X25519StaticSecret::parse_bytes(static_x25519.as_ref())?;
            x25519_static_secret.to_public_key()?
        }
        None => {
            let (keychain_key_bytes, public_key) = util_keychainstatic::generate_static_x25519_secret();
            debugging!("Keychain key : {}", keychain_key_bytes);
            opt_result!(
                keychain_key.set_password(keychain_key_bytes.as_bytes()),
                "Write static x25519 failed: {}"
            );
            public_key
        }
    };

    let public_key_hex = hex::encode(public_key.as_bytes());
    success!("Keychain name: {}", &key_name);
    success!("Public key   : {}", &public_key_hex);

    let config_envelop = TinyEncryptConfigEnvelop {
        r#type: TinyEncryptEnvelopType::StaticX25519,
        sid: Some(key_name.clone()),
        kid: format!("keychain:{}", &public_key_hex),
        desc: Some("Keychain static".to_string()),
        args: Some(vec![keychain_key.to_str()]),
        public_part: public_key_hex,
    };

    information!("Config envelop:\n{}", serde_json::to_string_pretty(&config_envelop).unwrap());

    Ok(())
}