use clap::Args;
use rust_util::{debugging, information, opt_result, opt_value_result, simple_error, success, XResult};
use security_framework::os::macos::keychain::SecKeychain;

use crate::config::TinyEncryptConfigEnvelop;
use crate::spec::TinyEncryptEnvelopType;
#[cfg(feature = "secure-enclave")]
use crate::util_keychainkey;
use crate::util_keychainstatic;

#[derive(Debug, Args)]
pub struct CmdKeychainKey {
    /// Secure Enclave
    #[arg(long, short = 'S')]
    pub secure_enclave: bool,
    // /// Keychain name, or default
    // #[arg(long, short = 'c')]
    // pub keychain_name: Option<String>,
    /// Service name, or tiny-encrypt
    #[arg(long, short = 's')]
    pub server_name: Option<String>,
    /// Key name
    #[arg(long, short = 'n')]
    pub key_name: Option<String>,
}

#[allow(dead_code)]
const DEFAULT_SERVICE_NAME: &str = "tiny-encrypt";

pub fn keychain_key(cmd_keychain_key: CmdKeychainKey) -> XResult<()> {
    if cmd_keychain_key.secure_enclave {
        #[cfg(feature = "secure-enclave")]
        return keychain_key_se(cmd_keychain_key);
        #[cfg(not(feature = "secure-enclave"))]
        return simple_error!("Feature secure-enclave is not built");
    } else {
        keychain_key_static(cmd_keychain_key)
    }
}

#[cfg(feature = "secure-enclave")]
pub fn keychain_key_se(cmd_keychain_key: CmdKeychainKey) -> XResult<()> {
    if !util_keychainkey::is_support_se() {
        return simple_error!("Secure enclave is not supported.");
    }
    let (public_key_hex, private_key_base64) = util_keychainkey::generate_se_p256_keypair()?;
    let public_key_compressed_hex = public_key_hex.chars()
        .skip(2).take(public_key_hex.len() / 2 - 1).collect::<String>();

    let config_envelop = TinyEncryptConfigEnvelop {
        r#type: TinyEncryptEnvelopType::KeyP256,
        sid: cmd_keychain_key.key_name.clone(),
        kid: format!("keychain:02{}", &public_key_compressed_hex),
        desc: Some("Keychain Secure Enclave".to_string()),
        args: Some(vec![
            private_key_base64
        ]),
        public_part: public_key_hex,
    };

    information!("Config envelop:\n{}", serde_json::to_string_pretty(&config_envelop).unwrap());

    Ok(())
}

pub fn keychain_key_static(cmd_keychain_key: CmdKeychainKey) -> XResult<()> {
    let service_name = cmd_keychain_key.server_name.as_deref().unwrap_or(DEFAULT_SERVICE_NAME);
    let sec_keychain = opt_result!(SecKeychain::default(), "Get keychain failed: {}");
    let key_name = opt_value_result!(&cmd_keychain_key.key_name, "Key name is required.");
    if sec_keychain.find_generic_password(service_name, key_name).is_ok() {
        return simple_error!("Static x25519 exists: {}.{}", service_name, &key_name);
    }

    let (keychain_key, public_key) = util_keychainstatic::generate_static_x25519_secret();
    opt_result!(
        sec_keychain.set_generic_password(service_name, key_name, keychain_key.as_bytes()),
        "Write static x25519 failed: {}"
    );

    let public_key_hex = hex::encode(public_key.as_bytes());
    debugging!("Keychain key : {}", keychain_key);
    success!("Keychain name: {}", &key_name);
    success!("Public key   : {}", &public_key_hex);

    let config_envelop = TinyEncryptConfigEnvelop {
        r#type: TinyEncryptEnvelopType::StaticX25519,
        sid: Some(key_name.clone()),
        kid: format!("keychain:{}", &public_key_hex),
        desc: Some("Keychain static".to_string()),
        args: Some(vec![
            "".to_string(),
            service_name.to_string(),
            key_name.clone(),
        ]),
        public_part: public_key_hex,
    };

    information!("Config envelop:\n{}", serde_json::to_string_pretty(&config_envelop).unwrap());

    Ok(())
}