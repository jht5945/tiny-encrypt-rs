use clap::Args;
use rust_util::{debugging, information, opt_result, simple_error, success, XResult};
use security_framework::os::macos::keychain::SecKeychain;

use crate::config::TinyEncryptConfigEnvelop;
use crate::spec::TinyEncryptEnvelopType;
use crate::util_keychainstatic;

#[derive(Debug, Args)]
pub struct CmdKeychainKey {
    // /// Keychain name, or default
    // #[arg(long, short = 'c')]
    // pub keychain_name: Option<String>,
    /// Service name, or tiny-encrypt
    #[arg(long, short = 's')]
    pub server_name: Option<String>,
    /// Key name
    #[arg(long, short = 'n')]
    pub key_name: String,
}

#[allow(dead_code)]
const DEFAULT_SERVICE_NAME: &str = "tiny-encrypt";

pub fn keychain_key(cmd_keychain_key: CmdKeychainKey) -> XResult<()> {
    let service_name = cmd_keychain_key.server_name.as_deref().unwrap_or(DEFAULT_SERVICE_NAME);
    let sec_keychain = opt_result!(SecKeychain::default(), "Get keychain failed: {}");
    if sec_keychain.find_generic_password(service_name, &cmd_keychain_key.key_name).is_ok() {
        return simple_error!("Static x25519 exists: {}.{}", service_name, &cmd_keychain_key.key_name);
    }

    let (keychain_key, public_key) = util_keychainstatic::generate_pass_x25519_static_secret();
    opt_result!(
        sec_keychain.set_generic_password(service_name, &cmd_keychain_key.key_name, keychain_key.as_bytes()),
        "Write static x25519 failed: {}"
    );

    let public_key_hex = hex::encode(public_key.as_bytes());
    debugging!("Keychain key : {}", keychain_key);
    success!("Keychain name: {}", &cmd_keychain_key.key_name);
    success!("Public key   : {}", &public_key_hex);

    let config_envelop = TinyEncryptConfigEnvelop {
        r#type: TinyEncryptEnvelopType::StaticX25519,
        sid: Some(cmd_keychain_key.key_name.clone()),
        kid: format!("keychain:{}", &public_key_hex),
        desc: Some("Keychain static".to_string()),
        args: Some(vec![
            "".to_string(),
            service_name.to_string(),
            cmd_keychain_key.key_name.clone(),
        ]),
        public_part: public_key_hex,
    };

    information!("Config envelop:\n{}", serde_json::to_string_pretty(&config_envelop).unwrap());

    Ok(())
}