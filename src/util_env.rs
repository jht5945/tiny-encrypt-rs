use std::env;

use rust_util::{debugging, util_env, warning};
use rust_util::util_env as rust_util_env;

use crate::consts;

pub const TINY_ENCRYPT_ENV_DEFAULT_ALGORITHM: &str = "TINY_ENCRYPT_DEFAULT_ALGORITHM";
pub const TINY_ENCRYPT_ENV_DEFAULT_COMPRESS: &str = "TINY_ENCRYPT_DEFAULT_COMPRESS";
pub const TINY_ENCRYPT_ENV_NO_PROGRESS: &str = "TINY_ENCRYPT_NO_PROGRESS";
pub const TINY_ENCRYPT_ENV_USE_DIALOGUER: &str = "TINY_ENCRYPT_USE_DIALOGUER";
pub const TINY_ENCRYPT_ENV_PIN: &str = "TINY_ENCRYPT_PIN";
pub const TINY_ENCRYPT_ENV_KEY_ID: &str = "TINY_ENCRYPT_KEY_ID";
pub const TINY_ENCRYPT_ENV_AUTO_SELECT_KEY_IDS: &str = "TINY_ENCRYPT_AUTO_SELECT_KEY_IDS";
pub const TINY_ENCRYPT_ENV_GPG_COMMAND: &str = "TINY_ENCRYPT_GPG_COMMAND";
pub const TINY_ENCRYPT_ENV_NO_DEFAULT_PIN_HINT: &str = "TINY_ENCRYPT_NO_DEFAULT_PIN_HINT";
pub const TINY_ENCRYPT_ENV_PIN_ENTRY: &str = "TINY_ENCRYPT_PIN_ENTRY";

pub fn get_default_encryption_algorithm() -> Option<&'static str> {
    let env_default_algorithm = env::var(TINY_ENCRYPT_ENV_DEFAULT_ALGORITHM).ok();
    debugging!("Environment variable {} = {:?}", TINY_ENCRYPT_ENV_DEFAULT_ALGORITHM, env_default_algorithm);
    if let Some(env_algorithm) = env_default_algorithm {
        let lower_default_algorithm = env_algorithm.to_lowercase();
        match lower_default_algorithm.as_str() {
            "aes" | "aes/gcm" => return Some(consts::TINY_ENC_AES_GCM),
            "chacha20" | "chacha20/poly1305" => return Some(consts::TINY_ENC_CHACHA20_POLY1305),
            _ => { warning!("Not matched any algorithm: {}", env_algorithm); }
        }
    }
    None
}

pub fn get_pin() -> Option<String> {
    env::var(TINY_ENCRYPT_ENV_PIN).ok()
}

pub fn get_key_id() -> Option<String> {
    env::var(TINY_ENCRYPT_ENV_KEY_ID).ok()
}

pub fn get_gpg_cmd() -> Option<String> {
    env::var(TINY_ENCRYPT_ENV_GPG_COMMAND).ok()
}

pub fn get_pin_entry() -> Option<String> {
    env::var(TINY_ENCRYPT_ENV_PIN_ENTRY).ok()
}

pub fn get_auto_select_key_ids() -> Option<Vec<String>> {
    env::var(TINY_ENCRYPT_ENV_AUTO_SELECT_KEY_IDS).ok().map(|key_ids| {
        key_ids.split(',').map(ToString::to_string).collect::<Vec<_>>()
    })
}

pub fn get_default_compress() -> Option<bool> {
    env::var(TINY_ENCRYPT_ENV_DEFAULT_COMPRESS).ok().map(|val| util_env::is_on(&val))
}

pub fn get_no_progress() -> bool {
    rust_util_env::is_env_on(TINY_ENCRYPT_ENV_NO_PROGRESS)
}

pub fn get_no_default_pin_hint() -> bool {
    rust_util_env::is_env_on(TINY_ENCRYPT_ENV_NO_DEFAULT_PIN_HINT)
}

pub fn get_use_dialoguer() -> bool {
    rust_util_env::is_env_on(TINY_ENCRYPT_ENV_USE_DIALOGUER)
}
