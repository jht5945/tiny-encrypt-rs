use std::env;

use rust_util::{debugging, iff, warning};
use rust_util::util_env as rust_util_env;

use crate::consts;

pub const TINY_ENCRYPT_ENV_DEFAULT_ALGORITHM: &str = "TINY_ENCRYPT_DEFAULT_ALGORITHM";
pub const TINY_ENCRYPT_ENV_DEFAULT_COMPRESS: &str = "TINY_ENCRYPT_DEFAULT_COMPRESS";
pub const TINY_ENCRYPT_ENV_NO_PROGRESS: &str = "TINY_ENCRYPT_NO_PROGRESS";

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

pub fn get_default_compress() -> Option<bool> {
    iff!(rust_util_env::is_env_off(TINY_ENCRYPT_ENV_DEFAULT_COMPRESS), Some(true), None)
}

pub fn get_no_progress() -> bool {
    rust_util_env::is_env_on(TINY_ENCRYPT_ENV_NO_PROGRESS)
}