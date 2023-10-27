use std::env;

use rust_util::{debugging, warning};

use crate::consts;

pub fn get_default_encryption_algorithm() -> Option<&'static str> {
    let env_default_algorithm = env::var(consts::TINY_ENCRYPT_ENV_DEFAULT_ALGORITHM).ok();
    debugging!("Environment variable {} = {:?}", consts::TINY_ENCRYPT_ENV_DEFAULT_ALGORITHM, env_default_algorithm);
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