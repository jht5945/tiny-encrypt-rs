use std::io;
use std::io::Write;

use base64::Engine;
use base64::engine::general_purpose;
use rust_util::{warning, XResult};

pub const ENC_AES256_GCM_P256: &str = "aes256-gcm-p256";
pub const TINY_ENC_FILE_EXT: &str = ".tinyenc";
pub const TINY_ENC_CONFIG_FILE: &str = "~/.tinyencrypt/config-rs.json";

pub fn simple_kdf(input: &[u8]) -> Vec<u8> {
    let input = hex::decode(sha256::digest(input)).unwrap();
    let input = hex::decode(sha256::digest(input)).unwrap();
    let input = hex::decode(sha256::digest(input)).unwrap();
    let input = hex::decode(sha256::digest(input)).unwrap();
    let input = hex::decode(sha256::digest(input)).unwrap();
    let input = hex::decode(sha256::digest(input)).unwrap();
    let input = hex::decode(sha256::digest(input)).unwrap();
    let input = hex::decode(sha256::digest(input)).unwrap();
    input
}

pub fn decode_base64(input: &str) -> XResult<Vec<u8>> {
    Ok(general_purpose::STANDARD.decode(input)?)
}

pub fn encode_base64(input: &[u8]) -> String {
    general_purpose::STANDARD.encode(input)
}

pub fn decode_base64_url_no_pad(input: &str) -> XResult<Vec<u8>> {
    Ok(general_purpose::URL_SAFE_NO_PAD.decode(input)?)
}

pub fn read_number(hint: &str, from: usize, to: usize) -> usize {
    loop {
        print!("{} ({}-{}): ", hint, from, to);
        io::stdout().flush().ok();
        let mut buff = String::new();
        let _ = io::stdin().read_line(&mut buff).expect("Read line from stdin");
        let buff = buff.trim();
        match buff.parse() {
            Err(_) => warning!("Input number error!"),
            Ok(number) => if number < from || number > to {
                warning!("Input number is not in range.");
            } else {
                return number;
            },
        }
    }
}

pub fn get_user_agent() -> String {
    format!("TinyEncrypt-rs v{}@{}", env!("CARGO_PKG_VERSION"),
            if cfg!(target_os = "macos") {
                "MacOS"
            } else if cfg!(target_os = "ios") {
                "iOS"
            } else if cfg!(target_os = "android") {
                "Android"
            } else if cfg!(target_os = "windows") {
                "Windows"
            } else if cfg!(target_os = "linux") {
                "Linux"
            } else if cfg!(target_os = "freebsd") {
                "FreeBSD"
            } else if cfg!(target_os = "dragonfly") {
                "Dragonfly"
            } else if cfg!(target_os = "openbsd") {
                "OpenBSD"
            } else if cfg!(target_os = "netbsd") {
                "NetBSD"
            } else {
                panic!("Unsupported OS!");
            }
    )
}