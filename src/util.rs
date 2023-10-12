use std::{fs, io};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose;
use rand::random;
use rust_util::{simple_error, warning, XResult};
use zeroize::Zeroize;

pub const ENC_AES256_GCM_P256: &str = "aes256-gcm-p256";
pub const ENC_AES256_GCM_P384: &str = "aes256-gcm-p384";
pub const ENC_AES256_GCM_X25519: &str = "aes256-gcm-x25519";
pub const TINY_ENC_FILE_EXT: &str = ".tinyenc";
pub const TINY_ENC_CONFIG_FILE: &str = "~/.tinyencrypt/config-rs.json";

pub const TINY_ENC_AES_GCM: &str = "AES/GCM";

pub const TINY_ENC_MAGIC_TAG: u16 = 0x01;
pub const TINY_ENC_COMPRESSED_MAGIC_TAG: u16 = 0x02;

pub const SALT_COMMENT: &[u8] = b"salt:comment";
pub const SALT_META: &[u8] = b"salt:meta";

pub fn get_file_name(path: &PathBuf) -> String {
    let path_display = format!("{}", path.display());
    if path_display.contains("/") {
        if let Some(p) = path_display.split("/").last() {
            return p.to_string();
        }
    }
    path_display
}

pub fn require_tiny_enc_file_and_exists(path: impl AsRef<Path>) -> XResult<()> {
    let path = path.as_ref();
    let path_display = format!("{}", path.display());
    if !path_display.ends_with(TINY_ENC_FILE_EXT) {
        return simple_error!("File is not tiny encrypt file: {}", &path_display);
    }
    require_file_exists(path)?;
    Ok(())
}

pub fn require_file_exists(path: impl AsRef<Path>) -> XResult<()> {
    let path = path.as_ref();
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return simple_error!("File: {} not exists", path.display()),
    };
    if !metadata.is_file() {
        return simple_error!("Path: {} is not a file", path.display());
    }
    Ok(())
}

pub fn require_file_not_exists(path: impl AsRef<Path>) -> XResult<()> {
    let path = path.as_ref();
    match fs::metadata(path) {
        Ok(_) => simple_error!("File: {} exists", path.display()),
        Err(_) => Ok(()),
    }
}

pub fn make_key256_and_nonce() -> (Vec<u8>, Vec<u8>) {
    let key: [u8; 32] = random();
    let nonce: [u8; 12] = random();
    let result = (key.into(), nonce.into());
    let (mut key, mut nonce) = (key, nonce);
    key.zeroize();
    nonce.zeroize();
    result
}

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

pub fn encode_base64_url_no_pad(input: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(input)
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

pub fn zeroize(object: impl Zeroize) {
    let mut object = object;
    object.zeroize();
}

pub fn read_line(ln: &str) {
    print!("{}", ln);
    io::stdout().flush().ok();
    let mut buff = String::new();
    let _ = io::stdin().read_line(&mut buff).expect("Read line from stdin");
}

