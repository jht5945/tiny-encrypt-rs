use std::{fs, io};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose;
use rand::random;
use rust_util::{information, opt_result, print_ex, simple_error, util_term, warning, XResult};
use zeroize::Zeroize;

use crate::consts::TINY_ENC_FILE_EXT;
use crate::util_digest::DigestWrite;

pub struct SecVec(pub Vec<u8>);

impl Drop for SecVec {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl AsRef<[u8]> for SecVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub fn read_pin(pin: &Option<String>) -> String {
    match pin {
        Some(pin) => pin.to_string(),
        None => if util_term::read_yes_no("Use default PIN 123456, please confirm") {
            "123456".into()
        } else {
            rpassword::prompt_password("Please input PIN: ").expect("Read PIN failed")
        }
    }
}

pub fn remove_file_with_msg(path: &PathBuf) {
    match fs::remove_file(path) {
        Err(e) => warning!("Remove file: {} failed: {}", path.display(), e),
        Ok(_) => information!("Remove file: {} succeed", path.display()),
    }
}

pub fn get_file_name(path: &Path) -> String {
    let path_display = format!("{}", path.display());
    if path_display.contains('/') {
        if let Some(p) = path_display.split('/').last() {
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

pub fn make_nonce() -> SecVec {
    let (_, nonce) = make_key256_and_nonce();
    nonce
}

pub fn make_key256_and_nonce() -> (SecVec, SecVec) {
    let key: [u8; 32] = random();
    let nonce: [u8; 12] = random();
    let key_vec: Vec<u8> = key.into();
    let nonce_vec: Vec<u8> = nonce.into();
    let (mut key, mut nonce) = (key, nonce);
    key.zeroize();
    nonce.zeroize();
    (SecVec(key_vec), SecVec(nonce_vec))
}

pub fn simple_kdf(input: &[u8]) -> Vec<u8> {
    let mut input = input.to_vec();
    for _ in 0..8 {
        let mut sha256 = DigestWrite::sha256();
        sha256.write_all(&input).expect("SHOULD NOT HAPPEN");
        input = sha256.digest();
    }
    input
}

pub fn parse_pem(pem: &str) -> XResult<Vec<u8>> {
    let mut pem = pem.trim().to_owned();
    if pem.starts_with("-----BEGIN") {
        let mut filter_lines = vec![];
        let lines = pem.lines().skip(1);
        for ln in lines {
            if ln.starts_with("-----END") {
                break;
            } else {
                filter_lines.push(ln.to_string());
            }
        }
        pem = filter_lines.join("");
    }
    pem = pem.chars().filter(|c| *c != '\n' && *c != '\r').clone().collect::<String>();

    Ok(opt_result!(decode_base64(&pem), "Decode PEM failed: {}"))
}

pub fn to_pem(bs: &[u8], name: &str) -> String {
    let bs_base64 = encode_base64(bs);
    let mut pem = String::with_capacity(bs.len() + 64);
    pem.push_str(&format!("-----BEGIN {}-----", name));
    for (i, c) in bs_base64.chars().enumerate() {
        if i % 64 == 0 { pem.push('\n'); }
        pem.push(c);
    }
    if !pem.ends_with('\n') { pem.push('\n'); }
    pem.push_str(&format!("-----END {}-----", name));
    pem
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
        print_ex!("{} ({}-{}): ", hint, from, to);
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
    format!("TinyEncrypt-rs v{}@{}-{}", env!("CARGO_PKG_VERSION"), get_os(), get_arch())
}

pub fn get_os() -> String {
    if cfg!(target_os = "macos") {
        "macOS"
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
        "UnknownOS"
    }.to_string()
}

pub fn get_arch() -> String {
    if cfg!(target_arch = "x86_64") {
        "x86-64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else if cfg!(target_arch = "riscv64") {
        "riscv64"
    } else if cfg!(target_arch = "riscv32") {
        "riscv32"
    } else if cfg!(target_arch = "mips64") {
        "mips64"
    } else if cfg!(target_arch = "mips") {
        "mips"
    } else if cfg!(target_arch = "powerpc64") {
        "powerpc64"
    } else if cfg!(target_arch = "powerpc") {
        "powerpc"
    } else {
        "unknown"
    }.to_string()
}

pub fn zeroize(object: impl Zeroize) {
    let mut object = object;
    object.zeroize();
}

pub fn read_line(ln: &str) {
    print_ex!("{}", ln);
    io::stdout().flush().ok();
    let mut buff = String::new();
    let _ = io::stdin().read_line(&mut buff).expect("Read line from stdin");
}

pub fn ratio(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        return "∞".to_string();
    }
    let r = (numerator * 10000) / denominator;
    format!("{:.2}", r as f64 / 100f64)
}

#[test]
fn test_simple_kdf() {
    assert_eq!("30edbc354e8cf656adcddbeefbf3f5073372cdc42e4eca2e797bda8abebb6a05",
               hex::encode(simple_kdf(b"")));
    assert_eq!("0624d2a57bcb50f70aa19bab9fa75af1ca66cc701c341df865d430e2e6d9d936",
               hex::encode(simple_kdf(b"hello")));
    assert_eq!("43367d255eddedc3c84b692b68de6d3d21da28caad6abd20ed85a4f2c89706ad",
               hex::encode(simple_kdf(b"hello world")));
}

