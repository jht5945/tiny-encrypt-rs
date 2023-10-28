use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use clap::Args;
use rust_util::{debugging, information, opt_result, simple_error, success, warning, XResult};
use zeroize::Zeroize;

use crate::crypto_cryptor::{Cryptor, KeyNonce};
use crate::util;
use crate::util_progress::Progress;

#[derive(Debug, Args)]
pub struct CmdDirectDecrypt {
    /// Files in
    #[arg(long, short = 'i')]
    pub file_in: PathBuf,
    /// Files output
    #[arg(long, short = 'o')]
    pub file_out: PathBuf,
    /// Remove source file
    #[arg(long, short = 'R')]
    pub remove_file: bool,
    /// Key in HEX
    #[arg(long, short = 'k')]
    pub key: String,
}

impl Drop for CmdDirectDecrypt {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

const DIRECT_ENCRYPT_MAGIC: &str = "e2c50001";

// Format
// [4 bytes] - magic 0xe2c50001
// [32 bytes] - key digest
// [12 bytes] - nonce
pub fn direct_decrypt(cmd_direct_decrypt: CmdDirectDecrypt) -> XResult<()> {
    let key = opt_result!(hex::decode(&cmd_direct_decrypt.key), "Parse key failed: {}");
    if key.len() != 32 {
        return simple_error!("Key length error, must be AES256.");
    }

    let mut file_in = opt_result!(File::open(&cmd_direct_decrypt.file_in), "Open in file failed: {}");
    let file_in_len = file_in.metadata().map(|m| m.len()).unwrap_or(0);
    if fs::metadata(&cmd_direct_decrypt.file_out).is_ok() {
        return simple_error!("Out file exists.");
    }

    let mut magic = [0_u8; 4];
    opt_result!(file_in.read_exact(&mut magic), "Read magic failed: {}");
    if hex::encode(magic) != DIRECT_ENCRYPT_MAGIC {
        return simple_error!("File magic mismatch.");
    }
    let mut key_digest = [0_u8; 32];
    opt_result!(file_in.read_exact(&mut key_digest), "Read key digest failed: {}");
    if sha256::digest(&key) != hex::encode(key_digest) {
        debugging!("Key digest mismatch: {} vs {}", sha256::digest(&key), hex::encode(key_digest));
        return simple_error!("Key digest mismatch.");
    }
    let mut nonce = [0_u8; 12];
    opt_result!(file_in.read_exact(&mut nonce), "Read nonce failed: {}");

    let mut file_out = opt_result!(File::create(&cmd_direct_decrypt.file_out), "Create out file failed: {}");
    let key_nonce = KeyNonce { k: &key, n: &nonce };
    let instant = Instant::now();
    let decrypted_len = opt_result!(
        decrypt_file(&mut file_in, file_in_len, &mut file_out, Cryptor::Aes256Gcm, &key_nonce),
        "Decrypt file {} -> {}, failed: {}",
        cmd_direct_decrypt.file_in.display(),
        cmd_direct_decrypt.file_out.display()
    );
    let elapsed_millis = instant.elapsed().as_millis();
    success!("Decrypt file succeed: {}, file size: {} byte(s), elapsed: {} ms",
        cmd_direct_decrypt.file_out.display(), decrypted_len, elapsed_millis);

    util::zeroize(key);
    nonce.zeroize();
    drop(file_in);
    drop(file_out);

    if cmd_direct_decrypt.remove_file {
        information!("Remove in file: {}", cmd_direct_decrypt.file_in.display());
        if let Err(e) = fs::remove_file(&cmd_direct_decrypt.file_in) {
            warning!("Remove in file failed: {}", e);
        }
    }

    Ok(())
}


fn decrypt_file(file_in: &mut File, file_len: u64, file_out: &mut impl Write,
                cryptor: Cryptor, key_nonce: &KeyNonce) -> XResult<u64> {
    let mut total_len = 0_u64;
    let mut buffer = [0u8; 1024 * 8];
    let progress = Progress::new(file_len);
    let mut decryptor = cryptor.decryptor(key_nonce)?;
    loop {
        let len = opt_result!(file_in.read(&mut buffer), "Read file failed: {}");
        if len == 0 {
            let last_block = opt_result!(decryptor.finalize(), "Decrypt file failed: {}");
            opt_result!(file_out.write_all(&last_block), "Write file failed: {}");
            progress.finish();
            debugging!("Decrypt finished, total: {} byte(s)", total_len);
            break;
        } else {
            total_len += len as u64;
            let decrypted = decryptor.update(&buffer[0..len]);
            opt_result!(file_out.write_all(&decrypted), "Write file failed: {}");
            progress.position(total_len);
        }
    }
    Ok(total_len)
}