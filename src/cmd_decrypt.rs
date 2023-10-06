use std::{fs, io};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Instant;

use clap::Args;
use openpgp_card::crypto_data::Cryptogram;
use openpgp_card::OpenPgp;
use rust_util::{debugging, failure, iff, information, opt_result, simple_error, success, util_msg, util_term, warning, XResult};
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;
use yubikey::piv::{AlgorithmId, decrypt_data, RetiredSlotId, SlotId};
use yubikey::YubiKey;
use zeroize::Zeroize;

use crate::{card, file, util};
use crate::compress::GzStreamDecoder;
use crate::crypto_aes::aes_gcm_decrypt;
use crate::spec::{TinyEncryptEnvelop, TinyEncryptEnvelopType, TinyEncryptMeta};
use crate::util::{ENC_AES256_GCM_P256, TINY_ENC_FILE_EXT};
use crate::wrap_key::WrapKey;

#[derive(Debug, Args)]
pub struct CmdDecrypt {
    /// Files need to be decrypted
    pub paths: Vec<PathBuf>,
    /// PIN
    #[arg(long, short = 'p')]
    pub pin: Option<String>,
    /// Slot
    #[arg(long, short = 's')]
    pub slot: Option<String>,
    /// Remove source file
    #[arg(long, short = 'R')]
    pub remove_file: bool,
}

pub fn decrypt(cmd_decrypt: CmdDecrypt) -> XResult<()> {
    debugging!("Cmd decrypt: {:?}", cmd_decrypt);
    let start = Instant::now();
    let mut succeed_count = 0;
    let mut failed_count = 0;
    let mut total_len = 0_u64;
    for path in &cmd_decrypt.paths {
        let start_decrypt_single = Instant::now();
        match decrypt_single(path, &cmd_decrypt.pin, &cmd_decrypt.slot, &cmd_decrypt) {
            Ok(len) => {
                succeed_count += 1;
                total_len += len;
                success!(
                    "Decrypt {} succeed, cost {} ms, file size {} byte(s)",
                    path.to_str().unwrap_or("N/A"),
                    start_decrypt_single.elapsed().as_millis(),
                    len
                );
            }
            Err(e) => {
                failed_count += 1;
                failure!("Decrypt {} failed: {}", path.to_str().unwrap_or("N/A"), e);
            }
        }
    }
    if (succeed_count + failed_count) > 1 {
        success!(
            "Decrypt succeed {} file(s) {} byte(s), failed {} file(s), total cost {} ms",
            succeed_count,
            total_len,
            failed_count,
            start.elapsed().as_millis(),
        );
    }
    Ok(())
}

pub fn decrypt_single(path: &PathBuf, pin: &Option<String>, slot: &Option<String>, cmd_decrypt: &CmdDecrypt) -> XResult<u64> {
    let path_display = format!("{}", path.display());
    util::require_tiny_enc_file_and_exists(path)?;

    let mut file_in = opt_result!(File::open(path), "Open file: {} failed: {}", &path_display);
    let meta = opt_result!(file::read_tiny_encrypt_meta_and_normalize(&mut file_in), "Read file: {}, failed: {}", &path_display);
    debugging!("Found meta: {}", serde_json::to_string_pretty(&meta).unwrap());

    let path_out = &path_display[0..path_display.len() - TINY_ENC_FILE_EXT.len()];
    util::require_file_not_exists(path_out)?;

    let selected_envelop = select_envelop(&meta)?;

    let key = try_decrypt_key(selected_envelop, pin, slot)?;
    let nonce = opt_result!(util::decode_base64(&meta.nonce), "Decode nonce failed: {}");

    debugging!("Decrypt key: {}", hex::encode(&key));
    debugging!("Decrypt nonce: {}", hex::encode(&nonce));

    let mut file_out = File::create(path_out)?;

    let start = Instant::now();
    util_msg::print_lastline(
        &format!("Decrypting file: {}{} ...", path_display, iff!(meta.compress, " [compressed]", ""))
    );
    let _ = decrypt_file(&mut file_in, &mut file_out, &key, &nonce, meta.compress)?;
    util_msg::clear_lastline();
    let encrypt_duration = start.elapsed();
    debugging!("Encrypt file: {} elapsed: {} ms", path_display, encrypt_duration.as_millis());

    util::zeroize(key);
    util::zeroize(nonce);
    drop(file_in);
    drop(file_out);
    if cmd_decrypt.remove_file {
        match fs::remove_file(path) {
            Err(e) => warning!("Remove file: {} failed: {}", path_display, e),
            Ok(_) => information!("Remove file: {} succeed", path_display),
        }
    }
    Ok(meta.file_length)
}

fn decrypt_file(file_in: &mut File, file_out: &mut File, key: &[u8], nonce: &[u8], compress: bool) -> XResult<usize> {
    let mut total_len = 0;
    let mut buffer = [0u8; 1024 * 8];
    let key = opt_result!(key.try_into(), "Key is not 32 bytes: {}");
    let mut decryptor = aes_gcm_stream::Aes256GcmStreamDecryptor::new(key, &nonce);
    let mut gz_decoder = GzStreamDecoder::new();
    loop {
        let len = opt_result!(file_in.read(&mut buffer), "Read file failed: {}");
        if len == 0 {
            let last_block = opt_result!(decryptor.finalize(), "Decrypt file failed: {}");
            let last_block = if compress {
                let mut decompressed = opt_result!(gz_decoder.update(&last_block), "Decompress file failed: {}");
                let last_decompressed_buffer = opt_result!(gz_decoder.finalize(), "Decompress file failed: {}");
                decompressed.extend_from_slice(&last_decompressed_buffer);
                decompressed
            } else {
                last_block
            };
            opt_result!(file_out.write_all(&last_block), "Write file failed: {}");
            debugging!("Decrypt finished, total bytes: {}", total_len);
            break;
        } else {
            total_len += len;
            let decrypted = decryptor.update(&buffer[0..len]);
            let decrypted = if compress {
                opt_result!(gz_decoder.update(&decrypted), "Decompress file failed: {}")
            } else {
                decrypted
            };
            opt_result!(file_out.write_all(&decrypted), "Write file failed: {}");
        }
    }
    let mut key = key;
    key.zeroize();
    Ok(total_len)
}

fn try_decrypt_key(envelop: &TinyEncryptEnvelop, pin: &Option<String>, slot: &Option<String>) -> XResult<Vec<u8>> {
    match envelop.r#type {
        TinyEncryptEnvelopType::Pgp => try_decrypt_key_pgp(envelop, pin),
        TinyEncryptEnvelopType::Ecdh => try_decrypt_key_ecdh(envelop, pin, slot),
        unknown_type => {
            return simple_error!("Unknown or not supported type: {}", unknown_type.get_name());
        }
    }
}

fn try_decrypt_key_ecdh(envelop: &TinyEncryptEnvelop, pin: &Option<String>, slot: &Option<String>) -> XResult<Vec<u8>> {
    let wrap_key = WrapKey::parse(&envelop.encrypted_key)?;
    if wrap_key.header.enc.as_str() != ENC_AES256_GCM_P256 {
        return simple_error!("Unsupported header enc.");
    }
    let e_pub_key = &wrap_key.header.e_pub_key;
    let e_pub_key_bytes = opt_result!(util::decode_base64_url_no_pad(e_pub_key), "Invalid envelop: {}");
    let (_, subject_public_key_info) = opt_result!(SubjectPublicKeyInfo::from_der(&e_pub_key_bytes), "Invalid envelop: {}");

    let slot = read_slot(slot)?;
    let pin = read_pin(pin);
    let epk_bytes = subject_public_key_info.subject_public_key.as_ref();

    let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
    let retired_slot_id = opt_result!(RetiredSlotId::from_str(&slot), "Slot not found: {}");
    let slot_id = SlotId::Retired(retired_slot_id);
    opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");
    let decrypted_shared_secret = opt_result!(decrypt_data(
                &mut yk,
                &epk_bytes,
                AlgorithmId::EccP256,
                slot_id,
            ), "Decrypt via PIV card failed: {}");
    let key = util::simple_kdf(decrypted_shared_secret.as_slice());
    let decrypted_key = aes_gcm_decrypt(&key, &wrap_key.nonce, &wrap_key.encrypted_data)?;
    util::zeroize(key);
    Ok(decrypted_key)
}

fn try_decrypt_key_pgp(envelop: &TinyEncryptEnvelop, pin: &Option<String>) -> XResult<Vec<u8>> {
    let card = match card::get_card() {
        Err(e) => {
            failure!("Get PGP card failed: {}", e);
            return simple_error!("Get card failed: {}", e);
        }
        Ok(card) => card
    };
    let mut pgp = OpenPgp::new(card);
    let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");

    let pin = read_pin(pin);
    if let Err(e) = trans.verify_pw1_user(pin.as_ref()) {
        failure!("Verify user pin failed: {}", e);
        return simple_error!("User pin verify failed: {}", e);
    }
    success!("User pin verify success!");

    let pgp_envelop = &envelop.encrypted_key;
    debugging!("PGP envelop: {}", &pgp_envelop);
    let pgp_envelop_bytes = opt_result!(util::decode_base64(&pgp_envelop), "Decode PGP envelop failed: {}");

    let key = trans.decipher(Cryptogram::RSA(&pgp_envelop_bytes))?;
    Ok(key)
}

fn read_slot(slot: &Option<String>) -> XResult<String> {
    match slot {
        Some(slot) => Ok(slot.to_string()),
        None => {
            print!("Input slot(eg 82, 83 ...): ");
            io::stdout().flush().ok();
            let mut buff = String::new();
            let _ = io::stdin().read_line(&mut buff).expect("Read line from stdin");
            if buff.trim().is_empty() {
                simple_error!("Slot is required, and not inputted")
            } else {
                Ok(buff.trim().to_string())
            }
        }
    }
}

fn read_pin(pin: &Option<String>) -> String {
    match pin {
        Some(pin) => pin.to_string(),
        None => if util_term::read_yes_no("Use default PIN 123456, please confirm") {
            "123456".into()
        } else {
            rpassword::prompt_password("Please input PIN: ").expect("Read PIN failed")
        }
    }
}

fn select_envelop(meta: &TinyEncryptMeta) -> XResult<&TinyEncryptEnvelop> {
    let envelops = match &meta.envelops {
        None => return simple_error!("No envelops found"),
        Some(envelops) => if envelops.is_empty() {
            return simple_error!("No envelops found");
        } else {
            envelops
        },
    };

    success!("Found {} envelops:", envelops.len());
    if envelops.len() == 1 {
        let selected_envelop = &envelops[0];
        success!("Auto selected envelop: #{} {}", 1, selected_envelop.r#type.get_upper_name());
        return Ok(selected_envelop);
    }

    envelops.iter().enumerate().for_each(|(i, envelop)| {
        let kid = iff!(envelop.kid.is_empty(), "".into(), format!(", Kid: {}", envelop.kid));
        let desc = envelop.desc.as_ref().map(|desc| format!(", Desc: {}", desc)).unwrap_or_else(|| "".to_string());
        println!("#{} {}{}{}", i + 1,
                 envelop.r#type.get_upper_name(),
                 kid,
                 desc,
        );
    });

    let envelop_number = util::read_number("Please select an envelop:", 1, envelops.len());
    let selected_envelop = &envelops[envelop_number - 1];
    success!("Selected envelop: #{} {}", envelop_number, selected_envelop.r#type.get_upper_name());
    Ok(selected_envelop)
}