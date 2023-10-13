use std::{fs, io};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use clap::Args;
use openpgp_card::{OpenPgp, OpenPgpTransaction};
use openpgp_card::crypto_data::Cryptogram;
use rust_util::{
    debugging, failure, iff, information, opt_result, simple_error, success,
    util_msg, util_term, warning, XResult,
};
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;
use yubikey::piv::{AlgorithmId, decrypt_data};
use yubikey::YubiKey;
use zeroize::Zeroize;

use crate::{card, file, util, util_piv};
use crate::compress::GzStreamDecoder;
use crate::config::TinyEncryptConfig;
use crate::crypto_aes::{aes_gcm_decrypt, try_aes_gcm_decrypt_with_salt};
use crate::spec::{EncEncryptedMeta, TinyEncryptEnvelop, TinyEncryptEnvelopType, TinyEncryptMeta};
use crate::util::{ENC_AES256_GCM_P256, ENC_AES256_GCM_P384, ENC_AES256_GCM_X25519, SALT_COMMENT, TINY_ENC_CONFIG_FILE, TINY_ENC_FILE_EXT};
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
    /// Skip decrypt file
    #[arg(long)]
    pub skip_decrypt_file: bool,
}

pub fn decrypt(cmd_decrypt: CmdDecrypt) -> XResult<()> {
    debugging!("Cmd decrypt: {:?}", cmd_decrypt);
    let config = TinyEncryptConfig::load(TINY_ENC_CONFIG_FILE).ok();

    let start = Instant::now();
    let mut succeed_count = 0;
    let mut failed_count = 0;
    let mut total_len = 0_u64;
    for path in &cmd_decrypt.paths {
        let start_decrypt_single = Instant::now();
        match decrypt_single(&config, path, &cmd_decrypt.pin, &cmd_decrypt.slot, &cmd_decrypt) {
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

pub fn decrypt_single(config: &Option<TinyEncryptConfig>,
                      path: &PathBuf,
                      pin: &Option<String>,
                      slot: &Option<String>,
                      cmd_decrypt: &CmdDecrypt) -> XResult<u64> {
    let path_display = format!("{}", path.display());
    util::require_tiny_enc_file_and_exists(path)?;

    let mut file_in = opt_result!(File::open(path), "Open file: {} failed: {}", &path_display);
    let meta = opt_result!(file::read_tiny_encrypt_meta_and_normalize(&mut file_in), "Read file: {}, failed: {}", &path_display);
    debugging!("Found meta: {}", serde_json::to_string_pretty(&meta).unwrap());

    let path_out = &path_display[0..path_display.len() - TINY_ENC_FILE_EXT.len()];
    util::require_file_not_exists(path_out)?;

    let selected_envelop = select_envelop(&meta)?;

    let key = try_decrypt_key(config, selected_envelop, pin, slot)?;
    let nonce = opt_result!(util::decode_base64(&meta.nonce), "Decode nonce failed: {}");

    debugging!("Decrypt key: {}", hex::encode(&key));
    debugging!("Decrypt nonce: {}", hex::encode(&nonce));

    if let Some(enc_encrypted_meta) = &meta.encrypted_meta {
        let enc_encrypted_meta_bytes = opt_result!(
            util::decode_base64(enc_encrypted_meta), "Decode enc-encrypted-meta failed: {}");
        let enc_meta = opt_result!(
            EncEncryptedMeta::unseal(&key, &nonce, &enc_encrypted_meta_bytes), "Unseal enc-encrypted-meta failed: {}");
        if let Some(filename) = &enc_meta.filename {
            information!("Source filename: {}", filename);
        }
    }

    if let Some(encrypted_comment) = &meta.encrypted_comment {
        match util::decode_base64(encrypted_comment) {
            Err(e) => warning!("Decode encrypted comment failed: {}", e),
            Ok(ec_bytes) => match try_aes_gcm_decrypt_with_salt(&key, &nonce, SALT_COMMENT, &ec_bytes) {
                Err(e) => warning!("Decrypt encrypted comment failed: {}", e),
                Ok(decrypted_comment_bytes) => match String::from_utf8(decrypted_comment_bytes.clone()) {
                    Err(_) => success!("Encrypted message hex: {}", hex::encode(&decrypted_comment_bytes)),
                    Ok(message) => success!("Encrypted comment: {}", message),
                }
            }
        }
    }

    if cmd_decrypt.skip_decrypt_file {
        information!("Decrypt file is skipped.");
    } else {
        let mut file_out = File::create(path_out)?;

        let start = Instant::now();
        util_msg::print_lastline(
            &format!("Decrypting file: {}{} ...", path_display, iff!(meta.compress, " [compressed]", ""))
        );
        let _ = decrypt_file(&mut file_in, &mut file_out, &key, &nonce, meta.compress)?;
        util_msg::clear_lastline();
        let encrypt_duration = start.elapsed();
        debugging!("Encrypt file: {} elapsed: {} ms", path_display, encrypt_duration.as_millis());
        drop(file_out);
    }

    util::zeroize(key);
    util::zeroize(nonce);
    drop(file_in);
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
    let mut decryptor = aes_gcm_stream::Aes256GcmStreamDecryptor::new(key, nonce);
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

fn try_decrypt_key(config: &Option<TinyEncryptConfig>,
                   envelop: &TinyEncryptEnvelop,
                   pin: &Option<String>,
                   slot: &Option<String>) -> XResult<Vec<u8>> {
    match envelop.r#type {
        TinyEncryptEnvelopType::Pgp => try_decrypt_key_pgp(envelop, pin),
        TinyEncryptEnvelopType::PgpX25519 => try_decrypt_key_ecdh_pgp_x25519(envelop, pin),
        TinyEncryptEnvelopType::Ecdh => try_decrypt_key_ecdh(config, envelop, pin, ENC_AES256_GCM_P256, slot),
        TinyEncryptEnvelopType::EcdhP384 => try_decrypt_key_ecdh(config, envelop, pin, ENC_AES256_GCM_P384, slot),
        unknown_type => simple_error!("Unknown or not supported type: {}", unknown_type.get_name()),
    }
}

fn try_decrypt_key_ecdh(config: &Option<TinyEncryptConfig>,
                        envelop: &TinyEncryptEnvelop,
                        pin: &Option<String>,
                        expected_enc_type: &str,
                        slot: &Option<String>) -> XResult<Vec<u8>> {
    let wrap_key = WrapKey::parse(&envelop.encrypted_key)?;
    if wrap_key.header.enc.as_str() != expected_enc_type {
        return simple_error!("Unsupported header requires: {}, actual: {}", expected_enc_type, &wrap_key.header.enc);
    }
    let e_pub_key = &wrap_key.header.e_pub_key;
    let e_pub_key_bytes = opt_result!(util::decode_base64_url_no_pad(e_pub_key), "Invalid envelop: {}");
    let (_, subject_public_key_info) = opt_result!(SubjectPublicKeyInfo::from_der(&e_pub_key_bytes), "Invalid envelop: {}");

    let slot = read_slot(config, &envelop.kid, slot)?;
    let pin = read_pin(pin);
    let epk_bytes = subject_public_key_info.subject_public_key.as_ref();

    let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
    let slot_id = util_piv::get_slot_id(&slot)?;
    opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");
    let algo_id = iff!(
        expected_enc_type == ENC_AES256_GCM_P256, AlgorithmId::EccP256, AlgorithmId::EccP384
    );
    let shared_secret = opt_result!(decrypt_data(
                &mut yk,
                epk_bytes,
                algo_id,
                slot_id,
            ), "Decrypt via PIV card failed: {}");
    let key = util::simple_kdf(shared_secret.as_slice());
    let decrypted_key = aes_gcm_decrypt(&key, &wrap_key.nonce, &wrap_key.encrypted_data)?;
    util::zeroize(key);
    util::zeroize(shared_secret);
    Ok(decrypted_key)
}

fn try_decrypt_key_ecdh_pgp_x25519(envelop: &TinyEncryptEnvelop, pin: &Option<String>) -> XResult<Vec<u8>> {
    let wrap_key = WrapKey::parse(&envelop.encrypted_key)?;
    if wrap_key.header.enc.as_str() != ENC_AES256_GCM_X25519 {
        return simple_error!("Unsupported header requires: {}, actual: {}", ENC_AES256_GCM_X25519, &wrap_key.header.enc);
    }
    let e_pub_key = &wrap_key.header.e_pub_key;
    let epk_bytes = opt_result!(util::decode_base64_url_no_pad(e_pub_key), "Invalid envelop: {}");

    let mut pgp = get_openpgp()?;
    let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");

    read_and_verify_openpgp_pin(&mut trans, pin)?;

    let shared_secret = trans.decipher(Cryptogram::ECDH(&epk_bytes))?;

    let key = util::simple_kdf(shared_secret.as_slice());
    let decrypted_key = aes_gcm_decrypt(&key, &wrap_key.nonce, &wrap_key.encrypted_data)?;
    util::zeroize(key);
    util::zeroize(shared_secret);
    Ok(decrypted_key)
}

fn try_decrypt_key_pgp(envelop: &TinyEncryptEnvelop, pin: &Option<String>) -> XResult<Vec<u8>> {
    let mut pgp = get_openpgp()?;
    let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");

    read_and_verify_openpgp_pin(&mut trans, pin)?;

    let pgp_envelop = &envelop.encrypted_key;
    debugging!("PGP envelop: {}", &pgp_envelop);
    let pgp_envelop_bytes = opt_result!(util::decode_base64(pgp_envelop), "Decode PGP envelop failed: {}");

    let key = trans.decipher(Cryptogram::RSA(&pgp_envelop_bytes))?;
    Ok(key)
}

fn read_and_verify_openpgp_pin(trans: &mut OpenPgpTransaction, pin: &Option<String>) -> XResult<()> {
    let pin = read_pin(pin);
    if let Err(e) = trans.verify_pw1_user(pin.as_ref()) {
        failure!("Verify user pin failed: {}", e);
        return simple_error!("User pin verify failed: {}", e);
    }
    success!("User pin verify success!");
    Ok(())
}

fn get_openpgp() -> XResult<OpenPgp> {
    let card = match card::get_card() {
        Err(e) => {
            failure!("Get PGP card failed: {}", e);
            return simple_error!("Get card failed: {}", e);
        }
        Ok(card) => card
    };
    Ok(OpenPgp::new(card))
}

fn read_slot(config: &Option<TinyEncryptConfig>, kid: &str, slot: &Option<String>) -> XResult<String> {
    match slot {
        Some(slot) => Ok(slot.to_string()),
        None => {
            if let Some(config) = config {
                if let Some(first_arg) = config.find_first_arg_by_kid(kid) {
                    information!("Found kid: {}'s slot: {}", kid, first_arg);
                    return Ok(first_arg.to_string());
                }
            }
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
        util::read_line("Press enter to continue: ");
        return Ok(selected_envelop);
    }

    envelops.iter().enumerate().for_each(|(i, envelop)| {
        let kid = iff!(envelop.kid.is_empty(), "".into(), format!(", Kid: {}", envelop.kid));
        let desc = envelop.desc.as_ref()
            .map(|desc| format!(", Desc: {}", desc))
            .unwrap_or_else(|| "".to_string());
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