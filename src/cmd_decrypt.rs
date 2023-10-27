use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use clap::Args;
use openpgp_card::crypto_data::Cryptogram;
use rust_util::{debugging, failure, iff, information, opt_result, println_ex, simple_error, success, util_msg, warning, XResult};
use rust_util::util_time::UnixEpochTime;
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;
use yubikey::piv::{AlgorithmId, decrypt_data};
use yubikey::YubiKey;
use zeroize::Zeroize;

use crate::{consts, crypto_simple, util, util_enc_file, util_envelop, util_file, util_pgp, util_piv};
use crate::compress::GzStreamDecoder;
use crate::config::TinyEncryptConfig;
use crate::consts::{
    DATE_TIME_FORMAT,
    ENC_AES256_GCM_P256, ENC_AES256_GCM_P384, ENC_AES256_GCM_X25519,
    ENC_CHACHA20_POLY1305_P256, ENC_CHACHA20_POLY1305_P384, ENC_CHACHA20_POLY1305_X25519,
    SALT_COMMENT, TINY_ENC_CONFIG_FILE, TINY_ENC_FILE_EXT,
};
use crate::crypto_cryptor::{Cryptor, KeyNonce};
use crate::spec::{EncEncryptedMeta, TinyEncryptEnvelop, TinyEncryptEnvelopType, TinyEncryptMeta};
use crate::util::SecVec;
use crate::util_digest::DigestWrite;
use crate::util_progress::Progress;
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
    #[arg(long, short = 'S')]
    pub skip_decrypt_file: bool,
    /// Direct print to the console, file must less than 10K
    #[arg(long, short = 'P')]
    pub direct_print: bool,
    /// Split std out and std err
    #[arg(long)]
    pub split_print: bool,
    /// Digest file
    #[arg(long, short = 'D')]
    pub digest_file: bool,
    /// Digest algorithm (sha1, sha256[default], sha384, sha512 ...)
    #[arg(long, short = 'A')]
    pub digest_algorithm: Option<String>,
}

impl Drop for CmdDecrypt {
    fn drop(&mut self) {
        if let Some(p) = self.pin.as_mut() { p.zeroize(); }
    }
}

pub fn decrypt(cmd_decrypt: CmdDecrypt) -> XResult<()> {
    if cmd_decrypt.split_print { util_msg::set_logger_std_out(false); }
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
    let (_, meta) = opt_result!(
        util_enc_file::read_tiny_encrypt_meta_and_normalize(&mut file_in), "Read file: {}, failed: {}", &path_display);
    debugging!("Found meta: {}", serde_json::to_string_pretty(&meta).unwrap());

    let encryption_algorithm = meta.encryption_algorithm.as_deref()
        .unwrap_or(consts::TINY_ENC_AES_GCM);
    let cryptor = Cryptor::from(encryption_algorithm)?;

    let do_skip_file_out = cmd_decrypt.skip_decrypt_file || cmd_decrypt.direct_print || cmd_decrypt.digest_file;
    let path_out = &path_display[0..path_display.len() - TINY_ENC_FILE_EXT.len()];
    if !do_skip_file_out { util::require_file_not_exists(path_out)?; }

    let digest_algorithm = match &cmd_decrypt.digest_algorithm {
        None => "sha256",
        Some(algo) => algo.as_str(),
    };
    if cmd_decrypt.digest_file { DigestWrite::from_algo(digest_algorithm)?; } // QUICK CHECK

    let selected_envelop = select_envelop(&meta, config)?;

    let key = SecVec(try_decrypt_key(config, selected_envelop, pin, slot)?);
    let nonce = SecVec(opt_result!(util::decode_base64(&meta.nonce), "Decode nonce failed: {}"));
    let key_nonce = KeyNonce { k: &key.0, n: &nonce.0 };

    // debugging!("Decrypt key: {}", hex::encode(&key.0));
    debugging!("Decrypt nonce: {}", hex::encode(&nonce.0));

    let enc_meta = parse_encrypted_meta(&meta, cryptor, &key_nonce)?;
    parse_encrypted_comment(&meta, cryptor, &key_nonce)?;

    // Decrypt to output
    if cmd_decrypt.direct_print {
        if meta.file_length > 10 * 1024 {
            warning!("File too large(more than 10K) cannot direct print on console.");
            return Ok(0);
        }

        let mut output: Vec<u8> = Vec::with_capacity(10 * 1024);
        let _ = decrypt_file(
            &mut file_in, meta.file_length, &mut output, cryptor, &key_nonce, meta.compress,
        )?;
        match String::from_utf8(output) {
            Err(_) => warning!("File is not UTF-8 content."),
            Ok(output) => if cmd_decrypt.split_print {
                print!("{}", &output)
            } else {
                println!(">>>>> BEGIN CONTENT >>>>>\n{}\n<<<<< END CONTENT <<<<<", &output)
            }
        }
        return Ok(meta.file_length);
    }

    // Digest file
    if cmd_decrypt.digest_file {
        let mut digest_write = DigestWrite::from_algo(digest_algorithm)?;
        let _ = decrypt_file(
            &mut file_in, meta.file_length, &mut digest_write, cryptor, &key_nonce, meta.compress,
        )?;
        let digest = digest_write.digest();
        success!("File digest {}: {}", digest_algorithm.to_uppercase(), hex::encode(digest));
        return Ok(meta.file_length);
    }

    if cmd_decrypt.skip_decrypt_file {
        information!("Decrypt file content is skipped.");
        return Ok(0);
    }

    // Decrypt to file
    let compressed_desc = iff!(meta.compress, " [compressed]", "");
    let start = Instant::now();

    let mut file_out = File::create(path_out)?;
    let _ = decrypt_file(
        &mut file_in, meta.file_length, &mut file_out, cryptor, &key_nonce, meta.compress,
    )?;
    drop(file_out);
    util_file::update_out_file_time(enc_meta, path_out);

    let encrypt_duration = start.elapsed();
    debugging!("Inner decrypt file{}: {} elapsed: {} ms", compressed_desc, path_display, encrypt_duration.as_millis());

    if do_skip_file_out && cmd_decrypt.remove_file { util::remove_file_with_msg(path); }
    Ok(meta.file_length)
}

fn decrypt_file(file_in: &mut File, file_len: u64, file_out: &mut impl Write,
                cryptor: Cryptor, key_nonce: &KeyNonce, compress: bool) -> XResult<u64> {
    let mut total_len = 0_u64;
    let mut buffer = [0u8; 1024 * 8];
    let progress = Progress::new(file_len);
    let mut decryptor = cryptor.decryptor(key_nonce)?;
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
            progress.finish();
            break;
        } else {
            total_len += len as u64;
            let decrypted = decryptor.update(&buffer[0..len]);
            let decrypted = if compress {
                opt_result!(gz_decoder.update(&decrypted), "Decompress file failed: {}")
            } else {
                decrypted
            };
            opt_result!(file_out.write_all(&decrypted), "Write file failed: {}");
            progress.position(total_len);
        }
    }
    Ok(total_len)
}

fn parse_encrypted_comment(meta: &TinyEncryptMeta, crypto: Cryptor, key_nonce: &KeyNonce) -> XResult<()> {
    if let Some(encrypted_comment) = &meta.encrypted_comment {
        match util::decode_base64(encrypted_comment) {
            Err(e) => warning!("Decode encrypted comment failed: {}", e),
            Ok(ec_bytes) => match crypto_simple::try_decrypt_with_salt(crypto, key_nonce, SALT_COMMENT, &ec_bytes) {
                Err(e) => warning!("Decrypt encrypted comment failed: {}", e),
                Ok(decrypted_comment_bytes) => match String::from_utf8(decrypted_comment_bytes.clone()) {
                    Err(_) => success!("Encrypted message hex: {}", hex::encode(&decrypted_comment_bytes)),
                    Ok(message) => success!("Encrypted comment: {}", message),
                }
            }
        }
    }
    Ok(())
}

fn parse_encrypted_meta(meta: &TinyEncryptMeta, cryptor: Cryptor, key_nonce: &KeyNonce) -> XResult<Option<EncEncryptedMeta>> {
    let enc_encrypted_meta = match &meta.encrypted_meta {
        None => return Ok(None),
        Some(enc_encrypted_meta) => enc_encrypted_meta,
    };
    let enc_encrypted_meta_bytes = opt_result!(
            util::decode_base64(enc_encrypted_meta), "Decode enc-encrypted-meta failed: {}");
    let enc_meta = opt_result!(
            EncEncryptedMeta::unseal(cryptor, key_nonce, &enc_encrypted_meta_bytes), "Unseal enc-encrypted-meta failed: {}");
    debugging!("Encrypted meta: {:?}", enc_meta);
    if let Some(filename) = &enc_meta.filename {
        information!("Source filename: {}", filename);
    }
    let fmt = simpledateformat::fmt(DATE_TIME_FORMAT).unwrap();
    if let Some(c_time) = &enc_meta.c_time {
        information!("Source file create time: {}", fmt.format_local(SystemTime::from_millis(*c_time)));
    }
    if let Some(m_time) = &enc_meta.c_time {
        information!("Source file modified time: {}", fmt.format_local(SystemTime::from_millis(*m_time)));
    }
    Ok(Some(enc_meta))
}

fn try_decrypt_key(config: &Option<TinyEncryptConfig>,
                   envelop: &TinyEncryptEnvelop,
                   pin: &Option<String>,
                   slot: &Option<String>) -> XResult<Vec<u8>> {
    match envelop.r#type {
        TinyEncryptEnvelopType::Pgp => try_decrypt_key_pgp(envelop, pin),
        TinyEncryptEnvelopType::PgpX25519 => try_decrypt_key_ecdh_pgp_x25519(envelop, pin),
        TinyEncryptEnvelopType::Ecdh | TinyEncryptEnvelopType::EcdhP384 => try_decrypt_key_ecdh(config, envelop, pin, slot),
        unknown_type => simple_error!("Unknown or unsupported type: {}", unknown_type.get_name()),
    }
}

fn try_decrypt_key_ecdh(config: &Option<TinyEncryptConfig>,
                        envelop: &TinyEncryptEnvelop,
                        pin: &Option<String>,
                        slot: &Option<String>) -> XResult<Vec<u8>> {
    let wrap_key = WrapKey::parse(&envelop.encrypted_key)?;
    let (cryptor, algo_id) = match wrap_key.header.enc.as_str() {
        ENC_AES256_GCM_P256 => (Cryptor::Aes256Gcm, AlgorithmId::EccP256),
        ENC_AES256_GCM_P384 => (Cryptor::Aes256Gcm, AlgorithmId::EccP384),
        ENC_CHACHA20_POLY1305_P256 => (Cryptor::ChaCha20Poly1305, AlgorithmId::EccP256),
        ENC_CHACHA20_POLY1305_P384 => (Cryptor::ChaCha20Poly1305, AlgorithmId::EccP384),
        _ => return simple_error!("Unsupported header enc: {}", &wrap_key.header.enc),
    };
    let e_pub_key = &wrap_key.header.e_pub_key;
    let e_pub_key_bytes = opt_result!(util::decode_base64_url_no_pad(e_pub_key), "Invalid envelop: {}");
    let (_, subject_public_key_info) = opt_result!(
        SubjectPublicKeyInfo::from_der(&e_pub_key_bytes), "Invalid envelop: {}");

    let slot = util_piv::read_piv_slot(config, &envelop.kid, slot)?;
    let pin = util::read_pin(pin);
    let epk_bytes = subject_public_key_info.subject_public_key.as_ref();

    let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
    let slot_id = util_piv::get_slot_id(&slot)?;
    opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");

    let shared_secret = opt_result!(decrypt_data(
                &mut yk,
                epk_bytes,
                algo_id,
                slot_id,
            ), "Decrypt via PIV card failed: {}");
    let key = util::simple_kdf(shared_secret.as_slice());
    let key_nonce = KeyNonce { k: &key, n: &wrap_key.nonce };
    let decrypted_key = crypto_simple::decrypt(
        cryptor, &key_nonce, &wrap_key.encrypted_data)?;
    util::zeroize(pin);
    util::zeroize(key);
    util::zeroize(shared_secret);
    Ok(decrypted_key)
}

fn try_decrypt_key_ecdh_pgp_x25519(envelop: &TinyEncryptEnvelop, pin: &Option<String>) -> XResult<Vec<u8>> {
    let wrap_key = WrapKey::parse(&envelop.encrypted_key)?;
    let cryptor = match wrap_key.header.enc.as_str() {
        ENC_AES256_GCM_X25519 => Cryptor::Aes256Gcm,
        ENC_CHACHA20_POLY1305_X25519 => Cryptor::ChaCha20Poly1305,
        _ => return simple_error!("Unsupported header enc: {}", &wrap_key.header.enc),
    };
    let e_pub_key = &wrap_key.header.e_pub_key;
    let epk_bytes = opt_result!(util::decode_base64_url_no_pad(e_pub_key), "Invalid envelop: {}");

    let mut pgp = util_pgp::get_openpgp()?;
    let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");

    util_pgp::read_and_verify_openpgp_pin(&mut trans, pin)?;

    let shared_secret = trans.decipher(Cryptogram::ECDH(&epk_bytes))?;

    let key = util::simple_kdf(shared_secret.as_slice());
    let key_nonce = KeyNonce { k: &key, n: &wrap_key.nonce };
    let decrypted_key = crypto_simple::decrypt(
        cryptor, &key_nonce, &wrap_key.encrypted_data)?;
    util::zeroize(key);
    util::zeroize(shared_secret);
    Ok(decrypted_key)
}

fn try_decrypt_key_pgp(envelop: &TinyEncryptEnvelop, pin: &Option<String>) -> XResult<Vec<u8>> {
    let mut pgp = util_pgp::get_openpgp()?;
    let mut trans = opt_result!(pgp.transaction(), "Open card failed: {}");

    util_pgp::read_and_verify_openpgp_pin(&mut trans, pin)?;

    let pgp_envelop = &envelop.encrypted_key;
    debugging!("PGP envelop: {}", &pgp_envelop);
    let pgp_envelop_bytes = opt_result!(util::decode_base64(pgp_envelop), "Decode PGP envelop failed: {}");

    let key = trans.decipher(Cryptogram::RSA(&pgp_envelop_bytes))?;
    Ok(key)
}

fn select_envelop<'a>(meta: &'a TinyEncryptMeta, config: &Option<TinyEncryptConfig>) -> XResult<&'a TinyEncryptEnvelop> {
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
        success!("Auto selected envelop: #{} {}", 1, util_envelop::format_envelop(selected_envelop, config));
        util::read_line("Press enter to continue: ");
        return Ok(selected_envelop);
    }

    envelops.iter().enumerate().for_each(|(i, envelop)| {
        println_ex!("#{} {}", i + 1, util_envelop::format_envelop(envelop, config));
    });

    let envelop_number = util::read_number("Please select an envelop:", 1, envelops.len());
    let selected_envelop = &envelops[envelop_number - 1];
    success!("Selected envelop: #{} {}", envelop_number, selected_envelop.r#type.get_upper_name());
    Ok(selected_envelop)
}