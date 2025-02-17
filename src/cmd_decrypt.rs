use std::{env, fs};
use std::env::temp_dir;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Instant, SystemTime};

use clap::Args;
use dialoguer::console::Term;
use dialoguer::Select;
use dialoguer::theme::ColorfulTheme;
use flate2::Compression;
use openpgp_card::crypto_data::Cryptogram;
use rust_util::{
    debugging, failure, iff, information, opt_result, opt_value_result, println_ex, simple_error, success,
    util_cmd, util_msg, util_size, util_time, warning, XResult,
};
use rust_util::util_time::UnixEpochTime;
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;
use yubikey::piv::{AlgorithmId, decrypt_data};
use yubikey::YubiKey;
use zeroize::Zeroize;

use crate::{cmd_encrypt, config, consts, crypto_simple, util, util_enc_file, util_env, util_envelop, util_file, util_gpg, util_pgp, util_piv};
use crate::compress::GzStreamDecoder;
use crate::config::TinyEncryptConfig;
use crate::consts::{
    DATE_TIME_FORMAT,
    ENC_AES256_GCM_KYBER1204, ENC_AES256_GCM_P256, ENC_AES256_GCM_P384,
    ENC_AES256_GCM_X25519, ENC_CHACHA20_POLY1305_KYBER1204, ENC_CHACHA20_POLY1305_P256,
    ENC_CHACHA20_POLY1305_P384, ENC_CHACHA20_POLY1305_X25519,
    SALT_COMMENT, TINY_ENC_FILE_EXT,
};
use crate::crypto_cryptor::{Cryptor, KeyNonce};
use crate::spec::{EncEncryptedMeta, TinyEncryptEnvelop, TinyEncryptEnvelopType, TinyEncryptMeta};
use crate::util::SecVec;
use crate::util_digest::DigestWrite;
#[cfg(feature = "secure-enclave")]
use crate::util_keychainkey;
#[cfg(feature = "macos")]
use crate::util_keychainstatic;
#[cfg(feature = "macos")]
use crate::util_keychainstatic::KeychainKey;
use crate::util_progress::Progress;
use crate::wrap_key::WrapKey;

#[derive(Debug, Args)]
pub struct CmdDecrypt {
    /// PGP or PIV PIN
    #[arg(long, short = 'p')]
    pub pin: Option<String>,

    /// KeyID
    #[arg(long, short = 'k')]
    pub key_id: Option<String>,

    /// PIV slot
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

    /// Edit file
    #[arg(long, short = 'E')]
    pub edit_file: bool,

    /// Readonly mode
    #[arg(long)]
    pub readonly: bool,

    /// Digest algorithm (sha1, sha256[default], sha384, sha512 ...)
    #[arg(long, short = 'A')]
    pub digest_algorithm: Option<String>,

    /// Files need to be decrypted
    pub paths: Vec<PathBuf>,
}

impl Drop for CmdDecrypt {
    fn drop(&mut self) {
        if let Some(p) = self.pin.as_mut() { p.zeroize(); }
    }
}

pub fn decrypt(cmd_decrypt: CmdDecrypt) -> XResult<()> {
    if cmd_decrypt.split_print { util_msg::set_logger_std_out(false); }
    debugging!("Cmd decrypt: {:?}", cmd_decrypt);
    let config = TinyEncryptConfig::load_default().ok();

    let start = Instant::now();
    let mut succeed_count = 0;
    let mut failed_count = 0;
    let mut total_len = 0_u64;
    if cmd_decrypt.edit_file && (cmd_decrypt.paths.len() != 1) {
        return simple_error!("Edit mode only allows one file assigned.");
    }
    let pin = cmd_decrypt.pin.clone().or_else(util_env::get_pin);
    let key_id = cmd_decrypt.key_id.clone().or_else(util_env::get_key_id);

    for path in &cmd_decrypt.paths {
        let path = config::resolve_path_namespace(&config, path, true);
        let start_decrypt_single = Instant::now();
        match decrypt_single(&config, &path, &pin, &key_id, &cmd_decrypt.slot, &cmd_decrypt) {
            Ok(len) => {
                succeed_count += 1;
                if len > 0 {
                    total_len += len;
                    success!(
                        "Decrypt {} succeed, cost {} ms{}",
                        path.to_str().unwrap_or("N/A"),
                        start_decrypt_single.elapsed().as_millis(),
                        iff!(len == 0, "".to_string(), format!(", file size {}", util_size::get_display_size(len as i64)))
                    );
                }
            }
            Err(e) => {
                failed_count += 1;
                failure!("Decrypt {} failed: {}", path.to_str().unwrap_or("N/A"), e);
            }
        }
    }
    if (succeed_count + failed_count) > 1 {
        success!(
            "Decrypt succeed {} file(s) {}, failed {} file(s), total cost {} ms",
            succeed_count,
            util_size::get_display_size(total_len as i64),
            failed_count,
            start.elapsed().as_millis(),
        );
    }
    Ok(())
}

pub fn decrypt_single(config: &Option<TinyEncryptConfig>,
                      path: &PathBuf,
                      pin: &Option<String>,
                      key_id: &Option<String>,
                      slot: &Option<String>,
                      cmd_decrypt: &CmdDecrypt) -> XResult<u64> {
    let path_display = format!("{}", path.display());
    util::require_tiny_enc_file_and_exists(path)?;

    let mut file_in = opt_result!(File::open(path), "Open file: {} failed: {}", &path_display);
    let (_, is_meta_compressed, meta) = opt_result!(
        util_enc_file::read_tiny_encrypt_meta_and_normalize(&mut file_in), "Read file: {}, failed: {}", &path_display);
    util_msg::when_debug(|| {
        debugging!("Found meta: {}", serde_json::to_string_pretty(&meta).unwrap());
    });

    let encryption_algorithm = meta.encryption_algorithm.as_deref()
        .unwrap_or(consts::TINY_ENC_AES_GCM);
    let cryptor = Cryptor::from(encryption_algorithm)?;

    let do_skip_file_out = cmd_decrypt.skip_decrypt_file || cmd_decrypt.direct_print
        || cmd_decrypt.digest_file || cmd_decrypt.edit_file;
    let path_out = &path_display[0..path_display.len() - TINY_ENC_FILE_EXT.len()];
    if !do_skip_file_out { util::require_file_not_exists(path_out)?; }

    let digest_algorithm = cmd_decrypt.digest_algorithm.as_deref().unwrap_or("sha256");
    if cmd_decrypt.digest_file { DigestWrite::from_algo(digest_algorithm)?; } // FAST CHECK

    let selected_envelop = select_envelop(&meta, key_id, config, false)?;

    let key = SecVec(try_decrypt_key(config, selected_envelop, pin, slot, false)?);
    let nonce = SecVec(opt_result!(util::decode_base64(&meta.nonce), "Decode nonce failed: {}"));
    let key_nonce = KeyNonce { k: key.as_ref(), n: nonce.as_ref() };

    // debugging!("Decrypt key: {}", hex::encode(&key.0));
    util_msg::when_debug(|| debugging!("Decrypt nonce: {}", hex::encode(nonce.as_ref())));

    let enc_meta = parse_encrypted_meta(&meta, cryptor, &key_nonce)?;
    parse_encrypted_comment(&meta, cryptor, &key_nonce)?;

    // Decrypt to output
    if cmd_decrypt.direct_print {
        if let Some(output) = decrypt_limited_content_to_vec(&mut file_in, &meta, cryptor, &key_nonce)? {
            if cmd_decrypt.split_print {
                print!("{}", &output)
            } else {
                println!(">>>>> BEGIN CONTENT >>>>>\n{}\n<<<<< END CONTENT <<<<<", &output)
            }
            return Ok(meta.file_length);
        }
        return Ok(0);
    }

    // Edit file
    if cmd_decrypt.edit_file {
        let file_content = match decrypt_limited_content_to_vec(&mut file_in, &meta, cryptor, &key_nonce)? {
            None => return Ok(0),
            Some(output) => output,
        };
        let (secure_editor, editor) = get_file_editor();
        let temp_cryptor = Cryptor::Aes256Gcm;
        let temp_encryption_key_nonce = util::make_key256_and_nonce();
        let temp_key_nonce = KeyNonce { k: temp_encryption_key_nonce.0.as_ref(), n: temp_encryption_key_nonce.1.as_ref() };
        let write_file_content = if secure_editor {
            let mut encryptor = temp_cryptor.encryptor(&temp_key_nonce)?;
            encryptor.encrypt(file_content.as_bytes())
        } else {
            file_content.as_bytes().to_vec()
        };
        let temp_file = create_edit_temp_file(&write_file_content, path_out)?;

        let do_edit_file = || -> XResult<()> {
            let temp_file_content_bytes = run_file_editor_and_wait_content(
                &editor, &temp_file, secure_editor, cmd_decrypt.readonly, &temp_encryption_key_nonce)?;
            if cmd_decrypt.readonly {
                information!("Readonly, do not check temp file is changed.");
                return Ok(());
            }
            let temp_file_content_bytes = if secure_editor {
                let mut decryptor = temp_cryptor.decryptor(&temp_key_nonce)?;
                decryptor.decrypt(&temp_file_content_bytes)?
            } else {
                temp_file_content_bytes
            };
            let temp_file_content = opt_result!(String::from_utf8(temp_file_content_bytes), "Read temp file failed: {}");
            if temp_file_content == file_content {
                information!("Temp file is not changed.");
                return Ok(());
            }
            success!("Temp file is changed, save file ...");
            drop(file_in);
            let mut meta = meta;
            meta.latest_user_agent = Some(util::get_user_agent());
            meta.file_length = temp_file_content.len() as u64;
            meta.file_last_modified = util_time::get_current_millis() as u64;
            match &mut meta.file_edit_count {
                None => { meta.file_edit_count = Some(1); }
                Some(file_edit_count) => { *file_edit_count += 1; }
            }
            let mut file_out = File::create(path)?;
            let _ = util_enc_file::write_tiny_encrypt_meta(&mut file_out, &meta, is_meta_compressed)?;
            let compress_level = iff!(meta.compress, Some(Compression::default().level()), None);
            cmd_encrypt::encrypt_file(
                &mut temp_file_content.as_bytes(), meta.file_length, &mut file_out, cryptor,
                &key_nonce, &compress_level,
            )?;
            drop(file_out);

            Ok(())
        };
        let do_edit_file_result = do_edit_file();
        if let Err(e) = fs::remove_file(&temp_file) {
            warning!("Remove temp file: {} failed: {}", temp_file.display(), e)
        }
        do_edit_file_result?;
        return Ok(0);
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
    let start = Instant::now();

    let mut file_out = File::create(path_out)?;
    let _ = decrypt_file(
        &mut file_in, meta.file_length, &mut file_out, cryptor, &key_nonce, meta.compress,
    )?;
    drop(file_out);
    util_file::update_file_time(enc_meta, path_out);

    let encrypt_duration = start.elapsed();
    debugging!("Inner decrypt file{}: {} elapsed: {} ms",
        iff!(meta.compress, " [compressed]", ""),
        path_display,
        encrypt_duration.as_millis()
    );

    if cmd_decrypt.remove_file {
        util::remove_file_with_msg(path);
    }
    Ok(meta.file_length)
}

fn run_file_editor_and_wait_content(editor: &str, temp_file: &PathBuf, secure_editor: bool, readonly: bool, temp_encryption_key_nonce: &(SecVec, SecVec)) -> XResult<Vec<u8>> {
    let mut command = Command::new(editor);
    command.arg(temp_file.to_str().expect("Get temp file path failed."));
    if secure_editor {
        command.arg("aes-256-gcm");
        command.arg(hex::encode(&temp_encryption_key_nonce.0));
        command.arg(hex::encode(&temp_encryption_key_nonce.1));
        if readonly { command.env("READONLY", "true"); }
    }
    debugging!("Run cmd: {:?}", command);
    let run_cmd_result = util_cmd::run_command_and_wait(&mut command);
    debugging!("Run cmd result: {:?}", run_cmd_result);
    let run_cmd_exit_status = opt_result!(run_cmd_result, "Run cmd {} failed: {}", editor);
    if !run_cmd_exit_status.success() {
        return simple_error!("Run cmd {} failed: {:?}", editor, run_cmd_exit_status.code());
    }
    Ok(opt_result!(fs::read(temp_file), "Read file failed: {}"))
}

fn get_file_editor() -> (bool, String) {
    if let Ok(secure_editor) = env::var("SECURE_EDITOR") {
        // cmd <file-name> "aes-256-gcm" <key-in-hex> <nonce-in-hex>
        information!("Found secure editor: {}", &secure_editor);
        return (true, secure_editor);
    }
    match env::var("EDITOR").ok() {
        Some(editor) => (false, editor),
        None => {
            warning!("EDITOR is not assigned, use default editor vi");
            (false, "vi".to_string())
        }
    }
}

fn create_edit_temp_file(file_content: &[u8], path_out: &str) -> XResult<PathBuf> {
    let temp_dir = temp_dir();
    let current_millis = util_time::get_current_millis();
    let file_name = if path_out.contains('/') {
        path_out.split('/').last().unwrap().to_string()
    } else {
        path_out.to_string()
    };
    let temp_file = temp_dir.join(format!("tmp_file_{}_{}", current_millis, file_name));
    information!("Temp file: {}", temp_file.display());
    opt_result!(fs::write(&temp_file, file_content), "Write temp file failed: {}");
    Ok(temp_file)
}

pub fn decrypt_limited_content_to_vec(mut file_in: &mut File,
                                      meta: &TinyEncryptMeta, cryptor: Cryptor, key_nonce: &KeyNonce) -> XResult<Option<String>> {
    if meta.file_length > 100 * 1024 {
        failure!("File too large(more than 100K) cannot direct print on console.");
        return Ok(None);
    }
    if meta.file_length > 10 * 1024 {
        warning!("File is large(more than 10K) print on console.");
    }

    let mut output: Vec<u8> = Vec::with_capacity(10 * 1024);
    let _ = decrypt_file(
        &mut file_in, meta.file_length, &mut output, cryptor, key_nonce, meta.compress,
    )?;
    match String::from_utf8(output) {
        Err(_) => failure!("File content is not UTF-8 encoded."),
        Ok(output) => return Ok(Some(output)),
    }
    Ok(None)
}

fn decrypt_file(file_in: &mut impl Read, file_len: u64, file_out: &mut impl Write,
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
            progress.finish();
            debugging!("Decrypt finished, total: {} byte(s)", total_len);
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

pub fn try_decrypt_key(config: &Option<TinyEncryptConfig>,
                       envelop: &TinyEncryptEnvelop,
                       pin: &Option<String>,
                       slot: &Option<String>,
                       silent: bool) -> XResult<Vec<u8>> {
    match envelop.r#type {
        TinyEncryptEnvelopType::PgpRsa => try_decrypt_key_pgp_rsa(envelop, pin),
        TinyEncryptEnvelopType::PgpX25519 => try_decrypt_key_ecdh_pgp_x25519(envelop, pin),
        TinyEncryptEnvelopType::Gpg => try_decrypt_key_gpg(envelop),
        #[cfg(feature = "macos")]
        TinyEncryptEnvelopType::StaticX25519 => try_decrypt_key_ecdh_static_x25519(config, envelop),
        TinyEncryptEnvelopType::PivP256 | TinyEncryptEnvelopType::PivP384 => try_decrypt_piv_key_ecdh(config, envelop, pin, slot, silent),
        #[cfg(feature = "secure-enclave")]
        TinyEncryptEnvelopType::KeyP256 => try_decrypt_se_key_ecdh(config, envelop),
        TinyEncryptEnvelopType::PivRsa => try_decrypt_piv_key_rsa(config, envelop, pin, slot, silent),
        #[cfg(feature = "macos")]
        TinyEncryptEnvelopType::StaticKyber1024 => try_decrypt_key_ecdh_static_kyber1204(config, envelop),
        unknown_type => simple_error!("Unknown or unsupported type: {}", unknown_type.get_name()),
    }
}

fn try_decrypt_piv_key_ecdh(config: &Option<TinyEncryptConfig>,
                            envelop: &TinyEncryptEnvelop,
                            pin: &Option<String>,
                            slot: &Option<String>,
                            silent: bool) -> XResult<Vec<u8>> {
    let wrap_key = WrapKey::parse(&envelop.encrypted_key)?;
    let (cryptor, algo_id) = match wrap_key.header.enc.as_str() {
        ENC_AES256_GCM_P256 => (Cryptor::Aes256Gcm, AlgorithmId::EccP256),
        ENC_AES256_GCM_P384 => (Cryptor::Aes256Gcm, AlgorithmId::EccP384),
        ENC_CHACHA20_POLY1305_P256 => (Cryptor::ChaCha20Poly1305, AlgorithmId::EccP256),
        ENC_CHACHA20_POLY1305_P384 => (Cryptor::ChaCha20Poly1305, AlgorithmId::EccP384),
        _ => return simple_error!("Unsupported header enc: {}", &wrap_key.header.enc),
    };
    let e_pub_key_bytes = wrap_key.header.get_e_pub_key_bytes()?;
    let (_, subject_public_key_info) = opt_result!(
        SubjectPublicKeyInfo::from_der(&e_pub_key_bytes), "Invalid envelop: {}");

    let slot = util_piv::read_piv_slot(config, &envelop.kid, slot, silent)?;
    let pin = util::read_pin(pin)?;
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

fn try_decrypt_piv_key_rsa(config: &Option<TinyEncryptConfig>,
                           envelop: &TinyEncryptEnvelop,
                           pin: &Option<String>,
                           slot: &Option<String>,
                           silent: bool) -> XResult<Vec<u8>> {
    let encrypted_key_bytes = opt_result!(util::decode_base64(&envelop.encrypted_key), "Decode encrypt key failed: {}");

    let slot = util_piv::read_piv_slot(config, &envelop.kid, slot, silent)?;
    let pin = util::read_pin(pin)?;

    let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
    let slot_id = util_piv::get_slot_id(&slot)?;
    opt_result!(yk.verify_pin(pin.as_bytes()), "YubiKey verify pin failed: {}");

    let key = opt_result!(decrypt_data(
                &mut yk,
                &encrypted_key_bytes,
                AlgorithmId::Rsa2048,
                slot_id,
            ), "Decrypt via PIV card failed: {}");
    let key_bytes = key.as_slice();
    if !key_bytes.starts_with(&[0x00, 0x02]) {
        return simple_error!("RSA decrypted in error format: {}", hex::encode(key_bytes));
    }
    let after_2nd_0_bytes = key_bytes.iter()
        .skip(1)
        .skip_while(|b| **b != 0x00)
        .skip(1)
        .copied()
        .collect::<Vec<_>>();

    information!(">>>>>>>> {:?}", &after_2nd_0_bytes);
    util::zeroize(pin);
    util::zeroize(key);
    Ok(after_2nd_0_bytes)
}

#[cfg(feature = "secure-enclave")]
fn try_decrypt_se_key_ecdh(config: &Option<TinyEncryptConfig>,
                           envelop: &TinyEncryptEnvelop) -> XResult<Vec<u8>> {
    let wrap_key = WrapKey::parse(&envelop.encrypted_key)?;
    let cryptor = match wrap_key.header.enc.as_str() {
        ENC_AES256_GCM_P256 => Cryptor::Aes256Gcm,
        ENC_CHACHA20_POLY1305_P256 => Cryptor::ChaCha20Poly1305,
        _ => return simple_error!("Unsupported header enc: {}", &wrap_key.header.enc),
    };
    let e_pub_key_bytes = wrap_key.header.get_e_pub_key_bytes()?;

    let config = opt_value_result!(config, "Tiny encrypt config is not found");
    let config_envelop = opt_value_result!(
        config.find_by_kid(&envelop.kid), "Cannot find config for: {}", &envelop.kid);
    let config_envelop_args = opt_value_result!(&config_envelop.args, "No arguments found for: {}", &envelop.kid);
    if config_envelop_args.is_empty() {
        return simple_error!("Not enough arguments for: {}", &envelop.kid);
    }

    let private_key_base64 = if let Ok(keychain_key) = KeychainKey::parse(&config_envelop_args[0]) {
        let key = opt_value_result!(keychain_key.get_password()?, "Key: {} not found", &keychain_key.to_str());
        opt_result!(String::from_utf8(key), "Parse key failed: {}")
    } else {
        config_envelop_args[0].clone()
    };

    let shared_secret = opt_result!(util_keychainkey::decrypt_data(
                &private_key_base64,
                &e_pub_key_bytes
            ), "Decrypt via secure enclave failed: {}");
    let key = util::simple_kdf(shared_secret.as_slice());
    let key_nonce = KeyNonce { k: &key, n: &wrap_key.nonce };
    let decrypted_key = crypto_simple::decrypt(
        cryptor, &key_nonce, &wrap_key.encrypted_data)?;
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
    let e_pub_key_bytes = wrap_key.header.get_e_pub_key_bytes()?;

    let mut pgp = util_pgp::get_openpgp()?;
    let mut trans = opt_result!(pgp.transaction(), "Connect PIV card failed: {}");

    util_pgp::read_and_verify_openpgp_pin(&mut trans, pin)?;

    let shared_secret = trans.decipher(Cryptogram::ECDH(&e_pub_key_bytes))?;

    let key = util::simple_kdf(shared_secret.as_slice());
    let key_nonce = KeyNonce { k: &key, n: &wrap_key.nonce };
    let decrypted_key = crypto_simple::decrypt(
        cryptor, &key_nonce, &wrap_key.encrypted_data)?;
    util::zeroize(key);
    util::zeroize(shared_secret);
    Ok(decrypted_key)
}

fn try_decrypt_key_gpg(envelop: &TinyEncryptEnvelop) -> XResult<Vec<u8>> {
    util_gpg::gpg_decrypt(&envelop.encrypted_key)
}

#[cfg(feature = "macos")]
fn try_decrypt_key_ecdh_static_x25519(config: &Option<TinyEncryptConfig>, envelop: &TinyEncryptEnvelop) -> XResult<Vec<u8>> {
    let wrap_key = WrapKey::parse(&envelop.encrypted_key)?;
    let cryptor = match wrap_key.header.enc.as_str() {
        ENC_AES256_GCM_X25519 => Cryptor::Aes256Gcm,
        ENC_CHACHA20_POLY1305_X25519 => Cryptor::ChaCha20Poly1305,
        _ => return simple_error!("Unsupported header enc: {}", &wrap_key.header.enc),
    };
    let e_pub_key_bytes = wrap_key.header.get_e_pub_key_bytes()?;
    let config = opt_value_result!(config, "Tiny encrypt config is not found");
    let config_envelop = opt_value_result!(
        config.find_by_kid(&envelop.kid), "Cannot find config for: {}", &envelop.kid);
    let config_envelop_args = opt_value_result!(&config_envelop.args, "No arguments found for: {}", &envelop.kid);
    if config_envelop_args.len() != 1 && config_envelop_args.len() != 3 {
        return simple_error!("Not enough arguments for: {}", &envelop.kid);
    }

    let keychain_key = if config_envelop_args.len() == 1 {
        KeychainKey::parse(&config_envelop_args[0])?
    } else {
        KeychainKey::from(&config_envelop_args[0], &config_envelop_args[1], &config_envelop_args[2])
    };

    let shared_secret = opt_result!(
        util_keychainstatic::decrypt_x25519_data(&keychain_key, &e_pub_key_bytes), "Decrypt static x25519 failed: {}");

    let key = util::simple_kdf(shared_secret.as_slice());
    let key_nonce = KeyNonce { k: &key, n: &wrap_key.nonce };
    let decrypted_key = crypto_simple::decrypt(
        cryptor, &key_nonce, &wrap_key.encrypted_data)?;
    util::zeroize(key);
    util::zeroize(shared_secret);
    Ok(decrypted_key)
}

#[cfg(feature = "macos")]
fn try_decrypt_key_ecdh_static_kyber1204(config: &Option<TinyEncryptConfig>, envelop: &TinyEncryptEnvelop) -> XResult<Vec<u8>> {
    let wrap_key = WrapKey::parse(&envelop.encrypted_key)?;
    let cryptor = match wrap_key.header.enc.as_str() {
        ENC_AES256_GCM_KYBER1204 => Cryptor::Aes256Gcm,
        ENC_CHACHA20_POLY1305_KYBER1204 => Cryptor::ChaCha20Poly1305,
        _ => return simple_error!("Unsupported header enc: {}", &wrap_key.header.enc),
    };
    let e_pub_key_bytes = wrap_key.header.get_e_pub_key_bytes()?;
    let config = opt_value_result!(config, "Tiny encrypt config is not found");
    let config_envelop = opt_value_result!(
        config.find_by_kid(&envelop.kid), "Cannot find config for: {}", &envelop.kid);
    let config_envelop_args = opt_value_result!(&config_envelop.args, "No arguments found for: {}", &envelop.kid);
    if config_envelop_args.len() != 1 && config_envelop_args.len() != 3 {
        return simple_error!("Not enough arguments for: {}", &envelop.kid);
    }

    let keychain_key = if config_envelop_args.len() == 1 {
        KeychainKey::parse(&config_envelop_args[0])?
    } else {
        KeychainKey::from(&config_envelop_args[0], &config_envelop_args[1], &config_envelop_args[2])
    };

    let shared_secret = opt_result!(
        util_keychainstatic::decrypt_kyber1204_data(&keychain_key, &e_pub_key_bytes), "Decrypt static kyber1204 failed: {}");

    let key = util::simple_kdf(shared_secret.as_slice());
    let key_nonce = KeyNonce { k: &key, n: &wrap_key.nonce };
    let decrypted_key = crypto_simple::decrypt(
        cryptor, &key_nonce, &wrap_key.encrypted_data)?;
    util::zeroize(key);
    util::zeroize(shared_secret);
    Ok(decrypted_key)
}

fn try_decrypt_key_pgp_rsa(envelop: &TinyEncryptEnvelop, pin: &Option<String>) -> XResult<Vec<u8>> {
    let mut pgp = util_pgp::get_openpgp()?;
    let mut trans = opt_result!(pgp.transaction(), "Connect OpenPGP card failed: {}");

    util_pgp::read_and_verify_openpgp_pin(&mut trans, pin)?;

    let pgp_envelop = &envelop.encrypted_key;
    debugging!("PGP envelop: {}", pgp_envelop);
    let pgp_envelop_bytes = opt_result!(util::decode_base64(pgp_envelop), "Decode PGP envelop failed: {}");

    let key = trans.decipher(Cryptogram::RSA(&pgp_envelop_bytes))?;
    Ok(key)
}

pub fn select_envelop<'a>(meta: &'a TinyEncryptMeta, key_id: &Option<String>, config: &Option<TinyEncryptConfig>, silent: bool) -> XResult<&'a TinyEncryptEnvelop> {
    let envelops = match &meta.envelops {
        None => return simple_error!("No envelops found"),
        Some(envelops) => if envelops.is_empty() {
            return simple_error!("No envelops found");
        } else {
            envelops
        },
    };

    if silent {
        debugging!("Found {} envelops:", envelops.len());
    } else {
        success!("Found {} envelops:", envelops.len());
    }
    if let Some(envelop) = match_envelop_by_key_id(envelops, key_id, config, silent) {
        return Ok(envelop);
    }

    if envelops.len() == 1 {
        let selected_envelop = &envelops[0];
        if silent {
            debugging!("Auto selected envelop: #{} {}", 1, util_envelop::format_envelop(selected_envelop, config));
        } else {
            success!("Auto selected envelop: #{} {}", 1, util_envelop::format_envelop(selected_envelop, config));
        }
        if !selected_envelop.r#type.auto_select() {
            util::read_line("Press enter to continue: ");
        }
        return Ok(selected_envelop);
    }

    // auto select
    if let Some(auto_select_key_ids) = util_env::get_auto_select_key_ids() {
        for auto_select_key_id in auto_select_key_ids {
            if let Some(envelop) = match_envelop_by_key_id(envelops, &Some(auto_select_key_id), config, silent) {
                return Ok(envelop);
            }
        }
    }

    let use_dialoguer = util_env::get_use_dialoguer();
    let envelop_number = if use_dialoguer {
        let format_envelops = envelops.iter().map(|envelop| {
            format!("#{}", util_envelop::format_envelop(envelop, config))
        }).collect::<Vec<_>>();
        util::register_ctrlc();
        let select_result = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Please select envelop: ")
            .items(&format_envelops[..])
            .default(0)
            .report(!silent)
            .clear(true)
            .interact();
        if select_result.is_err() {
            let _ = Term::stderr().show_cursor();
        }
        opt_result!(select_result, "Select envelop error: {}") + 1
    } else {
        envelops.iter().enumerate().for_each(|(i, envelop)| {
            println_ex!("#{} {}", i + 1, util_envelop::format_envelop(envelop, config));
        });
        util::read_number("Please select an envelop:", 1, envelops.len())
    };

    let selected_envelop = &envelops[envelop_number - 1];
    if silent {
        debugging!("Selected envelop: #{} {}", envelop_number, selected_envelop.r#type.get_upper_name());
    } else {
        success!("Selected envelop: #{} {}", envelop_number, selected_envelop.r#type.get_upper_name());
    }
    Ok(selected_envelop)
}

fn match_envelop_by_key_id<'a>(envelops: &'a Vec<TinyEncryptEnvelop>, key_id: &Option<String>, config: &Option<TinyEncryptConfig>, silent: bool) -> Option<&'a TinyEncryptEnvelop> {
    if let Some(key_id) = key_id {
        for envelop in envelops {
            let is_sid_matched = config.as_ref().and_then(|config| {
                config.find_by_kid(&envelop.kid).and_then(|config_envelop| {
                    config_envelop.sid.as_ref().map(|sid| sid == key_id)
                })
            }).unwrap_or(false);

            if is_sid_matched || (&envelop.kid == key_id) {
                if silent {
                    debugging!("Matched envelop: {}", util_envelop::format_envelop(envelop, config));
                } else {
                    information!("Matched envelop: {}", util_envelop::format_envelop(envelop, config));
                }
                return Some(envelop);
            }
        }
    }
    None
}
