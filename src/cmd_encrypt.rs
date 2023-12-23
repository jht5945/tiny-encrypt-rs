use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use clap::Args;
use flate2::Compression;
use rsa::Pkcs1v15Encrypt;
use rust_util::{debugging, failure, iff, information, opt_result, simple_error, success, util_size, XResult};
use rust_util::util_time::UnixEpochTime;

use crate::{crypto_cryptor, crypto_simple, util, util_enc_file, util_env};
use crate::compress::GzStreamEncoder;
use crate::config::{TinyEncryptConfig, TinyEncryptConfigEnvelop};
use crate::consts::{ENC_AES256_GCM_KYBER1204, ENC_AES256_GCM_P256, ENC_AES256_GCM_P384, ENC_AES256_GCM_X25519, ENC_CHACHA20_POLY1305_KYBER1204, ENC_CHACHA20_POLY1305_P256, ENC_CHACHA20_POLY1305_P384, ENC_CHACHA20_POLY1305_X25519, SALT_COMMENT, TINY_ENC_CONFIG_FILE, TINY_ENC_FILE_EXT};
use crate::crypto_cryptor::{Cryptor, KeyNonce};
use crate::crypto_rsa;
use crate::spec::{
    EncEncryptedMeta, EncMetadata,
    TinyEncryptEnvelop, TinyEncryptEnvelopType, TinyEncryptMeta,
};
use crate::util_ecdh::{ecdh_kyber1024, ecdh_p256, ecdh_p384, ecdh_x25519};
use crate::util_progress::Progress;
use crate::wrap_key::{WrapKey, WrapKeyHeader};

#[derive(Debug, Args)]
pub struct CmdEncrypt {
    /// Files need to be decrypted
    pub paths: Vec<PathBuf>,
    /// Plaintext comment
    #[arg(long, short = 'c')]
    pub comment: Option<String>,
    /// Encrypted comment
    #[arg(long, short = 'C')]
    pub encrypted_comment: Option<String>,
    /// Encryption profile (use default when --key-filter is assigned)
    #[arg(long, short = 'p')]
    pub profile: Option<String>,
    /// Encryption key filter (key_id or type:TYPE(e.g. ecdh, pgp, ecdh-p384, pgp-ed25519), multiple joined by ',', ALL for all)
    #[arg(long, short = 'k')]
    pub key_filter: Option<String>,
    /// Compress before encrypt
    #[arg(long, short = 'x')]
    pub compress: bool,
    /// Compress level (from 0[none], 1[fast] .. 6[default] .. to 9[best])
    #[arg(long, short = 'L')]
    pub compress_level: Option<u32>,
    /// Remove source file
    #[arg(long, short = 'R')]
    pub remove_file: bool,
    /// Create file (create a empty encrypted file)
    #[arg(long, short = 'a')]
    pub create: bool,
    /// Disable compress meta
    #[arg(long)]
    pub disable_compress_meta: bool,
    /// Encryption algorithm (AES/GCM, CHACHA20/POLY1305 or AES, CHACHA20, default AES/GCM)
    #[arg(long, short = 'A')]
    pub encryption_algorithm: Option<String>,
}

pub fn encrypt(cmd_encrypt: CmdEncrypt) -> XResult<()> {
    let config = TinyEncryptConfig::load(TINY_ENC_CONFIG_FILE)?;
    debugging!("Found tiny encrypt config: {:?}", config);
    let envelops = config.find_envelops(&cmd_encrypt.profile, &cmd_encrypt.key_filter)?;
    if envelops.is_empty() { return simple_error!("Cannot find any valid envelops"); }
    debugging!("Found envelops: {:?}", envelops);
    let envelop_tkids: Vec<_> = envelops.iter()
        .map(|e| format!("{}:{}", e.r#type.get_name(), e.kid))
        .collect();
    information!("Matched {} envelop(s): \n- {}", envelops.len(), envelop_tkids.join("\n- "));

    debugging!("Cmd encrypt: {:?}", cmd_encrypt);
    let start = Instant::now();
    let mut succeed_count = 0;
    let mut skipped_count = 0;
    let mut failed_count = 0;
    let mut total_len = 0_u64;
    for path in &cmd_encrypt.paths {
        let path = config.resolve_path_namespace(path, false);
        let start_encrypt_single = Instant::now();
        match encrypt_single(&path, &envelops, &cmd_encrypt) {
            Ok(len) => {
                total_len += len;
                if len > 0 { succeed_count += 1; } else { skipped_count += 1; }
                success!(
                    "Encrypt {} succeed, cost {} ms, file size {} byte(s)",
                    path.to_str().unwrap_or("N/A"),
                    start_encrypt_single.elapsed().as_millis(),
                    len
                );
            }
            Err(e) => {
                failed_count += 1;
                failure!("Encrypt {} failed: {}", path.to_str().unwrap_or("N/A"), e);
            }
        }
    }
    if (succeed_count + failed_count) > 1 {
        success!(
            "Encrypt succeed {} file(s) {} byte(s), failed {} file(s), skipped {} file(s), total cost {} ms",
            succeed_count,
            total_len,
            failed_count,
            skipped_count,
            start.elapsed().as_millis(),
        );
    }
    Ok(())
}

pub fn encrypt_single(path: &PathBuf, envelops: &[&TinyEncryptConfigEnvelop], cmd_encrypt: &CmdEncrypt) -> XResult<u64> {
    let path_display = format!("{}", path.display());
    let path_out = format!("{}{}", path_display, TINY_ENC_FILE_EXT);
    let encrypt_single_result = encrypt_single_file_out(path, &path_out, envelops, cmd_encrypt);
    if cmd_encrypt.create {
        if let Ok(content) = fs::read_to_string(path) {
            if content == "\n" {
                let _ = fs::remove_file(path);
            }
        }
    }
    encrypt_single_result
}

pub fn encrypt_single_file_out(path: &PathBuf, path_out: &str, envelops: &[&TinyEncryptConfigEnvelop], cmd_encrypt: &CmdEncrypt) -> XResult<u64> {
    let path_display = format!("{}", path.display());
    if path_display.ends_with(TINY_ENC_FILE_EXT) {
        information!("Tiny enc file skipped: {}", path_display);
        return Ok(0);
    }

    let cryptor = crypto_cryptor::get_cryptor_by_encryption_algorithm(&cmd_encrypt.encryption_algorithm)?;
    information!("Using encryption algorithm: {}", cryptor.get_name());

    if cmd_encrypt.create {
        util::require_file_not_exists(path)?;
        opt_result!(fs::write(path, "\n"), "Write empty file failed: {}");
    } else {
        util::require_file_exists(path)?;
    }

    let mut file_in = opt_result!(File::open(path), "Open file: {} failed: {}", &path_display);

    util::require_file_not_exists(path_out)?;

    let (key, nonce) = util::make_key256_and_nonce();
    let key_nonce = KeyNonce { k: key.as_ref(), n: nonce.as_ref() };
    // Encrypt session key to envelops
    let envelops = encrypt_envelops(cryptor, key.as_ref(), envelops)?;

    let encrypted_comment = match &cmd_encrypt.encrypted_comment {
        None => None,
        Some(encrypted_comment) => Some(util::encode_base64(
            &crypto_simple::encrypt_with_salt(
                cryptor, &key_nonce, SALT_COMMENT, encrypted_comment.as_bytes())?))
    };

    let file_metadata = opt_result!(fs::metadata(path), "Read file: {} meta failed: {}", path.display());
    let enc_encrypted_meta = EncEncryptedMeta {
        filename: Some(util::get_file_name(path)),
        c_time: file_metadata.created().ok().and_then(|t| t.to_millis()),
        m_time: file_metadata.modified().ok().and_then(|t| t.to_millis()),
    };
    let enc_encrypted_meta_bytes = opt_result!(enc_encrypted_meta.seal(
        cryptor, &key_nonce), "Seal enc-encrypted-meta failed: {}");

    let compress_level = get_compress_level(cmd_encrypt);

    let enc_metadata = EncMetadata {
        comment: cmd_encrypt.comment.clone(),
        encrypted_comment,
        encrypted_meta: Some(util::encode_base64(&enc_encrypted_meta_bytes)),
        compress: compress_level.is_some(),
    };

    let encrypt_meta = TinyEncryptMeta::new(
        &file_metadata, &enc_metadata, cryptor, nonce.as_ref(), envelops);
    debugging!("Encrypted meta: {:?}", encrypt_meta);

    let mut file_out = File::create(path_out)?;
    let compress_meta = !cmd_encrypt.disable_compress_meta;
    let _ = util_enc_file::write_tiny_encrypt_meta(&mut file_out, &encrypt_meta, compress_meta)?;

    let compress_desc = iff!(compress_level.is_some(), " [with compress]", "");

    let start = Instant::now();
    encrypt_file(
        &mut file_in, file_metadata.len(), &mut file_out, cryptor,
        &key_nonce, &compress_level,
    )?;
    drop(file_out);
    let encrypt_duration = start.elapsed();
    debugging!("Inner encrypt file{}: {} elapsed: {} ms", compress_desc, path_display, encrypt_duration.as_millis());

    if cmd_encrypt.remove_file { util::remove_file_with_msg(path); }
    Ok(file_metadata.len())
}

pub(crate) fn encrypt_file(file_in: &mut impl Read, file_len: u64, file_out: &mut impl Write, cryptor: Cryptor,
                           key_nonce: &KeyNonce, compress_level: &Option<u32>) -> XResult<u64> {
    let compress = compress_level.is_some();
    let mut total_len = 0_u64;
    let mut write_len = 0_u64;
    let mut buffer = [0u8; 1024 * 8];
    let mut gz_encoder = match compress_level {
        None => GzStreamEncoder::new_default(),
        Some(compress_level) => {
            if *compress_level > 9 {
                return simple_error!("Compress level must be in range [0, 9]");
            }
            GzStreamEncoder::new(Compression::new(*compress_level))
        }
    };
    let progress = Progress::new(file_len);
    let mut encryptor = cryptor.encryptor(key_nonce)?;
    loop {
        let len = opt_result!(file_in.read(&mut buffer), "Read file failed: {}");
        if len == 0 {
            let last_block_and_tag = if compress {
                let last_compressed_buffer = opt_result!(gz_encoder.finalize(), "Decompress file failed: {}");
                let mut encrypted_block = encryptor.update(&last_compressed_buffer);
                let (last_block, tag) = encryptor.finalize();
                write_len += encrypted_block.len() as u64;
                write_len += last_block.len() as u64;
                encrypted_block.extend_from_slice(&last_block);
                encrypted_block.extend_from_slice(&tag);
                encrypted_block
            } else {
                let (mut last_block, tag) = encryptor.finalize();
                write_len += last_block.len() as u64;
                last_block.extend_from_slice(&tag);
                last_block
            };
            opt_result!(file_out.write_all(&last_block_and_tag), "Write file failed: {}");
            progress.finish();
            debugging!("Encrypt finished, total bytes: {} byte(s)", total_len);
            if compress {
                information!("File is compressed: {} -> {}, ratio: {}%",
                    util_size::get_display_size(total_len as i64),
                    util_size::get_display_size(write_len as i64),
                    util::ratio(write_len, total_len));
            }
            break;
        } else {
            total_len += len as u64;
            let encrypted = if compress {
                let compressed = opt_result!(gz_encoder.update(&buffer[0..len]), "Decompress file failed: {}");
                encryptor.update(&compressed)
            } else {
                encryptor.update(&buffer[0..len])
            };
            write_len += encrypted.len() as u64;
            opt_result!(file_out.write_all(&encrypted), "Write file failed: {}");
            progress.position(total_len);
        }
    }
    Ok(total_len)
}

fn encrypt_envelops(cryptor: Cryptor, key: &[u8], envelops: &[&TinyEncryptConfigEnvelop]) -> XResult<Vec<TinyEncryptEnvelop>> {
    let mut encrypted_envelops = vec![];
    for envelop in envelops {
        match envelop.r#type {
            TinyEncryptEnvelopType::PgpRsa | TinyEncryptEnvelopType::PivRsa => {
                encrypted_envelops.push(encrypt_envelop_rsa(key, envelop)?);
            }
            TinyEncryptEnvelopType::PgpX25519 | TinyEncryptEnvelopType::StaticX25519 => {
                encrypted_envelops.push(encrypt_envelop_ecdh_x25519(cryptor, key, envelop)?);
            }
            TinyEncryptEnvelopType::PivP256 | TinyEncryptEnvelopType::KeyP256 => {
                encrypted_envelops.push(encrypt_envelop_ecdh_p256(cryptor, key, envelop)?);
            }
            TinyEncryptEnvelopType::PivP384 => {
                encrypted_envelops.push(encrypt_envelop_ecdh_p384(cryptor, key, envelop)?);
            }
            TinyEncryptEnvelopType::StaticKyber1024 => {
                encrypted_envelops.push(encrypt_envelop_ecdh_kyber1204(cryptor, key, envelop)?);
            }
            _ => return simple_error!("Not supported type: {:?}", envelop.r#type),
        }
    }
    Ok(encrypted_envelops)
}

fn encrypt_envelop_ecdh_p256(cryptor: Cryptor, key: &[u8], envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let public_key_point_hex = &envelop.public_part;
    let (shared_secret, ephemeral_spki) = ecdh_p256::compute_p256_shared_secret(public_key_point_hex)?;
    let enc_type = match cryptor {
        Cryptor::Aes256Gcm => ENC_AES256_GCM_P256,
        Cryptor::ChaCha20Poly1305 => ENC_CHACHA20_POLY1305_P256,
    };
    encrypt_envelop_shared_secret(cryptor, key, &shared_secret, &ephemeral_spki, enc_type, envelop)
}

fn encrypt_envelop_ecdh_p384(cryptor: Cryptor, key: &[u8], envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let public_key_point_hex = &envelop.public_part;
    let (shared_secret, ephemeral_spki) = ecdh_p384::compute_p384_shared_secret(public_key_point_hex)?;
    let enc_type = match cryptor {
        Cryptor::Aes256Gcm => ENC_AES256_GCM_P384,
        Cryptor::ChaCha20Poly1305 => ENC_CHACHA20_POLY1305_P384,
    };
    encrypt_envelop_shared_secret(cryptor, key, &shared_secret, &ephemeral_spki, enc_type, envelop)
}

fn encrypt_envelop_ecdh_x25519(cryptor: Cryptor, key: &[u8], envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let public_key_point_hex = &envelop.public_part;
    let (shared_secret, ephemeral_spki) = ecdh_x25519::compute_x25519_shared_secret(public_key_point_hex)?;
    let enc_type = match cryptor {
        Cryptor::Aes256Gcm => ENC_AES256_GCM_X25519,
        Cryptor::ChaCha20Poly1305 => ENC_CHACHA20_POLY1305_X25519,
    };
    encrypt_envelop_shared_secret(cryptor, key, &shared_secret, &ephemeral_spki, enc_type, envelop)
}

fn encrypt_envelop_ecdh_kyber1204(cryptor: Cryptor, key: &[u8], envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let public_key_point_hex = &envelop.public_part;
    let (shared_secret, ephemeral_spki) = ecdh_kyber1024::compute_kyber1024_shared_secret(public_key_point_hex)?;
    let enc_type = match cryptor {
        Cryptor::Aes256Gcm => ENC_AES256_GCM_KYBER1204,
        Cryptor::ChaCha20Poly1305 => ENC_CHACHA20_POLY1305_KYBER1204,
    };
    encrypt_envelop_shared_secret(cryptor, key, &shared_secret, &ephemeral_spki, enc_type, envelop)
}

fn encrypt_envelop_shared_secret(cryptor: Cryptor,
                                 key: &[u8],
                                 shared_secret: &[u8],
                                 ephemeral_spki: &[u8],
                                 enc_type: &str,
                                 envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let shared_key = util::simple_kdf(shared_secret);
    let nonce = util::make_nonce();
    let key_nonce = KeyNonce { k: &shared_key, n: nonce.as_ref() };

    let encrypted_key = crypto_simple::encrypt(
        cryptor, &key_nonce, key)?;

    let wrap_key = WrapKey {
        header: WrapKeyHeader::from(enc_type, ephemeral_spki),
        nonce: nonce.0.clone(),
        encrypted_data: encrypted_key,
    };
    let encoded_wrap_key = wrap_key.encode()?;

    Ok(TinyEncryptEnvelop {
        r#type: envelop.r#type,
        kid: envelop.kid.clone(),
        desc: None,
        encrypted_key: encoded_wrap_key,
    })
}

fn encrypt_envelop_rsa(key: &[u8], envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let rsa_public_key = opt_result!(crypto_rsa::parse_spki(&envelop.public_part), "Parse RSA public key failed: {}");
    let mut rng = rand::thread_rng();
    let encrypted_key = opt_result!(rsa_public_key.encrypt(&mut rng, Pkcs1v15Encrypt, key), "RSA public key encrypt failed: {}");
    Ok(TinyEncryptEnvelop {
        r#type: envelop.r#type,
        kid: envelop.kid.clone(),
        desc: None,
        encrypted_key: util::encode_base64(&encrypted_key),
    })
}

fn get_compress_level(cmd_encrypt: &CmdEncrypt) -> Option<u32> {
    if cmd_encrypt.compress || util_env::get_default_compress().unwrap_or(false) {
        Some(cmd_encrypt.compress_level.unwrap_or_else(|| Compression::default().level()))
    } else {
        None
    }
}
