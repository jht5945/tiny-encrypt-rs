use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use clap::Args;
use flate2::Compression;
use rsa::Pkcs1v15Encrypt;
use rust_util::{debugging, failure, information, opt_result, simple_error, success, util_msg, warning, XResult};
use zeroize::Zeroize;

use crate::{util, util_ecdh, util_p384, util_x25519};
use crate::compress::GzStreamEncoder;
use crate::config::{TinyEncryptConfig, TinyEncryptConfigEnvelop};
use crate::crypto_aes::aes_gcm_encrypt;
use crate::crypto_rsa::parse_spki;
use crate::spec::{EncMetadata, TINY_ENCRYPT_VERSION_10, TinyEncryptEnvelop, TinyEncryptEnvelopType, TinyEncryptMeta};
use crate::util::{ENC_AES256_GCM_P256, ENC_AES256_GCM_P384, ENC_AES256_GCM_X25519, TINY_ENC_CONFIG_FILE};
use crate::wrap_key::{WrapKey, WrapKeyHeader};

#[derive(Debug, Args)]
pub struct CmdEncrypt {
    /// Files need to be decrypted
    pub paths: Vec<PathBuf>,
    /// Comment
    #[arg(long, short = 'c')]
    pub comment: Option<String>,
    /// Encrypted comment
    #[arg(long, short = 'C')]
    pub encrypted_comment: Option<String>,
    /// Encryption profile
    #[arg(long, short = 'p')]
    pub profile: Option<String>,
    /// Compress before encrypt
    #[arg(long, short = 'x')]
    pub compress: bool,
    /// Compress level (from 0[none], 1[fast] .. 6[default] .. to 9[best])
    #[arg(long, short = 'L')]
    pub compress_level: Option<u32>,
    /// Compatible with 1.0
    #[arg(long, short = '1')]
    pub compatible_with_1_0: bool,
    /// Remove source file
    #[arg(long, short = 'R')]
    pub remove_file: bool,
}

pub fn encrypt(cmd_encrypt: CmdEncrypt) -> XResult<()> {
    let config = TinyEncryptConfig::load(TINY_ENC_CONFIG_FILE)?;
    debugging!("Found tiny encrypt config: {:?}", config);
    let envelops = config.find_envelops(&cmd_encrypt.profile)?;
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
        let start_encrypt_single = Instant::now();
        match encrypt_single(path, &envelops, &cmd_encrypt) {
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

fn encrypt_single(path: &PathBuf, envelops: &[&TinyEncryptConfigEnvelop], cmd_encrypt: &CmdEncrypt) -> XResult<u64> {
    let path_display = format!("{}", path.display());
    if path_display.ends_with(util::TINY_ENC_FILE_EXT) {
        information!("Tiny enc file skipped: {}", path_display);
        return Ok(0);
    }

    util::require_file_exists(path)?;

    let mut file_in = opt_result!(File::open(path), "Open file: {} failed: {}", &path_display);

    let path_out = format!("{}{}", path_display, util::TINY_ENC_FILE_EXT);
    util::require_file_not_exists(path_out.as_str())?;

    let (key, nonce) = util::make_key256_and_nonce();
    let envelops = encrypt_envelops(&key, &envelops)?;

    let encrypted_comment = match &cmd_encrypt.encrypted_comment {
        None => None,
        Some(encrypted_comment) => Some(util::encode_base64(
            &aes_gcm_encrypt(&key, &nonce, encrypted_comment.as_bytes())?))
    };

    let file_metadata = opt_result!(fs::metadata(path), "Read file: {} meta failed: {}", path.display());
    let enc_metadata = EncMetadata {
        comment: cmd_encrypt.comment.clone(),
        encrypted_comment,
        encrypted_meta: None,
        compress: cmd_encrypt.compress,
    };

    let mut encrypt_meta = TinyEncryptMeta::new(&file_metadata, &enc_metadata, &nonce, envelops);
    debugging!("Encrypted meta: {:?}", encrypt_meta);

    if cmd_encrypt.compatible_with_1_0 {
        if let Some(envelops) = encrypt_meta.envelops {
            let mut filter_envelops = vec![];
            for envelop in envelops {
                if (envelop.r#type == TinyEncryptEnvelopType::Pgp) && encrypt_meta.pgp_envelop.is_none() {
                    encrypt_meta.pgp_fingerprint = Some(format!("KID:{}", envelop.kid));
                    encrypt_meta.pgp_envelop = Some(envelop.encrypted_key.clone());
                } else if (envelop.r#type == TinyEncryptEnvelopType::Ecdh) && encrypt_meta.ecdh_envelop.is_none() {
                    encrypt_meta.ecdh_point = Some(format!("KID:{}", envelop.kid));
                    encrypt_meta.ecdh_envelop = Some(envelop.encrypted_key.clone());
                } else {
                    filter_envelops.push(envelop);
                }
            }
            encrypt_meta.envelops = if filter_envelops.is_empty() { None } else { Some(filter_envelops) };
            if encrypt_meta.envelops.is_none() {
                encrypt_meta.version = TINY_ENCRYPT_VERSION_10.to_string();
            }
        }
    }

    let mut file_out = File::create(&path_out)?;
    opt_result!(file_out.write_all(&util::TINY_ENC_MAGIC_TAG.to_be_bytes()), "Write tag failed: {}");
    let encrypted_meta_bytes = opt_result!(serde_json::to_vec(&encrypt_meta), "Generate meta json bytes failed: {}");
    let encrypted_meta_bytes_len = encrypted_meta_bytes.len() as u32;
    opt_result!(file_out.write_all(&encrypted_meta_bytes_len.to_be_bytes()), "Write meta len failed: {}");
    opt_result!(file_out.write_all(&encrypted_meta_bytes), "Write meta failed: {}");

    let start = Instant::now();
    util_msg::print_lastline(&format!("Encrypting file: {} ...", path_display));
    encrypt_file(&mut file_in, &mut file_out, &key, &nonce, cmd_encrypt.compress, &cmd_encrypt.compress_level)?;
    util_msg::clear_lastline();
    let encrypt_duration = start.elapsed();
    debugging!("Encrypt file: {} elapsed: {} ms", path_display, encrypt_duration.as_millis());

    util::zeroize(key);
    util::zeroize(nonce);
    drop(file_in);
    drop(file_out);
    if cmd_encrypt.remove_file {
        match fs::remove_file(path) {
            Err(e) => warning!("Remove file: {} failed: {}", path_display, e),
            Ok(_) => information!("Remove file: {} succeed", path_display),
        }
    }
    Ok(file_metadata.len())
}


fn encrypt_file(file_in: &mut File, file_out: &mut File, key: &[u8], nonce: &[u8], compress: bool, compress_level: &Option<u32>) -> XResult<usize> {
    let mut total_len = 0;
    let mut buffer = [0u8; 1024 * 8];
    let key = opt_result!(key.try_into(), "Key is not 32 bytes: {}");
    let mut gz_encoder = match compress_level {
        None => GzStreamEncoder::new_default(),
        Some(compress_level) => {
            if *compress_level > 9 {
                return simple_error!("Compress level must in range [0, 9]");
            }
            GzStreamEncoder::new(Compression::new(*compress_level))
        }
    };
    let mut encryptor = aes_gcm_stream::Aes256GcmStreamEncryptor::new(key, &nonce);
    loop {
        let len = opt_result!(file_in.read(&mut buffer), "Read file failed: {}");
        if len == 0 {
            let last_block = if compress {
                let last_compressed_buffer = opt_result!(gz_encoder.finalize(), "Decompress file failed: {}");
                let mut encrypted_block = encryptor.update(&last_compressed_buffer);
                let (last_block, tag) = encryptor.finalize();
                encrypted_block.extend_from_slice(&last_block);
                encrypted_block.extend_from_slice(&tag);
                encrypted_block
            } else {
                let (mut last_block, tag) = encryptor.finalize();
                last_block.extend_from_slice(&tag);
                last_block
            };
            opt_result!(file_out.write_all(&last_block), "Write file failed: {}");
            debugging!("Encrypt finished, total bytes: {}", total_len);
            break;
        } else {
            total_len += len;
            let encrypted = if compress {
                let compressed = opt_result!(gz_encoder.update(&buffer[0..len]), "Decompress file failed: {}");
                encryptor.update(&compressed)
            } else {
                encryptor.update(&buffer[0..len])
            };
            opt_result!(file_out.write_all(&encrypted), "Write file failed: {}");
        }
    }
    let mut key = key;
    key.zeroize();
    Ok(total_len)
}

fn encrypt_envelops(key: &[u8], envelops: &[&TinyEncryptConfigEnvelop]) -> XResult<Vec<TinyEncryptEnvelop>> {
    let mut encrypted_envelops = vec![];
    for envelop in envelops {
        match envelop.r#type {
            TinyEncryptEnvelopType::Pgp => {
                encrypted_envelops.push(encrypt_envelop_pgp(key, envelop)?);
            }
            TinyEncryptEnvelopType::PgpX25519 => {
                encrypted_envelops.push(encrypt_envelop_ecdh_x25519(key, envelop)?);
            }
            TinyEncryptEnvelopType::Ecdh => {
                encrypted_envelops.push(encrypt_envelop_ecdh(key, envelop)?);
            }
            TinyEncryptEnvelopType::EcdhP384 => {
                encrypted_envelops.push(encrypt_envelop_ecdh_p384(key, envelop)?);
            }
            _ => return simple_error!("Not supported type: {:?}", envelop.r#type),
        }
    }
    Ok(encrypted_envelops)
}

fn encrypt_envelop_ecdh(key: &[u8], envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let public_key_point_hex = &envelop.public_part;
    let (shared_secret, ephemeral_spki) = util_ecdh::compute_shared_secret(public_key_point_hex)?;

    encrypt_envelop_shared_secret(key, &shared_secret, &ephemeral_spki, ENC_AES256_GCM_P256, envelop)
}

fn encrypt_envelop_ecdh_p384(key: &[u8], envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let public_key_point_hex = &envelop.public_part;
    let (shared_secret, ephemeral_spki) = util_p384::compute_p384_shared_secret(public_key_point_hex)?;

    encrypt_envelop_shared_secret(key, &shared_secret, &ephemeral_spki, ENC_AES256_GCM_P384, envelop)
}

fn encrypt_envelop_ecdh_x25519(key: &[u8], envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let public_key_point_hex = &envelop.public_part;
    let (shared_secret, ephemeral_spki) = util_x25519::compute_x25519_shared_secret(public_key_point_hex)?;

    encrypt_envelop_shared_secret(key, &shared_secret, &ephemeral_spki, ENC_AES256_GCM_X25519, envelop)
}

fn encrypt_envelop_shared_secret(key: &[u8],
                                 shared_secret: &[u8],
                                 ephemeral_spki: &[u8],
                                 enc_type: &str,
                                 envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let shared_key = util::simple_kdf(shared_secret);
    let (_, nonce) = util::make_key256_and_nonce();

    let encrypted_key = aes_gcm_encrypt(&shared_key, &nonce, key)?;

    let wrap_key = WrapKey {
        header: WrapKeyHeader {
            kid: Some(envelop.kid.clone()),
            enc: enc_type.to_string(),
            e_pub_key: util::encode_base64_url_no_pad(&ephemeral_spki),
        },
        nonce,
        encrypted_data: encrypted_key,
    };
    let encoded_wrap_key = wrap_key.encode()?;

    Ok(TinyEncryptEnvelop {
        r#type: envelop.r#type,
        kid: envelop.kid.clone(),
        desc: envelop.desc.clone(),
        encrypted_key: encoded_wrap_key,
    })
}

fn encrypt_envelop_pgp(key: &[u8], envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let pgp_public_key = opt_result!(parse_spki(&envelop.public_part), "Parse PGP public key failed: {}");
    let mut rng = rand::thread_rng();
    let encrypted_key = opt_result!(pgp_public_key.encrypt(&mut rng, Pkcs1v15Encrypt, key), "PGP public key encrypt failed: {}");
    Ok(TinyEncryptEnvelop {
        r#type: envelop.r#type,
        kid: envelop.kid.clone(),
        desc: envelop.desc.clone(),
        encrypted_key: util::encode_base64(&encrypted_key),
    })
}
