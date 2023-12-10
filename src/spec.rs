use rust_util::{opt_result, util_time, XResult};
use rust_util::util_time::get_millis;
use serde::{Deserialize, Serialize};
use std::fs::Metadata;

use crate::{compress, crypto_simple};
use crate::consts::SALT_META;
use crate::crypto_cryptor::{Cryptor, KeyNonce};
use crate::util::{encode_base64, get_user_agent};

// Compatible with 1.0 is removed from v0.6.0
// pub const TINY_ENCRYPT_VERSION_10: &str = "1.0";
pub const TINY_ENCRYPT_VERSION_11: &str = "1.1";

/// Specification: [Tiny Encrypt Spec V1.1](https://github.com/OpenWebStandard/tiny-encrypt-format-spec/blob/main/TinyEncryptSpecv1.1.md)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TinyEncryptMeta {
    pub version: String,
    pub created: u64,
    pub user_agent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_meta: Option<String>,
    // ---------------------------------------
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgp_envelop: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgp_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_envelop: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_recipient: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecdh_envelop: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecdh_point: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelop: Option<String>,
    // ---------------------------------------
    pub envelops: Option<Vec<TinyEncryptEnvelop>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_algorithm: Option<String>,
    pub nonce: String,
    pub file_length: u64,
    pub file_last_modified: u64,
    pub file_edit_count: Option<u64>,
    pub compress: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TinyEncryptEnvelop {
    pub r#type: TinyEncryptEnvelopType,
    pub kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    pub encrypted_key: String,
}

/// NOTICE: Kms and Age is not being supported in the future
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum TinyEncryptEnvelopType {
    // OpenPGP Card RSA
    #[serde(rename = "pgp-rsa", alias = "pgp")]
    PgpRsa,
    // OpenPGP Card X25519
    #[serde(rename = "pgp-x25519")]
    PgpX25519,
    // Keychain Static X25519 (less secure)
    #[serde(rename = "static-x25519")]
    StaticX25519,
    // Secure Enclave ECDH P256
    #[serde(rename = "key-p256")]
    KeyP256,
    // Age, tiny-encrypt-rs is not supported
    #[serde(rename = "age")]
    Age,
    // PIV ECDH P256
    #[serde(rename = "piv-p256", alias = "ecdh")]
    PivP256,
    // PIV ECDH P384
    #[serde(rename = "piv-p384", alias = "ecdh-p384")]
    PivP384,
    // PIV RSA
    #[serde(rename = "piv-rsa")]
    PivRsa,
    // KMS, tiny-encrypt-rs is not supported
    #[serde(rename = "kms")]
    Kms,
}

impl TinyEncryptEnvelopType {
    pub fn get_upper_name(&self) -> String {
        self.get_name().to_uppercase()
    }

    pub fn get_name(&self) -> &'static str {
        match self {
            TinyEncryptEnvelopType::PgpRsa => "pgp-rsa",
            TinyEncryptEnvelopType::PgpX25519 => "pgp-x25519",
            TinyEncryptEnvelopType::StaticX25519 => "static-x25519",
            TinyEncryptEnvelopType::KeyP256 => "key-p256",
            TinyEncryptEnvelopType::Age => "age",
            TinyEncryptEnvelopType::PivP256 => "piv-p256",
            TinyEncryptEnvelopType::PivP384 => "piv-p384",
            TinyEncryptEnvelopType::PivRsa => "piv-rsa",
            TinyEncryptEnvelopType::Kms => "kms",
        }
    }

    pub fn auto_select(&self) -> bool {
        match self {
            TinyEncryptEnvelopType::PgpRsa => false,
            TinyEncryptEnvelopType::PgpX25519 => false,
            TinyEncryptEnvelopType::StaticX25519 => true,
            TinyEncryptEnvelopType::KeyP256 => true,
            TinyEncryptEnvelopType::Age => false,
            TinyEncryptEnvelopType::PivP256 => false,
            TinyEncryptEnvelopType::PivP384 => false,
            TinyEncryptEnvelopType::PivRsa => false,
            TinyEncryptEnvelopType::Kms => true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncEncryptedMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub m_time: Option<u64>,
}

impl EncEncryptedMeta {
    pub fn unseal(crypto: Cryptor, key_nonce: &KeyNonce, message: &[u8]) -> XResult<Self> {
        let mut decrypted = opt_result!(crypto_simple::try_decrypt_with_salt(
            crypto, key_nonce, SALT_META, message), "Decrypt encrypted meta failed: {}");
        decrypted = opt_result!(compress::decompress(&decrypted), "Depress encrypted meta failed: {}");
        let meta = opt_result!(
            serde_json::from_slice::<Self>(&decrypted), "Parse encrypted meta failed: {}");
        Ok(meta)
    }

    pub fn seal(&self, crypto: Cryptor, key_nonce: &KeyNonce) -> XResult<Vec<u8>> {
        let mut encrypted_meta_json = serde_json::to_vec(self).unwrap();
        encrypted_meta_json = opt_result!(
            compress::compress_default(&encrypted_meta_json), "Compress encrypted meta failed: {}");
        let encrypted = opt_result!(crypto_simple::encrypt_with_salt(
                crypto, key_nonce, SALT_META, encrypted_meta_json.as_slice()), "Encrypt encrypted meta failed: {}");
        Ok(encrypted)
    }
}

pub struct EncMetadata {
    pub comment: Option<String>,
    pub encrypted_comment: Option<String>,
    pub encrypted_meta: Option<String>,
    pub compress: bool,
}

impl TinyEncryptMeta {
    pub fn new(metadata: &Metadata, enc_metadata: &EncMetadata, cryptor: Cryptor, nonce: &[u8], envelops: Vec<TinyEncryptEnvelop>) -> Self {
        TinyEncryptMeta {
            version: TINY_ENCRYPT_VERSION_11.to_string(),
            created: util_time::get_current_millis() as u64,
            user_agent: get_user_agent(),
            comment: enc_metadata.comment.to_owned(),
            encrypted_comment: enc_metadata.encrypted_comment.to_owned(),
            encrypted_meta: enc_metadata.encrypted_meta.to_owned(),
            pgp_envelop: None,
            pgp_fingerprint: None,
            age_envelop: None,
            age_recipient: None,
            ecdh_envelop: None,
            ecdh_point: None,
            envelop: None,
            envelops: Some(envelops),
            encryption_algorithm: Some(cryptor.get_name()),
            nonce: encode_base64(nonce),
            file_length: metadata.len(),
            file_last_modified: match metadata.modified() {
                Ok(modified) => get_millis(&modified) as u64,
                Err(_) => 0,
            },
            file_edit_count: None,
            compress: enc_metadata.compress,
        }
    }

    pub fn normalize(&mut self) {
        if self.envelops.is_none() {
            self.envelops = Some(vec![]);
        }
        self.normalize_envelop();
        self.normalize_pgp_envelop();
        self.normalize_age_envelop();
        self.normalize_ecdh_envelop();
    }

    fn normalize_envelop(&mut self) {
        if let (Some(envelop), Some(envelops)) = (&self.envelop, &mut self.envelops) {
            envelops.push(TinyEncryptEnvelop {
                r#type: TinyEncryptEnvelopType::Kms,
                kid: "".to_string(),
                desc: None,
                encrypted_key: envelop.into(),
            });
            self.envelop = None;
        }
    }

    fn normalize_pgp_envelop(&mut self) {
        if let (Some(pgp_envelop), Some(pgp_fingerprint), Some(envelops))
            = (&self.pgp_envelop, &self.pgp_fingerprint, &mut self.envelops) {
            envelops.push(TinyEncryptEnvelop {
                r#type: TinyEncryptEnvelopType::PgpRsa,
                kid: pgp_fingerprint.into(),
                desc: None,
                encrypted_key: pgp_envelop.into(),
            });
            self.pgp_envelop = None;
            self.pgp_fingerprint = None;
        }
    }

    fn normalize_age_envelop(&mut self) {
        if let (Some(age_envelop), Some(age_recipient), Some(envelops))
            = (&self.age_envelop, &self.age_recipient, &mut self.envelops) {
            envelops.push(TinyEncryptEnvelop {
                r#type: TinyEncryptEnvelopType::Age,
                kid: age_recipient.into(),
                desc: None,
                encrypted_key: age_envelop.into(),
            });
            self.age_envelop = None;
            self.age_recipient = None;
        }
    }

    fn normalize_ecdh_envelop(&mut self) {
        if let (Some(ecdh_envelop), Some(ecdh_point), Some(envelops))
            = (&self.ecdh_envelop, &self.ecdh_point, &mut self.envelops) {
            envelops.push(TinyEncryptEnvelop {
                r#type: TinyEncryptEnvelopType::PivP256,
                kid: ecdh_point.into(),
                desc: None,
                encrypted_key: ecdh_envelop.into(),
            });
            self.ecdh_envelop = None;
            self.ecdh_point = None;
        }
    }
}
