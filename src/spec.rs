use std::fs::Metadata;

use rust_util::util_time;
use rust_util::util_time::get_millis;
use serde::{Deserialize, Serialize};

use crate::util::{encode_base64, get_user_agent};

// pub const TINY_ENCRYPT_VERSION_10: &'static str = "1.0";
pub const TINY_ENCRYPT_VERSION_11: &'static str = "1.1";

/// Specification: [Tiny Encrypt Spec V1.1](https://git.hatter.ink/hatter/tiny-encrypt-java/src/branch/master/TinyEncryptSpecV1.1.md)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TinyEncryptMeta {
    pub version: String,
    pub created: u64,
    pub user_agent: String,
    pub comment: Option<String>,
    pub encrypted_comment: Option<String>,
    pub encrypted_meta: Option<String>,
    // ---------------------------------------
    pub pgp_envelop: Option<String>,
    pub pgp_fingerprint: Option<String>,
    pub age_envelop: Option<String>,
    pub age_recipient: Option<String>,
    pub ecdh_envelop: Option<String>,
    pub ecdh_point: Option<String>,
    pub envelop: Option<String>,
    // ---------------------------------------
    pub envelops: Option<Vec<TinyEncryptEnvelop>>,
    pub encryption_algorithm: Option<String>,
    pub nonce: String,
    pub file_length: u64,
    pub file_last_modified: u64,
    pub compress: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TinyEncryptEnvelop {
    pub r#type: TinyEncryptEnvelopType,
    pub kid: String,
    pub desc: Option<String>,
    pub encrypted_key: String,
}

/// NOTICE: Kms and Age is not being supported in the future
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum TinyEncryptEnvelopType {
    #[serde(rename = "pgp")]
    Pgp,
    #[serde(rename = "age")]
    Age,
    #[serde(rename = "ecdh")]
    Ecdh,
    #[serde(rename = "kms")]
    Kms,
}

impl TinyEncryptEnvelopType {
    pub fn get_upper_name(&self) -> String {
        self.get_name().to_uppercase()
    }
    pub fn get_name(&self) -> &'static str {
        match self {
            TinyEncryptEnvelopType::Pgp => "pgp",
            TinyEncryptEnvelopType::Age => "age",
            TinyEncryptEnvelopType::Ecdh => "ecdh",
            TinyEncryptEnvelopType::Kms => "kms",
        }
    }
}

pub struct EncMetadata {
    pub comment: Option<String>,
    pub encrypted_comment: Option<String>,
    pub encrypted_meta: Option<String>,
    pub compress: bool,
}

impl TinyEncryptMeta {
    pub fn new(metadata: &Metadata, enc_metadata: &EncMetadata, nonce: &[u8], envelops: Vec<TinyEncryptEnvelop>) -> Self {
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
            encryption_algorithm: None,
            nonce: encode_base64(nonce),
            file_length: metadata.len(),
            file_last_modified: match metadata.modified() {
                Ok(modified) => get_millis(&modified) as u64,
                Err(_) => 0,
            },
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
                r#type: TinyEncryptEnvelopType::Pgp,
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
                r#type: TinyEncryptEnvelopType::Ecdh,
                kid: ecdh_point.into(),
                desc: None,
                encrypted_key: ecdh_envelop.into(),
            });
            self.ecdh_envelop = None;
            self.ecdh_point = None;
        }
    }
}
