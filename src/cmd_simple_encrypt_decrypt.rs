use crate::config::TinyEncryptConfig;
use crate::spec::TinyEncryptEnvelop;
use crate::{cmd_encrypt, crypto_cryptor, util, util_env};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use clap::Args;
use rust_util::{debugging, opt_result, simple_error, XResult};
use serde::Serialize;
use std::io;
use std::io::Write;
use std::process::exit;
use crate::util_simple_pbe::SimplePbkdfEncryptionV1;

// Reference: https://git.hatter.ink/hatter/tiny-encrypt-rs/issues/3
const SIMPLE_ENCRYPTION_HEADER: &str = "tinyencrypt-dir";
const SIMPLE_ENCRYPTION_DOT: &str = ".";

#[derive(Debug, Args)]
pub struct CmdSimpleEncrypt {
    /// Encryption profile (use default when --key-filter is assigned)
    #[arg(long, short = 'p')]
    pub profile: Option<String>,

    /// Encryption key filter (key_id or type:TYPE(e.g. ecdh, pgp, ecdh-p384, pgp-ed25519), multiple joined by ',', ALL for all)
    #[arg(long, short = 'k')]
    pub key_filter: Option<String>,

    /// Encrypt value from stdin
    #[arg(long)]
    pub value_stdin: bool,

    /// Encrypt value
    #[arg(long, short = 'v')]
    pub value: Option<String>,

    /// Encrypt value in bse64
    #[arg(long)]
    pub value_base64: Option<String>,

    /// Encrypt value in hex
    #[arg(long)]
    pub value_hex: Option<String>,

    /// With PBKDF encryption
    #[arg(long, short = 'P')]
    pub with_pbkdf_encryption: bool,

    /// PBKDF encryption password
    #[arg(long, short = 'A')]
    pub password: Option<String>,

    /// Direct output result value
    #[arg(long)]
    pub direct_output: bool,
}

#[derive(Debug, Args)]
pub struct CmdSimpleDecrypt {
    /// PGP or PIV PIN
    #[arg(long, short = 'p')]
    pub pin: Option<String>,

    /// Decrypt key ID
    #[arg(long, short = 'k')]
    pub key_id: Option<String>,

    /// PIV slot
    #[arg(long, short = 's')]
    pub slot: Option<String>,

    /// Decrypt value from stdin
    #[arg(long)]
    pub value_stdin: bool,

    /// Decrypt value
    #[arg(long, short = 'v')]
    pub value: Option<String>,

    /// Decrypt result output format (plain, hex, bse64)
    #[arg(long, short = 'o')]
    pub output_format: Option<String>,

    /// PBKDF encryption password
    #[arg(long, short = 'A')]
    pub password: Option<String>,

    /// Direct output result value
    #[arg(long)]
    pub direct_output: bool,
}

impl CmdSimpleEncrypt {
    pub fn get_value(&self) -> XResult<Option<Vec<u8>>> {
        if self.value_stdin {
            return Ok(Some(util::read_stdin()?));
        }
        if let Some(value) = &self.value {
            return Ok(Some(value.as_bytes().to_vec()));
        }
        if let Some(value_base64) = &self.value_base64 {
            return Ok(Some(opt_result!(STANDARD.decode(value_base64), "Parse value base64 failed: {}")));
        }
        if let Some(value_hex) = &self.value_hex {
            return Ok(Some(opt_result!(hex::decode(value_hex), "Parse value hex failed: {}")));
        }
        Ok(None)
    }
}

impl CmdSimpleDecrypt {
    pub fn get_value(&self) -> XResult<Option<String>> {
        if self.value_stdin {
            return Ok(Some(opt_result!(String::from_utf8(util::read_stdin()?), "Read stdin value failed: {}")));
        }
        Ok(self.value.clone())
    }
}

#[derive(Serialize)]
pub struct CmdResult {
    pub code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
}

impl CmdResult {
    pub fn fail(code: i32, message: &str) -> Self {
        Self {
            code,
            message: Some(message.to_string()),
            result: None,
        }
    }

    pub fn success(result: &str) -> Self {
        Self {
            code: 0,
            message: None,
            result: Some(result.to_string()),
        }
    }

    pub fn print_exit(&self, direct_output_value: bool) -> ! {
        // TODO direct_output_value
        if direct_output_value {
            if self.code == 0 {
                print!("{}", self.result.as_deref().unwrap());
            } else {
                println!("{}", self.message.as_deref().unwrap_or("unknown error"));
            }
        } else {
            let result = serde_json::to_string_pretty(self).unwrap();
            println!("{}", result);
        }
        exit(self.code)
    }
}

pub fn simple_encrypt(cmd_simple_encrypt: CmdSimpleEncrypt) -> XResult<()> {
    let direct_output = cmd_simple_encrypt.direct_output;
    if let Err(inner_result_error) = inner_simple_encrypt(cmd_simple_encrypt) {
        CmdResult::fail(-1, &format!("{}", inner_result_error)).print_exit(direct_output);
    }
    Ok(())
}

#[cfg(feature = "decrypt")]
pub fn simple_decrypt(cmd_simple_decrypt: CmdSimpleDecrypt) -> XResult<()> {
    let direct_output = cmd_simple_decrypt.direct_output;
    if let Err(inner_result_error) = inner_simple_decrypt(cmd_simple_decrypt) {
        CmdResult::fail(-1, &format!("{}", inner_result_error)).print_exit(direct_output);
    }
    Ok(())
}

pub fn inner_simple_encrypt(cmd_simple_encrypt: CmdSimpleEncrypt) -> XResult<()> {
    let config = TinyEncryptConfig::load_default()?;
    debugging!("Found tiny encrypt config: {:?}", config);
    let envelops = config.find_envelops(&cmd_simple_encrypt.profile, &cmd_simple_encrypt.key_filter)?;
    if envelops.is_empty() { return simple_error!("Cannot find any valid envelops"); }
    debugging!("Found envelops: {:?}", envelops);
    let envelop_tkids: Vec<_> = envelops.iter()
        .map(|e| format!("{}:{}", e.r#type.get_name(), e.kid))
        .collect();
    debugging!("Matched {} envelop(s): \n- {}", envelops.len(), envelop_tkids.join("\n- "));

    if envelop_tkids.is_empty() {
        return simple_error!("no matched envelops found");
    }

    let value = match cmd_simple_encrypt.get_value()? {
        None => return simple_error!("--value-stdin/value/value-base64/value-hex must assign one"),
        Some(value) => value,
    };

    let cryptor = crypto_cryptor::get_cryptor_by_encryption_algorithm(&None)?;
    let envelops = cmd_encrypt::encrypt_envelops(cryptor, &value, &envelops)?;

    let envelops_json = serde_json::to_string(&envelops)?;
    let mut simple_encrypt_result = format!("{}.{}",
                                        SIMPLE_ENCRYPTION_HEADER,
                                        URL_SAFE_NO_PAD.encode(envelops_json.as_bytes())
    );

    let with_pbkdf_encryption = cmd_simple_encrypt.with_pbkdf_encryption || cmd_simple_encrypt.password.is_some();
    if with_pbkdf_encryption {
        let password = util::read_password(&cmd_simple_encrypt.password)?;
        simple_encrypt_result = SimplePbkdfEncryptionV1::encrypt(&password, simple_encrypt_result.as_bytes())?.to_string();
    }

    CmdResult::success(&simple_encrypt_result).print_exit(cmd_simple_encrypt.direct_output);
}

#[cfg(feature = "decrypt")]
pub fn inner_simple_decrypt(cmd_simple_decrypt: CmdSimpleDecrypt) -> XResult<()> {
    let config = TinyEncryptConfig::load_default().ok();

    let pin = cmd_simple_decrypt.pin.clone().or_else(util_env::get_pin);
    let slot = cmd_simple_decrypt.slot.clone();

    let output_format = cmd_simple_decrypt.output_format.as_deref().unwrap_or("plain");
    match output_format {
        "plain" | "hex" | "base64" => (),
        _ => return simple_error!("not supported output format: {}", output_format),
    };

    let mut value = match cmd_simple_decrypt.get_value()? {
        None => return simple_error!("--value-stdin/value must assign one"),
        Some(value) => value,
    };

    if SimplePbkdfEncryptionV1::matches(&value) {
        let simple_pbkdf_encryption_v1: SimplePbkdfEncryptionV1 = value.as_str().try_into()?;
        let password = util::read_password(&cmd_simple_decrypt.password)?;
        let plaintext_bytes = simple_pbkdf_encryption_v1.decrypt(&password)?;
        value = opt_result!(String::from_utf8(plaintext_bytes), "Decrypt PBKDF encryption failed: {}");
    }

    let value_parts = value.trim().split(SIMPLE_ENCRYPTION_DOT).collect::<Vec<_>>();
    if value_parts.len() != 2 {
        return simple_error!("bad value format: {}", value);
    }
    if value_parts[0] != SIMPLE_ENCRYPTION_HEADER {
        return simple_error!("bad value format: {}", value);
    }
    let envelopes_json = opt_result!(URL_SAFE_NO_PAD.decode(value_parts[1]), "bad value format: {}");
    let envelops: Vec<TinyEncryptEnvelop> = match serde_json::from_slice(&envelopes_json) {
        Err(_) => return simple_error!("bad value format: {}", value),
        Ok(value) => value,
    };

    let filter_envelops = envelops.iter().filter(|e| {
        match &cmd_simple_decrypt.key_id {
            None => true,
            Some(key_id) => &e.kid == key_id,
        }
    }).collect::<Vec<_>>();
    if filter_envelops.is_empty() {
        return simple_error!("no envelops found: {:?}", cmd_simple_decrypt.key_id);
    }
    if filter_envelops.len() > 1 {
        let mut kids = vec![];
        debugging!("Found {} envelopes", filter_envelops.len());
        for envelop in &filter_envelops {
            kids.push(envelop.kid.clone());
            debugging!("- {} {}", envelop.kid, envelop.r#type.get_name());
        }
        return simple_error!("too many envelops: {:?}, len: {}, matched kids: [{}]", cmd_simple_decrypt.key_id, filter_envelops.len(), kids.join(","));
    }
    let value = crate::cmd_decrypt::try_decrypt_key(&config, filter_envelops[0], &pin, &slot, false)?;
    if cmd_simple_decrypt.direct_output && output_format == "plain" {
        io::stdout().write_all(&value).expect("unable to write to stdout");
        exit(0);
    }
    let value = match output_format {
        "plain" => opt_result!(String::from_utf8(value), "bad value encoding: {}"),
        "hex" => hex::encode(&value),
        "base64" => STANDARD.encode(&value),
        _ => return simple_error!("not supported output format: {}", output_format),
    };
    CmdResult::success(&value).print_exit(cmd_simple_decrypt.direct_output);
}