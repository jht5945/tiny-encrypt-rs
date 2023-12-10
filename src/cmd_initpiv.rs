use clap::Args;
use p256::pkcs8::der::Decode;
use rust_util::{failure, iff, information, opt_result, simple_error, warning, XResult};
use spki::{ObjectIdentifier, SubjectPublicKeyInfoOwned};
use spki::der::Encode;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::RSAPublicKey;
use yubikey::Certificate;
use yubikey::Key;
use yubikey::piv::{AlgorithmId, SlotId};
use yubikey::YubiKey;

use crate::config::TinyEncryptConfigEnvelop;
use crate::spec::TinyEncryptEnvelopType;
use crate::{util, util_piv};
use crate::util_digest::sha256_digest;

#[derive(Debug, Args)]
pub struct CmdInitPiv {
    /// PIV slot
    #[arg(long, short = 's')]
    pub slot: String,
}

const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const ECC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

const ECC_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const ECC_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

pub fn init_piv(cmd_init_piv: CmdInitPiv) -> XResult<()> {
    let mut yk = opt_result!(YubiKey::open(), "YubiKey not found: {}");
    let slot_id = util_piv::get_slot_id(&cmd_init_piv.slot)?;
    let slot_id_hex = to_slot_hex(&slot_id);
    let keys = opt_result!(Key::list(&mut yk), "List keys failed: {}");

    let find_key = || {
        for k in &keys {
            let key_slot_str = format!("{:x}", Into::<u8>::into(k.slot()));
            if slot_equals(&slot_id, &key_slot_str) {
                return Some(k);
            }
        }
        None
    };
    let key = match find_key() {
        None => {
            warning!("Key not found.");
            return Ok(());
        }
        Some(key) => key,
    };
    let cert = &key.certificate().cert.tbs_certificate;
    if let Ok(algorithm_id) = get_algorithm_id_by_certificate(key.certificate()) {
        let public_key_bit_string = &cert.subject_public_key_info.subject_public_key;
        match algorithm_id {
            AlgorithmId::EccP256 | AlgorithmId::EccP384 => {
                let pk_point_hex = public_key_bit_string.raw_bytes();
                let public_key_point_hex = hex::encode(pk_point_hex);
                let compressed_public_key_point_hex = format!("02{}", hex::encode(&pk_point_hex[1..(pk_point_hex.len() / 2) + 1]));

                let is_p256 = algorithm_id == AlgorithmId::EccP256;
                let config_envelop = TinyEncryptConfigEnvelop {
                    r#type: iff!(is_p256, TinyEncryptEnvelopType::PivP256, TinyEncryptEnvelopType::PivP384),
                    sid: Some(format!("piv-{}-ecdh-{}", &slot_id_hex, iff!(is_p256, "p256", "p384"))),
                    kid: compressed_public_key_point_hex.clone(),
                    desc: Some(format!("PIV --slot {}", &slot_id_hex)),
                    args: Some(vec![
                        slot_id_hex.clone()
                    ]),
                    public_part: public_key_point_hex,
                };

                information!("Config envelop:\n{}", serde_json::to_string_pretty(&config_envelop).unwrap());
            }
            AlgorithmId::Rsa2048 => {
                let spki = opt_result!(cert.subject_public_key_info.to_der(), "Generate SPKI DER failed: {}");
                let config_envelop = TinyEncryptConfigEnvelop {
                    r#type: TinyEncryptEnvelopType::PivRsa,
                    sid: Some(format!("piv-{}-rsa2048", &slot_id_hex)),
                    kid: format!("piv:{}", hex::encode(sha256_digest(&spki))),
                    desc: Some(format!("PIV --slot {}", &slot_id_hex)),
                    args: Some(vec![
                        slot_id_hex.clone()
                    ]),
                    public_part: util::to_pem(&spki, "PUBLIC KEY"),
                };

                information!("Config envelop:\n{}", serde_json::to_string_pretty(&config_envelop).unwrap());
            }
            _ => {
                failure!("Only support P256, P384 or RSA2048, actual: {:?}", algorithm_id);
            }
        }
    }

    Ok(())
}


fn get_algorithm_id_by_certificate(certificate: &Certificate) -> XResult<AlgorithmId> {
    let tbs_certificate = &certificate.cert.tbs_certificate;
    get_algorithm_id(&tbs_certificate.subject_public_key_info)
}

fn get_algorithm_id(public_key_info: &SubjectPublicKeyInfoOwned) -> XResult<AlgorithmId> {
    if public_key_info.algorithm.oid == RSA {
        let rsa_public_key = opt_result!(
            RSAPublicKey::from_der(public_key_info.subject_public_key.raw_bytes()), "Parse public key failed: {}");
        let starts_with_0 = rsa_public_key.1.modulus.starts_with(&[0]);
        let public_key_bits = (rsa_public_key.1.modulus.len() - iff!(starts_with_0, 1, 0)) * 8;
        if public_key_bits == 1024 {
            return Ok(AlgorithmId::Rsa1024);
        }
        if public_key_bits == 2048 {
            return Ok(AlgorithmId::Rsa2048);
        }
        return simple_error!("Unknown rsa bits: {}", public_key_bits);
    }
    if public_key_info.algorithm.oid == ECC {
        if let Some(any) = &public_key_info.algorithm.parameters {
            let any_parameter_der = opt_result!(any.to_der(), "Bad any parameter: {}");
            let any_parameter_oid = opt_result!(ObjectIdentifier::from_der(&any_parameter_der), "Bad any parameter der: {}");
            if any_parameter_oid == ECC_P256 {
                return Ok(AlgorithmId::EccP256);
            }
            if any_parameter_oid == ECC_P384 {
                return Ok(AlgorithmId::EccP384);
            }
            return simple_error!("Unknown any parameter oid: {}", any_parameter_oid);
        }
    }
    simple_error!("Unknown algorithm: {}", public_key_info.algorithm.oid)
}

fn slot_equals(slot_id: &SlotId, slot: &str) -> bool {
    util_piv::get_slot_id(slot).map(|sid| &sid == slot_id).unwrap_or(false)
}

fn to_slot_hex(slot: &SlotId) -> String {
    let slot_id: u8 = (*slot).into();
    format!("{:x}", slot_id)
}
