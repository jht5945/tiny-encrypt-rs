use rust_util::{opt_result, simple_error, XResult};
use swift_rs::{Bool, SRString};
use swift_rs::swift;

use crate::util;

swift!(fn is_support_secure_enclave() -> Bool);
swift!(fn generate_secure_enclave_p256_keypair() -> SRString);
swift!(fn compute_secure_enclave_p256_ecdh(private_key_base64: SRString, ephemera_public_key_base64: SRString) -> SRString);

pub fn is_support_se() -> bool {
    unsafe { is_support_secure_enclave() }
}


pub fn decrypt_data(private_key_base64: &str, ephemeral_public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    let ephemera_public_key_base64 = util::encode_base64(ephemeral_public_key_bytes);
    let result = unsafe {
        compute_secure_enclave_p256_ecdh(
            SRString::from(private_key_base64), SRString::from(ephemera_public_key_base64.as_str()),
        )
    };
    let result = result.as_str();
    if !result.starts_with("ok:SharedSecret:") {
        return simple_error!("ECDH P256 in secure enclave failed: {}", result);
    }

    let shared_secret_hex = result.chars().skip("ok:SharedSecret:".len()).collect::<String>();
    let shared_secret_hex = shared_secret_hex.trim();

    Ok(opt_result!(hex::decode(shared_secret_hex), "Decrypt shared secret hex: {}, failed: {}", shared_secret_hex))
}

pub fn generate_se_p256_keypair() -> XResult<(String, String)> {
    if !is_support_se() {
        return simple_error!("Secure enclave is not supported.");
    }
    let result = unsafe { generate_secure_enclave_p256_keypair() };
    let result = result.as_str();
    if !result.starts_with("ok:") {
        return simple_error!("Generate P256 in secure enclave failed: {}", result);
    }
    let public_key_and_private_key = result.chars().skip(3).collect::<String>();
    let public_key_and_private_keys = public_key_and_private_key.split(',').collect::<Vec<_>>();
    if public_key_and_private_keys.len() != 2 {
        return simple_error!("Generate P256 in secure enclave result is bad: {}", public_key_and_private_key);
    }
    let public_key = hex::encode(
        opt_result!(util::decode_base64(public_key_and_private_keys[0]), "Public key is not base64 encoded: {}"));
    let private_key = public_key_and_private_keys[1].to_string();

    Ok((public_key, private_key))
}
