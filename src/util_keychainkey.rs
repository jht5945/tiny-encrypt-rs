use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rust_util::{simple_error, XResult};
use swift_secure_enclave_tool_rs::{ControlFlag, KeyPurpose};

pub fn is_support_se() -> bool {
    swift_secure_enclave_tool_rs::is_secure_enclave_supported().unwrap_or(false)
}

pub fn decrypt_data(
    private_key_base64: &str,
    ephemeral_public_key_bytes: &[u8],
) -> XResult<Vec<u8>> {
    let private_key_representation = STANDARD.decode(private_key_base64)?;
    let shared_secret = swift_secure_enclave_tool_rs::private_key_ecdh(
        &private_key_representation,
        ephemeral_public_key_bytes,
    )?;
    Ok(shared_secret)
}

pub fn generate_se_p256_keypair(control_flag: ControlFlag) -> XResult<(String, String)> {
    if !is_support_se() {
        return simple_error!("Secure enclave is not supported.");
    }
    let key_material =
        swift_secure_enclave_tool_rs::generate_keypair(KeyPurpose::KeyAgreement, control_flag)?;
    Ok((
        hex::encode(&key_material.public_key_point),
        STANDARD.encode(&key_material.private_key_representation),
    ))
}
