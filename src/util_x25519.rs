use rand::rngs::OsRng;
use rust_util::{opt_result, simple_error, XResult};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub fn compute_x25519_shared_secret(public_key_point_hex: &str) -> XResult<(Vec<u8>, Vec<u8>)> {
    let public_key_bytes = opt_result!(hex::decode(public_key_point_hex), "Parse X25519 public key hex failed: {}");
    if public_key_bytes.len() != 32 {
        return simple_error!("Parse X25519 key failed: not 32 bytes");
    }
    let public_key_bytes: [u8; 32] = public_key_bytes.try_into().unwrap();
    let public_key_card = PublicKey::from(public_key_bytes);

    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(&public_key_card);

    Ok((shared_secret.as_bytes().to_vec(), ephemeral_public.as_bytes().to_vec()))
}