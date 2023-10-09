use p384::ecdh::EphemeralSecret;
use rand::rngs::OsRng;
use rust_util::{opt_result, XResult};

use p384::pkcs8::EncodePublicKey;
use p384::{EncodedPoint, PublicKey};
use p384::elliptic_curve::sec1::FromEncodedPoint;

pub fn compute_p384_shared_secret(public_key_point_hex: &str) -> XResult<(Vec<u8>, Vec<u8>)> {
    let public_key_point_bytes = opt_result!(hex::decode(public_key_point_hex), "Parse public key point hex failed: {}");
    let encoded_point = opt_result!(EncodedPoint::from_bytes(&public_key_point_bytes), "Parse public key point failed: {}");
    let public_key = PublicKey::from_encoded_point(&encoded_point).unwrap();

    let esk = EphemeralSecret::random(&mut OsRng);
    let epk = esk.public_key();
    let shared_secret = esk.diffie_hellman(&public_key);
    let epk_public_key_der = opt_result!(epk.to_public_key_der(), "Convert epk to SPKI failed: {}");
    Ok((shared_secret.raw_secret_bytes().as_slice().to_vec(), epk_public_key_der.to_vec()))
}