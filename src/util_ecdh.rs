pub mod ecdh_p256 {
    use p256::{EncodedPoint, PublicKey};
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::pkcs8::EncodePublicKey;
    use rand::rngs::OsRng;
    use rust_util::{opt_result, XResult};

    pub fn compute_p256_shared_secret(public_key_point_hex: &str) -> XResult<(Vec<u8>, Vec<u8>)> {
        let public_key_point_bytes = opt_result!(hex::decode(public_key_point_hex), "Parse public key point hex failed: {}");
        let encoded_point = opt_result!(EncodedPoint::from_bytes(public_key_point_bytes), "Parse public key point failed: {}");
        let public_key = PublicKey::from_encoded_point(&encoded_point).unwrap();

        let esk = EphemeralSecret::random(&mut OsRng);
        let epk = esk.public_key();
        let shared_secret = esk.diffie_hellman(&public_key);
        let epk_public_key_der = opt_result!(epk.to_public_key_der(), "Convert epk to SPKI failed: {}");
        Ok((shared_secret.raw_secret_bytes().as_slice().to_vec(), epk_public_key_der.to_vec()))
    }
}

pub mod ecdh_p384 {
    use p384::{EncodedPoint, PublicKey};
    use p384::ecdh::EphemeralSecret;
    use p384::elliptic_curve::sec1::FromEncodedPoint;
    use p384::pkcs8::EncodePublicKey;
    use rand::rngs::OsRng;
    use rust_util::{opt_result, XResult};

    pub fn compute_p384_shared_secret(public_key_point_hex: &str) -> XResult<(Vec<u8>, Vec<u8>)> {
        let public_key_point_bytes = opt_result!(hex::decode(public_key_point_hex), "Parse public key point hex failed: {}");
        let encoded_point = opt_result!(EncodedPoint::from_bytes(public_key_point_bytes), "Parse public key point failed: {}");
        let public_key = PublicKey::from_encoded_point(&encoded_point).unwrap();

        let esk = EphemeralSecret::random(&mut OsRng);
        let epk = esk.public_key();
        let shared_secret = esk.diffie_hellman(&public_key);
        let epk_public_key_der = opt_result!(epk.to_public_key_der(), "Convert epk to SPKI failed: {}");
        Ok((shared_secret.raw_secret_bytes().as_slice().to_vec(), epk_public_key_der.to_vec()))
    }
}

pub mod ecdh_x25519 {
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
}
