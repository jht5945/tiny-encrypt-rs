use rust_util::{opt_result, simple_error, XResult};
use security_framework::os::macos::keychain::SecKeychain;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const X2559_PLAIN_PREFIX: &str = "x25519-plain:";

pub struct X25519StaticSecret {
    pub secret: Vec<u8>,
}

impl Zeroize for X25519StaticSecret {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl X25519StaticSecret {
    pub fn parse(key: &str) -> XResult<Self> {
        if !key.starts_with(X2559_PLAIN_PREFIX) {
            return simple_error!("Not X25519 plain key");
        }
        let extract_key_hex = &key[X2559_PLAIN_PREFIX.len()..];
        let extract_key = opt_result!(hex::decode(extract_key_hex), "Decode X25519 plain key failed: {}");
        Ok(Self {
            secret: extract_key,
        })
    }

    pub fn to_str(&self) -> String {
        let mut v = String::new();
        v.push_str(X2559_PLAIN_PREFIX);
        v.push_str(&hex::encode(&self.secret));
        v
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            secret: bytes.to_vec(),
        }
    }

    pub fn to_static_secret(&self) -> XResult<StaticSecret> {
        let secret_slice = self.secret.as_slice();
        let mut inner_secret: [u8; 32] = opt_result!(secret_slice.try_into(), "X25519 secret key error: {}");
        let static_secret = StaticSecret::from(inner_secret);
        inner_secret.zeroize();
        Ok(static_secret)
    }
}

pub fn decrypt_data(service_name: &str, key_name: &str, ephemeral_public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    let sec_keychain = opt_result!(SecKeychain::default(), "Get keychain failed: {}");
    let (static_x25519, _) = opt_result!(sec_keychain.find_generic_password(service_name, key_name),
        "Cannot find static x25519 {}.{}: {}", service_name, key_name);
    let static_x25519_bytes = static_x25519.as_ref();
    let static_x25519_str = opt_result!(String::from_utf8(static_x25519_bytes.to_vec()), "Parse static x25519 failed: {}");

    let x25519_static_secret = X25519StaticSecret::parse(&static_x25519_str)?;
    let static_secret = x25519_static_secret.to_static_secret()?;
    let inner_ephemeral_public_key: [u8; 32] = opt_result!(
        ephemeral_public_key_bytes.try_into(), "X25519 public key error: {}");
    let ephemeral_public_key = PublicKey::from(inner_ephemeral_public_key);
    let shared_secret = static_secret.diffie_hellman(&ephemeral_public_key);

    Ok(shared_secret.as_bytes().to_vec())
}

pub fn generate_pass_x25519_static_secret() -> (String, PublicKey) {
    let static_secret = StaticSecret::random();
    let public_key: PublicKey = (&static_secret).into();
    let static_secret_bytes = static_secret.as_bytes();
    let x25519_static_secret = X25519StaticSecret::from_bytes(static_secret_bytes);
    (x25519_static_secret.to_str(), public_key)
}