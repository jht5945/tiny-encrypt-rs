use rust_util::{debugging, opt_result, opt_value_result, simple_error, XResult};
use security_framework::os::macos::keychain::SecKeychain;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const X2559_PLAIN_PREFIX: &str = "x25519-plain:";
const KEYCHAIN_KEY_PREFIX: &str = "keychain:";

pub struct KeychainKey {
    pub keychain_name: String,
    pub service_name: String,
    pub key_name: String,
}


pub struct X25519StaticSecret {
    pub secret: Vec<u8>,
}

impl Zeroize for X25519StaticSecret {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl X25519StaticSecret {
    pub fn parse_bytes(bs: &[u8]) -> XResult<Self> {
        let key_str = opt_result!(String::from_utf8(bs.to_vec()), "Parse static x25519 failed: {}");
        Self::parse(&key_str)
    }

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

    pub fn to_public_key(&self) -> XResult<PublicKey> {
        let static_secret = self.to_static_secret()?;
        let public_key: PublicKey = (&static_secret).into();
        Ok(public_key)
    }
}

impl KeychainKey {
    pub fn from_default_keychain(service_name: &str, key_name: &str) -> Self {
        Self::from("", service_name, key_name)
    }

    pub fn from(keychain_name: &str, service_name: &str, key_name: &str) -> Self {
        Self {
            keychain_name: keychain_name.to_string(),
            service_name: service_name.to_string(),
            key_name: key_name.to_string(),
        }
    }

    pub fn parse(keychain_key: &str) -> XResult<Self> {
        if !keychain_key.starts_with(KEYCHAIN_KEY_PREFIX) {
            return simple_error!("Not a valid keychain key: {}", keychain_key);
        }
        //keychain:keychain_name:service_name:key_name
        let keychain_key_parts = keychain_key.split(':').collect::<Vec<_>>();
        if keychain_key_parts.len() != 4 {
            return simple_error!("Not a valid keychain key: {}", keychain_key);
        }
        Ok(Self {
            keychain_name: keychain_key_parts[1].to_string(),
            service_name: keychain_key_parts[2].to_string(),
            key_name: keychain_key_parts[3].to_string(),
        })
    }

    pub fn to_str(&self) -> String {
        let mut s = String::new();
        s.push_str(KEYCHAIN_KEY_PREFIX);
        s.push_str(&self.keychain_name);
        s.push(':');
        s.push_str(&self.service_name);
        s.push(':');
        s.push_str(&self.key_name);
        s
    }

    pub fn get_password(&self) -> XResult<Option<Vec<u8>>> {
        let sec_keychain = self.get_keychain()?;
        match sec_keychain.find_generic_password(&self.service_name, &self.key_name) {
            Ok((item_password, _keychain_item)) => {
                Ok(Some(item_password.as_ref().to_vec()))
            }
            Err(e) => {
                debugging!("Get password: {} failed: {}", &self.to_str(), e);
                Ok(None)
            }
        }
    }

    pub fn set_password(&self, password: &[u8]) -> XResult<()> {
        let sec_keychain = self.get_keychain()?;
        if sec_keychain.find_generic_password(&self.service_name, &self.key_name).is_ok() {
            return simple_error!("Password {}.{} exists", &self.service_name, &self.key_name);
        }
        opt_result!(
            sec_keychain.set_generic_password(&self.service_name, &self.key_name, password),
            "Set password {}.{} error: {}", &self.service_name, &self.key_name
        );
        Ok(())
    }

    fn get_keychain(&self) -> XResult<SecKeychain> {
        if !self.keychain_name.is_empty() {
            return simple_error!("Keychain name must be empty.");
        }
        Ok(opt_result!(SecKeychain::default(), "Get keychain failed: {}"))
    }
}

pub fn decrypt_data(keychain_key: &KeychainKey, ephemeral_public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    let static_x25519 = opt_value_result!(keychain_key.get_password()?, "Static X25519 not found: {}", &keychain_key.to_str());

    let x25519_static_secret = X25519StaticSecret::parse_bytes(&static_x25519)?;
    let static_secret = x25519_static_secret.to_static_secret()?;
    let inner_ephemeral_public_key: [u8; 32] = opt_result!(
        ephemeral_public_key_bytes.try_into(), "X25519 public key error: {}");
    let ephemeral_public_key = PublicKey::from(inner_ephemeral_public_key);
    let shared_secret = static_secret.diffie_hellman(&ephemeral_public_key);

    Ok(shared_secret.as_bytes().to_vec())
}

pub fn generate_static_x25519_secret() -> (String, PublicKey) {
    let static_secret = StaticSecret::random();
    let public_key: PublicKey = (&static_secret).into();
    let static_secret_bytes = static_secret.as_bytes();
    let x25519_static_secret = X25519StaticSecret::from_bytes(static_secret_bytes);
    (x25519_static_secret.to_str(), public_key)
}