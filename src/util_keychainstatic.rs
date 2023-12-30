use std::path::PathBuf;

use pqcrypto_kyber::kyber1024;
use pqcrypto_kyber::kyber1024::Ciphertext as Kyber1024Ciphertext;
use pqcrypto_kyber::kyber1024::PublicKey as Kyber1024PublicKey;
use pqcrypto_kyber::kyber1024::SecretKey as Kyber1024SecretKey;
use rust_util::{debugging, opt_result, opt_value_result, simple_error, util_file, XResult};
use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const X2559_PLAIN_PREFIX: &str = "x25519-plain:";
const KYBER1024_PLAIN_PREFIX: &str = "kyber1024-plain:";
const KEYCHAIN_KEY_PREFIX: &str = "keychain:";

pub struct KeychainKey {
    pub keychain_name: String,
    pub service_name: String,
    pub key_name: String,
}

pub enum KeychainStaticSecretAlgorithm {
    X25519,
    Kyber1024,
}

impl KeychainStaticSecretAlgorithm {
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::X25519 => X2559_PLAIN_PREFIX,
            Self::Kyber1024 => KYBER1024_PLAIN_PREFIX,
        }
    }
    pub fn from_prefix(str: &str) -> Option<Self> {
        if str.starts_with(X2559_PLAIN_PREFIX) {
            Some(Self::X25519)
        } else if str.starts_with(KYBER1024_PLAIN_PREFIX) {
            Some(Self::Kyber1024)
        } else {
            None
        }
    }
}

pub struct KeychainStaticSecret {
    pub algo: KeychainStaticSecretAlgorithm,
    pub secret: Vec<u8>,
    pub public: Option<Vec<u8>>,
}

impl Zeroize for KeychainStaticSecret {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl KeychainStaticSecret {
    pub fn parse_bytes(bs: &[u8]) -> XResult<Self> {
        let key_str = opt_result!(String::from_utf8(bs.to_vec()), "Parse static secret failed: {}");
        Self::parse(&key_str)
    }

    pub fn parse(key: &str) -> XResult<Self> {
        let algo = opt_value_result!(
            KeychainStaticSecretAlgorithm::from_prefix(key), "Unknown static secret: {}", key);
        let extract_key_hex = &key[algo.prefix().len()..];
        let extract_key = opt_result!(hex::decode(extract_key_hex), "Decode static secret plain key failed: {}");
        let (secret, public) = match algo {
            KeychainStaticSecretAlgorithm::X25519 => {
                (extract_key, None)
            }
            KeychainStaticSecretAlgorithm::Kyber1024 => {
                // pub const PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 3168;
                // pub const PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1568;
                let secret_key_bytes_len = 3168;
                let public_key_bytes_len = 1568;
                if extract_key.len() != secret_key_bytes_len + public_key_bytes_len {
                    return simple_error!("Bad kyber1024 secret and public keys.");
                }
                (extract_key[0..secret_key_bytes_len].to_vec(), Some(extract_key[secret_key_bytes_len..].to_vec()))
            }
        };
        Ok(Self {
            algo,
            secret,
            public,
        })
    }

    pub fn to_str(&self) -> String {
        let mut v = String::new();
        v.push_str(self.algo.prefix());
        v.push_str(&hex::encode(&self.secret));
        if let Some(public) = &self.public {
            v.push_str(&hex::encode(public));
        }
        v
    }

    pub fn from_x25519_bytes(secret: &[u8]) -> Self {
        Self::from_bytes(KeychainStaticSecretAlgorithm::X25519, secret, None)
    }

    pub fn from_kyber1024_bytes(secret: &[u8], public: &[u8]) -> Self {
        Self::from_bytes(KeychainStaticSecretAlgorithm::Kyber1024, secret, Some(public))
    }

    pub fn from_bytes(algo: KeychainStaticSecretAlgorithm, secret: &[u8], public: Option<&[u8]>) -> Self {
        Self {
            algo,
            secret: secret.to_vec(),
            public: public.map(|p| p.to_vec()),
        }
    }

    pub fn to_kyber1204_static_secret(&self) -> XResult<(Kyber1024SecretKey, Kyber1024PublicKey)> {
        use pqcrypto_traits::kem::{PublicKey, SecretKey};
        let secret_key = opt_result!(Kyber1024SecretKey::from_bytes(&self.secret),
            "Parse kyber1204 private key failed: {}");
        let public_key = opt_result!(match &self.public {
            None => return simple_error!("Kyber1204 public key not found."),
            Some(public) => Kyber1024PublicKey::from_bytes(public),
        }, "Parse kyber1204 public key failed: {}");
        Ok((secret_key, public_key))
    }

    pub fn to_x25519_static_secret(&self) -> XResult<StaticSecret> {
        let secret_slice = self.secret.as_slice();
        let mut inner_secret: [u8; 32] = opt_result!(secret_slice.try_into(), "X25519 secret key error: {}");
        let static_secret = StaticSecret::from(inner_secret);
        inner_secret.zeroize();
        Ok(static_secret)
    }

    pub fn to_x25519_public_key(&self) -> XResult<PublicKey> {
        let static_secret = self.to_x25519_static_secret()?;
        let public_key: PublicKey = (&static_secret).into();
        Ok(public_key)
    }
}

impl KeychainKey {
    pub fn from(keychain_name: &str, service_name: &str, key_name: &str) -> Self {
        debugging!("Keychain key: {} - {} - {}", keychain_name, service_name, key_name);
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
        debugging!("Try find generic password: {}.{}", &self.service_name, &self.key_name);
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
            let keychain_file_name = format!("{}.keychain", &self.keychain_name);
            debugging!("Open or create keychain: {}", &keychain_file_name);
            let keychain_exists = check_keychain_exists(&keychain_file_name);
            if keychain_exists {
                Ok(opt_result!(SecKeychain::open(&keychain_file_name), "Open keychain: {}, failed: {}", &keychain_file_name))
            } else {
                match CreateOptions::new().prompt_user(true).create(&keychain_file_name) {
                    Ok(sec_keychain) => Ok(sec_keychain),
                    Err(ce) => match SecKeychain::open(&keychain_file_name) {
                        Ok(sec_keychain) => Ok(sec_keychain),
                        Err(oe) => simple_error!("Create keychain: {}, failed: {}, open also failed: {}", &self.keychain_name, ce, oe)
                    }
                }
            }
        } else {
            Ok(opt_result!(SecKeychain::default(), "Get keychain failed: {}"))
        }
    }
}

pub fn decrypt_x25519_data(keychain_key: &KeychainKey, ephemeral_public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    let static_x25519 = opt_value_result!(keychain_key.get_password()?, "Static X25519 not found: {}", &keychain_key.to_str());

    let x25519_static_secret = KeychainStaticSecret::parse_bytes(&static_x25519)?;
    let static_secret = x25519_static_secret.to_x25519_static_secret()?;
    let inner_ephemeral_public_key: [u8; 32] = opt_result!(
        ephemeral_public_key_bytes.try_into(), "X25519 public key error: {}");
    let ephemeral_public_key = PublicKey::from(inner_ephemeral_public_key);
    let shared_secret = static_secret.diffie_hellman(&ephemeral_public_key);

    Ok(shared_secret.as_bytes().to_vec())
}

pub fn decrypt_kyber1204_data(keychain_key: &KeychainKey, ephemeral_public_key_bytes: &[u8]) -> XResult<Vec<u8>> {
    use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
    let static_kyber1204 = opt_value_result!(keychain_key.get_password()?, "Static Kyber1204 not found: {}", &keychain_key.to_str());

    let kyber1204_static_secret = KeychainStaticSecret::parse_bytes(&static_kyber1204)?;
    let (static_secret, _) = kyber1204_static_secret.to_kyber1204_static_secret()?;
    let ciphertext = opt_result!(
        Kyber1024Ciphertext::from_bytes(ephemeral_public_key_bytes), "Parse kyber1204 ciphertext failed: {}");
    let shared_secret = kyber1024::decapsulate(&ciphertext, &static_secret);

    Ok(shared_secret.as_bytes().to_vec())
}

pub fn generate_static_x25519_secret() -> (String, PublicKey) {
    let static_secret = StaticSecret::random();
    let public_key: PublicKey = (&static_secret).into();
    let static_secret_bytes = static_secret.as_bytes();
    let x25519_static_secret = KeychainStaticSecret::from_x25519_bytes(static_secret_bytes);
    (x25519_static_secret.to_str(), public_key)
}

pub fn generate_static_kyber1024_secret() -> (String, Kyber1024PublicKey) {
    use pqcrypto_traits::kem::{PublicKey, SecretKey};
    let (public_key, private_key) = kyber1024::keypair();
    let static_secret_bytes = private_key.as_bytes();
    let static_public_bytes = public_key.as_bytes();
    let kyber1024_static_secret =
        KeychainStaticSecret::from_kyber1024_bytes(static_secret_bytes, static_public_bytes);
    (kyber1024_static_secret.to_str(), public_key)
}

fn check_keychain_exists(keychain_file_name: &str) -> bool {
    let keychain_path = PathBuf::from(util_file::resolve_file_path("~/Library/Keychains/"));
    match keychain_path.read_dir() {
        Ok(read_dir) => {
            for dir in read_dir {
                match dir {
                    Ok(dir) => if let Some(file_name) = dir.file_name().to_str() {
                        if file_name.starts_with(keychain_file_name) {
                            debugging!("Found key chain file: {:?}", dir);
                            return true;
                        }
                    }
                    Err(e) => {
                        debugging!("Read path sub dir: {:?} failed: {}", keychain_path, e);
                    }
                }
            }
        }
        Err(e) => {
            debugging!("Read path: {:?} failed: {}", keychain_path, e);
        }
    }
    false
}