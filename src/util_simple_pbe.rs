use crate::util_digest;
use aes_gcm_stream::{Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::random;
use rust_util::{opt_result, simple_error, SimpleError, XResult};
use std::fmt::Display;

const SIMPLE_PBKDF_ENCRYPTION_PREFIX: &str = "tinyencrypt-pbkdf-encryption-v1";
// FORMAT
// <PREFIX>.<repeation>.<iterations>.<base64_uri(salt)>.<base64_uri(nonce)>.<base64_uri(ciphertext)>.<base64_uri(tag)>

pub struct SimplePbkdfEncryptionV1 {
    pub repetition: u32,
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

impl SimplePbkdfEncryptionV1 {
    pub fn matches(enc: &str) -> bool {
        enc.starts_with(&format!("{SIMPLE_PBKDF_ENCRYPTION_PREFIX}."))
    }

    pub fn encrypt(password: &str, plaintext: &[u8]) -> XResult<SimplePbkdfEncryptionV1> {
        let salt: [u8; 12] = random();
        let repetition = 1000;
        let iterations = 10000;
        let key = simple_pbkdf(password.as_bytes(), &salt, repetition, iterations);

        let key_bytes: [u8; 32] = opt_result!(key.try_into(), "Bad AES 256 key: {:?}");
        let nonce: [u8; 12] = random();
        let mut ciphertext = vec![];

        let mut aes256_gcm_stream_encryptor = Aes256GcmStreamEncryptor::new(key_bytes, &nonce);
        ciphertext.extend_from_slice(&aes256_gcm_stream_encryptor.update(plaintext));
        let (last_ciphertext, tag) = aes256_gcm_stream_encryptor.finalize();
        ciphertext.extend_from_slice(&last_ciphertext);

        Ok(SimplePbkdfEncryptionV1 {
            repetition,
            iterations,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            ciphertext,
            tag,
        })
    }

    pub fn decrypt(&self, password: &str) -> XResult<Vec<u8>> {
        let key = simple_pbkdf(
            password.as_bytes(),
            &self.salt,
            self.repetition,
            self.iterations,
        );
        let key_bytes: [u8; 32] = opt_result!(key.try_into(), "Bad AES 256 key: {:?}");
        let mut plaintext = vec![];

        let mut aes256_gcm_stream_decryptor = Aes256GcmStreamDecryptor::new(key_bytes, &self.nonce);
        plaintext.extend_from_slice(&aes256_gcm_stream_decryptor.update(&self.ciphertext));
        plaintext.extend_from_slice(&aes256_gcm_stream_decryptor.update(&self.tag));
        plaintext.extend_from_slice(&opt_result!(
            aes256_gcm_stream_decryptor.finalize(),
            "Decrypt failed: {}"
        ));

        Ok(plaintext)
    }
}

impl TryFrom<String> for SimplePbkdfEncryptionV1 {
    type Error = SimpleError;

    fn try_from(enc: String) -> Result<Self, Self::Error> {
        TryFrom::<&str>::try_from(enc.as_str())
    }
}

impl TryFrom<&str> for SimplePbkdfEncryptionV1 {
    type Error = SimpleError;

    fn try_from(enc: &str) -> Result<Self, Self::Error> {
        if !Self::matches(enc) {
            return simple_error!("Not simple PBKDF encryption: {enc}");
        }
        let parts = enc.split(".").collect::<Vec<_>>();

        let repetition: u32 = opt_result!(
            parts[1].parse(),
            "Parse simple PBKDF failed, invalid repetition: {}, error: {}",
            parts[1]
        );
        let iterations: u32 = opt_result!(
            parts[2].parse(),
            "Parse simple PBKDF failed, invalid iterations: {}, error: {}",
            parts[2]
        );
        let salt = opt_result!(
            URL_SAFE_NO_PAD.decode(parts[3]),
            "Parse simple PBKDF failed, invalid salt: {}, error: {}",
            parts[3]
        );
        let nonce = opt_result!(
            URL_SAFE_NO_PAD.decode(parts[4]),
            "Parse simple PBKDF failed, invalid nonce: {}, error: {}",
            parts[4]
        );
        let ciphertext = opt_result!(
            URL_SAFE_NO_PAD.decode(parts[5]),
            "Parse simple PBKDF failed, invalid ciphertext: {}, error: {}",
            parts[5]
        );
        let tag = opt_result!(
            URL_SAFE_NO_PAD.decode(parts[6]),
            "Parse simple PBKDF failed, invalid tag: {}, error: {}",
            parts[6]
        );

        Ok(Self {
            repetition,
            iterations,
            salt,
            nonce,
            ciphertext,
            tag,
        })
    }
}

impl Display for SimplePbkdfEncryptionV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut enc = String::with_capacity(1024);
        enc.push_str(SIMPLE_PBKDF_ENCRYPTION_PREFIX);
        enc.push('.');
        enc.push_str(&self.repetition.to_string());
        enc.push('.');
        enc.push_str(&self.iterations.to_string());
        enc.push('.');
        enc.push_str(&URL_SAFE_NO_PAD.encode(&self.salt));
        enc.push('.');
        enc.push_str(&URL_SAFE_NO_PAD.encode(&self.nonce));
        enc.push('.');
        enc.push_str(&URL_SAFE_NO_PAD.encode(&self.ciphertext));
        enc.push('.');
        enc.push_str(&URL_SAFE_NO_PAD.encode(&self.tag));
        write!(f, "{}", enc)
    }
}

fn simple_pbkdf(password: &[u8], salt: &[u8], repetition: u32, iterations: u32) -> Vec<u8> {
    let mut input = password.to_vec();
    for it in 0..iterations {
        let mut message = Vec::with_capacity((input.len() + salt.len() + 4) * repetition as usize);
        for _ in 0..repetition {
            message.extend_from_slice(&it.to_be_bytes());
            message.extend_from_slice(&input);
            message.extend_from_slice(salt);
        }
        input = util_digest::sha256_digest(&message);
    }
    input
}

#[test]
fn test() {
    let enc = SimplePbkdfEncryptionV1::encrypt("helloworld", "test".as_bytes()).unwrap();
    let enc_str = enc.to_string();
    let enc2: SimplePbkdfEncryptionV1 = enc_str.try_into().unwrap();
    assert_eq!(enc.to_string(), enc2.to_string());
    let plain = enc2.decrypt("helloworld").unwrap();
    assert_eq!(b"test", plain.as_slice());
}
