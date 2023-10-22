use aes_gcm_stream::{Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor};
use chacha20_poly1305_stream::{ChaCha20Poly1305StreamDecryptor, ChaCha20Poly1305StreamEncryptor};
use rust_util::{opt_result, simple_error, XResult};
use zeroize::Zeroize;

use crate::consts;

#[derive(Debug, Copy, Clone)]
pub enum Cryptor {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Cryptor {
    pub fn from(algorithm: &str) -> XResult<Self> {
        match algorithm {
            "aes256-gcm" | consts::TINY_ENC_AES_GCM => Ok(Cryptor::Aes256Gcm),
            "chacha20-poly1305" | consts::TINY_ENC_CHACHA20_POLY1305 => Ok(Cryptor::ChaCha20Poly1305),
            _ => simple_error!("Unknown altorighm: {}",algorithm),
        }
    }

    pub fn get_name(&self) -> String {
        let name = match self {
            Cryptor::Aes256Gcm => consts::TINY_ENC_AES_GCM,
            Cryptor::ChaCha20Poly1305 => consts::TINY_ENC_CHACHA20_POLY1305,
        };
        name.to_string()
    }

    pub fn encryptor(self, key: &[u8], nonce: &[u8]) -> XResult<Box<dyn Encryptor>> {
        get_encryptor(self, key, nonce)
    }

    pub fn decryptor(self, key: &[u8], nonce: &[u8]) -> XResult<Box<dyn Decryptor>> {
        get_decryptor(self, key, nonce)
    }
}

pub trait Encryptor {
    fn update(&mut self, message: &[u8]) -> Vec<u8>;

    fn finalize(&mut self) -> (Vec<u8>, Vec<u8>);

    fn encrypt(&mut self, message: &[u8]) -> Vec<u8> {
        let mut cipher_text = self.update(message);
        let (last_block, tag) = self.finalize();
        cipher_text.extend_from_slice(&last_block);
        cipher_text.extend_from_slice(&tag);
        cipher_text
    }
}

pub trait Decryptor {
    fn update(&mut self, message: &[u8]) -> Vec<u8>;

    fn finalize(&mut self) -> XResult<Vec<u8>>;

    fn decrypt(&mut self, message: &[u8]) -> XResult<Vec<u8>> {
        let mut plaintext = self.update(message);
        let last_block = self.finalize()?;
        plaintext.extend_from_slice(&last_block);
        Ok(plaintext)
    }
}

fn get_encryptor(crypto: Cryptor, key: &[u8], nonce: &[u8]) -> XResult<Box<dyn Encryptor>> {
    match crypto {
        Cryptor::Aes256Gcm => {
            let mut key: [u8; 32] = opt_result!(key.try_into(), "Bad AES 256 key: {}");
            let aes256_gcm_stream_encryptor = Aes256GcmStreamEncryptor::new(key, nonce);
            key.zeroize();
            Ok(Box::new(Aes256GcmEncryptor {
                aes256_gcm_stream_encryptor,
            }))
        }
        Cryptor::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Encryptor {
            chacha20_poly1305_stream_encryptor: ChaCha20Poly1305StreamEncryptor::new(key, nonce)?,
        }))
    }
}

fn get_decryptor(crypto: Cryptor, key: &[u8], nonce: &[u8]) -> XResult<Box<dyn Decryptor>> {
    match crypto {
        Cryptor::Aes256Gcm => {
            let mut key: [u8; 32] = opt_result!(key.try_into(), "Bad AES 256 key: {}");
            let aes256_gcm_stream_decryptor = Aes256GcmStreamDecryptor::new(key, nonce);
            key.zeroize();
            Ok(Box::new(Aes256GcmDecryptor {
                aes256_gcm_stream_decryptor,
            }))
        }
        Cryptor::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Decryptor {
            chacha20_poly1305_stream_decryptor: ChaCha20Poly1305StreamDecryptor::new(key, nonce)?,
        }))
    }
}

pub struct Aes256GcmEncryptor {
    aes256_gcm_stream_encryptor: Aes256GcmStreamEncryptor,
}

impl Encryptor for Aes256GcmEncryptor {
    fn update(&mut self, message: &[u8]) -> Vec<u8> {
        self.aes256_gcm_stream_encryptor.update(message)
    }

    fn finalize(&mut self) -> (Vec<u8>, Vec<u8>) {
        self.aes256_gcm_stream_encryptor.finalize()
    }
}

pub struct ChaCha20Poly1305Encryptor {
    chacha20_poly1305_stream_encryptor: ChaCha20Poly1305StreamEncryptor,
}

impl Encryptor for ChaCha20Poly1305Encryptor {
    fn update(&mut self, message: &[u8]) -> Vec<u8> {
        self.chacha20_poly1305_stream_encryptor.update(message)
    }

    fn finalize(&mut self) -> (Vec<u8>, Vec<u8>) {
        self.chacha20_poly1305_stream_encryptor.finalize()
    }
}

pub struct Aes256GcmDecryptor {
    aes256_gcm_stream_decryptor: Aes256GcmStreamDecryptor,
}

impl Decryptor for Aes256GcmDecryptor {
    fn update(&mut self, message: &[u8]) -> Vec<u8> {
        self.aes256_gcm_stream_decryptor.update(message)
    }

    fn finalize(&mut self) -> XResult<Vec<u8>> {
        Ok(self.aes256_gcm_stream_decryptor.finalize()?)
    }
}

pub struct ChaCha20Poly1305Decryptor {
    chacha20_poly1305_stream_decryptor: ChaCha20Poly1305StreamDecryptor,
}

impl Decryptor for ChaCha20Poly1305Decryptor {
    fn update(&mut self, message: &[u8]) -> Vec<u8> {
        self.chacha20_poly1305_stream_decryptor.update(message)
    }

    fn finalize(&mut self) -> XResult<Vec<u8>> {
        Ok(self.chacha20_poly1305_stream_decryptor.finalize()?)
    }
}

#[test]
fn test_cryptor() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let ciphertext = Cryptor::Aes256Gcm.encryptor(&key, &nonce).unwrap()
        .encrypt(b"hello world");
    let plaintext = Cryptor::Aes256Gcm.decryptor(&key, &nonce).unwrap()
        .decrypt(&ciphertext).unwrap();

    assert_eq!(b"hello world", plaintext.as_slice());
}
