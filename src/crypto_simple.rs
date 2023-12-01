use rust_util::XResult;

use crate::crypto_cryptor::{Cryptor, KeyNonce};
use crate::util_digest;

pub fn try_decrypt_with_salt(crypto: Cryptor, key_nonce: &KeyNonce, salt: &[u8], message: &[u8]) -> XResult<Vec<u8>> {
    let new_nonce = build_salted_nonce(key_nonce.n, salt);
    let new_key_nonce = KeyNonce { k: key_nonce.k, n: &new_nonce };
    if let Ok(decrypted) = decrypt(crypto, &new_key_nonce, message) {
        return Ok(decrypted);
    }
    decrypt(crypto, key_nonce, message)
}

pub fn decrypt(crypto: Cryptor, key_nonce: &KeyNonce, message: &[u8]) -> XResult<Vec<u8>> {
    crypto.decryptor(key_nonce)?.decrypt(message)
}

pub fn encrypt_with_salt(crypto: Cryptor, key_nonce: &KeyNonce, salt: &[u8], message: &[u8]) -> XResult<Vec<u8>> {
    let new_nonce = build_salted_nonce(key_nonce.n, salt);
    let new_key_nonce = KeyNonce { k: key_nonce.k, n: &new_nonce };
    encrypt(crypto, &new_key_nonce, message)
}

pub fn encrypt(crypto: Cryptor, key_nonce: &KeyNonce, message: &[u8]) -> XResult<Vec<u8>> {
    Ok(crypto.encryptor(key_nonce)?.encrypt(message))
}

fn build_salted_nonce(nonce: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut nonce_with_salt = nonce.to_vec();
    nonce_with_salt.extend_from_slice(salt);
    let input = util_digest::sha256_digest(&nonce_with_salt);
    // let input = hex::decode(sha256::digest(nonce_with_salt)).unwrap();
    input[0..12].to_vec()
}
