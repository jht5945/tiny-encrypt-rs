use rust_util::XResult;

use crate::crypto_cryptor::Cryptor;

pub fn try_decrypt_with_salt(crypto: Cryptor, key: &[u8], nonce: &[u8], salt: &[u8], message: &[u8]) -> XResult<Vec<u8>> {
    let new_nonce = build_salted_nonce(nonce, salt);
    if let Ok(decrypted) = decrypt(crypto, key, &new_nonce, message) {
        return Ok(decrypted);
    }
    decrypt(crypto, key, nonce, message)
}

pub fn decrypt(crypto: Cryptor, key: &[u8], nonce: &[u8], message: &[u8]) -> XResult<Vec<u8>> {
    crypto.decryptor(key, nonce)?.decrypt(message)
}

pub fn encrypt_with_salt(crypto: Cryptor, key: &[u8], nonce: &[u8], salt: &[u8], message: &[u8]) -> XResult<Vec<u8>> {
    let new_nonce = build_salted_nonce(nonce, salt);
    encrypt(crypto, key, &new_nonce, message)
}

pub fn encrypt(crypto: Cryptor, key: &[u8], nonce: &[u8], message: &[u8]) -> XResult<Vec<u8>> {
    Ok(crypto.encryptor(key, nonce)?.encrypt(message))
}

fn build_salted_nonce(nonce: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut nonce_with_salt = nonce.to_vec();
    nonce_with_salt.extend_from_slice(salt);
    let input = hex::decode(sha256::digest(nonce_with_salt)).unwrap();
    input[0..12].to_vec()
}
