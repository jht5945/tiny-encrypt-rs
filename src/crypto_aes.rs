use aes_gcm_stream::{Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor};
use rust_util::{opt_result, XResult};

pub fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], message: &[u8]) -> XResult<Vec<u8>> {
    let key: [u8; 32] = opt_result!(key.try_into(), "Invalid envelop: {}");
    let mut aes256_gcm = Aes256GcmStreamDecryptor::new(key, nonce);
    let mut b1 = aes256_gcm.update(message);
    let b2 = opt_result!(aes256_gcm.finalize(), "Invalid envelop: {}");
    b1.extend_from_slice(&b2);
    Ok(b1)
}

pub fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], message: &[u8]) -> XResult<Vec<u8>> {
    let key: [u8; 32] = opt_result!(key.try_into(), "Invalid envelop: {}");
    let mut aes256_gcm = Aes256GcmStreamEncryptor::new(key, nonce);
    let mut b1 = aes256_gcm.update(message);
    let (b2, tag) = aes256_gcm.finalize();
    b1.extend_from_slice(&b2);
    b1.extend_from_slice(&tag);
    Ok(b1)
}

#[test]
fn test_aes_gcm_01() {
    let data_key = hex::decode("0001020304050607080910111213141516171819202122232425262728293031").unwrap();
    let nonce = hex::decode("000102030405060708091011").unwrap();

    let plain_text1 = "Hello world!".as_bytes();
    let encrypted_text1 = "dce9511866417cff5123fa08c9e92cf156c5fc8bf6108ff28816fb58";

    let plain_text2 = "This is a test message.".as_bytes();
    let encrypted_text2 = "c0e45407290878b0426fea4c09597ce323b056f975c63cce6c8da516c2a78c7d71b590c869cf92";

    let key256: [u8; 32] = data_key.as_slice().try_into().unwrap();
    {
        let mut encryptor = Aes256GcmStreamEncryptor::new(key256.clone(), &nonce);
        let mut encrypted = encryptor.update(plain_text1);
        let (last_block, tag) = encryptor.finalize();
        encrypted.extend_from_slice(&last_block);
        encrypted.extend_from_slice(&tag);
        assert_eq!(encrypted_text1, hex::encode(&encrypted));
    }
    {
        let mut encryptor = Aes256GcmStreamEncryptor::new(key256.clone(), &nonce);
        let mut encrypted = encryptor.update(plain_text2);
        let (last_block, tag) = encryptor.finalize();
        encrypted.extend_from_slice(&last_block);
        encrypted.extend_from_slice(&tag);
        assert_eq!(encrypted_text2, hex::encode(&encrypted));
    }
}

#[test]
fn test_aes_gcm_02() {
    let data_key = hex::decode("aa01020304050607080910111213141516171819202122232425262728293031").unwrap();
    let nonce = hex::decode("aa0102030405060708091011").unwrap();

    let plain_text1 = hex::encode("Hello world!".as_bytes());
    let encrypted_text1 = hex::decode("42b625d2bacb8a514076f14002f02770e9ccd98c90e556dc267aca30").unwrap();

    let plain_text2 = hex::encode("This is a test message.".as_bytes());
    let encrypted_text2 = hex::decode("5ebb20cdf5828e1e533ae1043ce6703cfa51574a83a069700aedefdbe2c735b01b74da214cba4a").unwrap();

    let key256: [u8; 32] = data_key.as_slice().try_into().unwrap();
    {
        let mut decryptor = Aes256GcmStreamDecryptor::new(key256.clone(), &nonce);
        let mut plain_text = decryptor.update(encrypted_text1.as_slice());
        let last_block = decryptor.finalize().unwrap();
        plain_text.extend_from_slice(&last_block);
        assert_eq!(plain_text1, hex::encode(&plain_text));
    }
    {
        let mut decryptor = Aes256GcmStreamDecryptor::new(key256.clone(), &nonce);
        let mut plain_text = decryptor.update(encrypted_text2.as_slice());
        let last_block = decryptor.finalize().unwrap();
        plain_text.extend_from_slice(&last_block);
        assert_eq!(plain_text2, hex::encode(&plain_text));
    }
}