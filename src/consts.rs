// AES-GCM-ECDH Algorithms
pub const ENC_AES256_GCM_P256: &str = "aes256-gcm-p256";
pub const ENC_AES256_GCM_P384: &str = "aes256-gcm-p384";
pub const ENC_AES256_GCM_X25519: &str = "aes256-gcm-x25519";

// Extend and config file
pub const TINY_ENC_FILE_EXT: &str = ".tinyenc";
pub const TINY_ENC_CONFIG_FILE: &str = "~/.tinyencrypt/config-rs.json";

pub const TINY_ENC_AES_GCM: &str = "AES/GCM";

// Tiny enc magic tag
pub const TINY_ENC_MAGIC_TAG: u16 = 0x01;
pub const TINY_ENC_COMPRESSED_MAGIC_TAG: u16 = 0x02;

// Encryption nonce salt
pub const SALT_COMMENT: &[u8] = b"salt:comment";
pub const SALT_META: &[u8] = b"salt:meta";
