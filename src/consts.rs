// AES-GCM-ECDH Algorithms
pub const ENC_AES256_GCM_P256: &str = "aes256-gcm-p256";
pub const ENC_AES256_GCM_P384: &str = "aes256-gcm-p384";
pub const ENC_AES256_GCM_X25519: &str = "aes256-gcm-x25519";
pub const ENC_AES256_GCM_KYBER1204: &str = "aes256-gcm-kyber1204";
pub const ENC_CHACHA20_POLY1305_P256: &str = "chacha20-poly1305-p256";
pub const ENC_CHACHA20_POLY1305_P384: &str = "chacha20-poly1305-p384";
pub const ENC_CHACHA20_POLY1305_X25519: &str = "chacha20-poly1305-x25519";
pub const ENC_CHACHA20_POLY1305_KYBER1204: &str = "chacha20-poly1305-kyber1204";

// Extend and config file
pub const TINY_ENC_FILE_EXT: &str = ".tinyenc";
pub const TINY_ENC_PEM_FILE_EXT: &str = ".tinyenc.pem";
pub const TINY_ENC_CONFIG_FILE: &str = "~/.tinyencrypt/config-rs.json";
pub const TINY_ENC_CONFIG_FILE_2: &str = "/etc/tinyencrypt/config-rs.json";

pub const TINY_ENC_PEM_NAME: &str = "TINY ENCRYPT";

pub const TINY_ENC_AES_GCM: &str = "AES/GCM";
pub const TINY_ENC_CHACHA20_POLY1305: &str = "CHACHA20/POLY1305";

// Tiny enc magic tag
pub const TINY_ENC_MAGIC_TAG: u16 = 0x01;
pub const TINY_ENC_COMPRESSED_MAGIC_TAG: u16 = 0x02;

// Encryption nonce salt
pub const SALT_COMMENT: &[u8] = b"salt:comment";
pub const SALT_META: &[u8] = b"salt:meta";

pub const DATE_TIME_FORMAT: &str = "EEE MMM dd HH:mm:ss z yyyy";
