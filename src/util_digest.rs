use std::io::Write;
use std::iter::repeat;

use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::ripemd160::Ripemd160;
use crypto::sha1::Sha1;
use crypto::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};
use crypto::sha3::Sha3;
use crypto::whirlpool::Whirlpool;
use rust_util::{simple_error, XResult};

pub struct DigestWrite {
    digest: Box<dyn Digest>,
}

impl Write for DigestWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.digest.input(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl DigestWrite {
    pub fn from_algo(algo: &str) -> XResult<Self> {
        match get_digest_by_algorithm(algo) {
            None => simple_error!("Unsupported algo: {}", algo),
            Some(digest) => Ok(Self { digest })
        }
    }

    pub fn sha256() -> Self {
        Self { digest: Box::new(Sha256::new()) }
    }

    pub fn digest(self) -> Vec<u8> {
        let mut digest = self.digest;
        let mut buf: Vec<u8> = repeat(0).take((digest.output_bits() + 7) / 8).collect();
        digest.result(&mut buf);
        buf
    }
}

fn get_digest_by_algorithm(algo: &str) -> Option<Box<dyn Digest>> {
    let algo = algo.to_uppercase();
    match algo.as_str() {
        "RIPEMD160" => Some(Box::new(Ripemd160::new())),
        "WHIRLPOOL" => Some(Box::new(Whirlpool::new())),
        // "BLAKE2S" => Some(Box::new(Blake2s::new(iff!(options.blake_len == 0_usize, 32, options.blake_len)))),
        // "BLAKE2B" => Some(Box::new(Blake2b::new(iff!(options.blake_len == 0_usize, 64, options.blake_len)))),
        "MD5" => Some(Box::new(Md5::new())),
        "SHA1" | "SHA-1" => Some(Box::new(Sha1::new())),
        "SHA224" | "SHA-224" => Some(Box::new(Sha224::new())),
        "SHA256" | "SHA-256" => Some(Box::new(Sha256::new())),
        "SHA384" | "SHA-384" => Some(Box::new(Sha384::new())),
        "SHA512" | "SHA-512" => Some(Box::new(Sha512::new())),
        "SHA512-224" => Some(Box::new(Sha512Trunc224::new())),
        "SHA512-256" => Some(Box::new(Sha512Trunc256::new())),
        "SHA3-224" => Some(Box::new(Sha3::sha3_224())),
        "SHA3-256" => Some(Box::new(Sha3::sha3_256())),
        "SHA3-384" => Some(Box::new(Sha3::sha3_384())),
        "SHA3-512" => Some(Box::new(Sha3::sha3_512())),
        "SHAKE-128" => Some(Box::new(Sha3::shake_128())),
        "SHAKE-256" => Some(Box::new(Sha3::shake_256())),
        "KECCAK-224" => Some(Box::new(Sha3::keccak224())),
        "KECCAK-256" => Some(Box::new(Sha3::keccak256())),
        "KECCAK-384" => Some(Box::new(Sha3::keccak384())),
        "KECCAK-512" => Some(Box::new(Sha3::keccak512())),
        _ => None,
    }
}