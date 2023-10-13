use std::io::{Read, Write};

use flate2::Compression;
use rust_util::{debugging, iff, opt_result, simple_error, XResult};

use crate::compress;
use crate::consts::{TINY_ENC_COMPRESSED_MAGIC_TAG, TINY_ENC_MAGIC_TAG};
use crate::spec::TinyEncryptMeta;

pub fn write_tiny_encrypt_meta<W: Write>(w: &mut W, meta: &TinyEncryptMeta, compress_meta: bool) -> XResult<usize> {
    let tag = iff!(compress_meta, TINY_ENC_COMPRESSED_MAGIC_TAG, TINY_ENC_MAGIC_TAG);
    opt_result!(w.write_all(&tag.to_be_bytes()), "Write tag failed: {}");
    let mut encrypted_meta_bytes = opt_result!(serde_json::to_vec(&meta), "Generate meta json bytes failed: {}");
    if compress_meta {
        encrypted_meta_bytes = opt_result!(
            compress::compress(Compression::default(), &encrypted_meta_bytes), "Compress encrypted meta failed: {}");
    }
    let encrypted_meta_bytes_len = encrypted_meta_bytes.len() as u32;
    debugging!("Encrypted meta len: {}", encrypted_meta_bytes_len);
    opt_result!(w.write_all(&encrypted_meta_bytes_len.to_be_bytes()), "Write meta len failed: {}");
    opt_result!(w.write_all(&encrypted_meta_bytes), "Write meta failed: {}");

    Ok(encrypted_meta_bytes.len() + 2 + 4)
}

pub fn read_tiny_encrypt_meta_and_normalize<R: Read>(r: &mut R) -> XResult<TinyEncryptMeta> {
    let mut meta = read_tiny_encrypt_meta(r);
    let _ = meta.as_mut().map(|meta| meta.normalize());
    meta
}

pub fn read_tiny_encrypt_meta<R: Read>(r: &mut R) -> XResult<TinyEncryptMeta> {
    let mut tag_buff = [0_u8; 2];
    opt_result!(r.read_exact(&mut tag_buff), "Read tag failed: {}");
    let tag = u16::from_be_bytes(tag_buff);
    let is_normal_tiny_enc = tag == TINY_ENC_MAGIC_TAG;
    let is_compressed_tiny_enc = tag == TINY_ENC_COMPRESSED_MAGIC_TAG;
    if !is_normal_tiny_enc && !is_compressed_tiny_enc {
        return simple_error!("Tag is not 0x01 or 0x02, but is: 0x{:x}", tag);
    }

    let mut length_buff = [0_u8; 4];
    opt_result!(r.read_exact(&mut length_buff), "Read length failed: {}");
    let length = u32::from_be_bytes(length_buff);
    if length > 1024 * 1024 {
        return simple_error!("Meta too large: {}", length);
    }

    debugging!("Encrypted meta len: {}", length);
    let mut meta_buff = vec![0; length as usize];
    opt_result!(r.read_exact(meta_buff.as_mut_slice()), "Read meta failed: {}");

    debugging!("Tiny enc meta compressed: {}", is_compressed_tiny_enc);
    if is_compressed_tiny_enc {
        meta_buff = opt_result!(compress::decompress(&meta_buff), "Decompress meta failed: {}");
    }
    debugging!("Encrypted meta: {}", String::from_utf8_lossy(&meta_buff));

    Ok(opt_result!(serde_json::from_slice(&meta_buff), "Parse meta failed: {}"))
}
