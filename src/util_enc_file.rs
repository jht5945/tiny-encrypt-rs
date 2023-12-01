use std::io::{Read, Write};

use rust_util::{debugging, iff, opt_result, simple_error, XResult};

use crate::compress;
use crate::consts::{TINY_ENC_COMPRESSED_MAGIC_TAG, TINY_ENC_MAGIC_TAG};
use crate::spec::TinyEncryptMeta;

pub fn write_tiny_encrypt_meta(write: &mut impl Write, meta: &TinyEncryptMeta, compress_meta: bool) -> XResult<usize> {
    let meta_tag = iff!(compress_meta, TINY_ENC_COMPRESSED_MAGIC_TAG, TINY_ENC_MAGIC_TAG);
    opt_result!(write.write_all(&meta_tag.to_be_bytes()), "Write tag failed: {}");
    let mut encrypted_meta_bytes = opt_result!(serde_json::to_vec(&meta), "Generate meta json bytes failed: {}");
    if compress_meta {
        encrypted_meta_bytes = opt_result!(
            compress::compress_default(&encrypted_meta_bytes), "Compress encrypted meta failed: {}");
    }
    let encrypted_meta_bytes_len = encrypted_meta_bytes.len() as u32;
    debugging!("Encrypted meta len: {}", encrypted_meta_bytes_len);
    opt_result!(write.write_all(&encrypted_meta_bytes_len.to_be_bytes()), "Write meta len failed: {}");
    opt_result!(write.write_all(&encrypted_meta_bytes), "Write meta failed: {}");

    Ok(encrypted_meta_bytes.len() + 2 + 4)
}

pub fn read_tiny_encrypt_meta_and_normalize(r: &mut impl Read) -> XResult<(u32, bool, TinyEncryptMeta)> {
    let mut meta_len_and_meta = read_tiny_encrypt_meta(r);
    let _ = meta_len_and_meta.as_mut().map(|ml| ml.2.normalize());
    meta_len_and_meta
}

pub fn read_tiny_encrypt_meta(r: &mut impl Read) -> XResult<(u32, bool, TinyEncryptMeta)> {
    let mut meta_tag_buff = [0_u8; 2];
    opt_result!(r.read_exact(&mut meta_tag_buff), "Read tag failed: {}");
    let meta_tag = u16::from_be_bytes(meta_tag_buff);
    debugging!("Found tag: {}", meta_tag);
    let is_meta_normal = meta_tag == TINY_ENC_MAGIC_TAG;
    let is_meta_compressed = meta_tag == TINY_ENC_COMPRESSED_MAGIC_TAG;
    if !is_meta_normal && !is_meta_compressed {
        return simple_error!("Tag is not 0x01 or 0x02, but is: 0x{:x}", meta_tag);
    }

    let mut meta_length_buff = [0_u8; 4];
    opt_result!(r.read_exact(&mut meta_length_buff), "Read length failed: {}");
    let meta_length = u32::from_be_bytes(meta_length_buff);
    if meta_length > 10 * 1024 * 1024 {
        return simple_error!("Meta too large: {}", meta_length);
    }

    debugging!("Encrypted meta length: {}", meta_length);
    let mut meta_buff = vec![0; meta_length as usize];
    opt_result!(r.read_exact(meta_buff.as_mut_slice()), "Read meta failed: {}");

    debugging!("Tiny enc meta compressed: {}", is_meta_compressed);
    if is_meta_compressed {
        meta_buff = opt_result!(compress::decompress(&meta_buff), "Decompress meta failed: {}");
        debugging!("Encrypted meta decompressed: {} byte(s) -> {} byte(s)", meta_length, meta_buff.len());
    }
    debugging!("Encrypted meta: {}", String::from_utf8_lossy(&meta_buff));

    Ok((meta_length, is_meta_compressed, opt_result!(serde_json::from_slice(&meta_buff), "Parse meta failed: {}")))
}
