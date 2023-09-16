use std::io::{Read, Write};

use rust_util::{opt_result, simple_error, XResult};

use crate::spec::TinyEncryptMeta;

pub fn _write_tiny_encrypt_meta<W: Write>(w: &mut W, meta: &TinyEncryptMeta) -> XResult<usize> {
    let meta_json = opt_result!( serde_json::to_string(meta), "Meta to JSON failed: {}");
    let meta_json_bytes = meta_json.as_bytes();
    let meta_json_bytes_len = meta_json_bytes.len();

    opt_result!(w.write_all(&((0x01) as u16).to_be_bytes()), "Write tag failed: {}");
    opt_result!(w.write_all(&(meta_json_bytes_len as u32).to_be_bytes()), "Write length failed: {}");
    opt_result!(w.write_all(&meta_json_bytes), "Write meta failed: {}");

    Ok(meta_json_bytes_len + 2 + 4)
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
    if tag != 0x01 {
        return simple_error!("Tag is not 0x01, but is: 0x{:x}", tag);
    }

    let mut length_buff = [0_u8; 4];
    opt_result!(r.read_exact(&mut length_buff), "Read length failed: {}");
    let length = u32::from_be_bytes(length_buff);
    if length > 1024 * 1024 {
        return simple_error!("Meta too large: {}", length);
    }

    let mut meta_buff = vec![0; length as usize];
    opt_result!(r.read_exact(meta_buff.as_mut_slice()), "Read meta failed: {}");

    Ok(opt_result!(serde_json::from_slice(&meta_buff), "Parse meta failed: {}"))
}
