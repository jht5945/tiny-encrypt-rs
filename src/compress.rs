use std::io::Write;

use flate2::Compression;
use flate2::write::{GzDecoder, GzEncoder};
use rust_util::{simple_error, XResult};

pub struct GzStreamEncoder {
    gz_encoder: GzEncoder<Vec<u8>>,
}

impl GzStreamEncoder {
    pub fn new_default() -> Self {
        GzStreamEncoder::new(Compression::default())
    }

    pub fn new(compression: Compression) -> Self {
        let buffer = Vec::with_capacity(1024 * 8);
        let gz_encoder = GzEncoder::new(buffer, compression);
        Self { gz_encoder }
    }

    pub fn update(&mut self, buff: &[u8]) -> XResult<Vec<u8>> {
        self.gz_encoder.write_all(buff)?;
        let inner = self.gz_encoder.get_mut();
        let result = inner.clone();
        inner.clear();
        Ok(result)
    }

    pub fn finalize(self) -> XResult<Vec<u8>> {
        match self.gz_encoder.finish() {
            Ok(last_buffer) => Ok(last_buffer),
            Err(e) => simple_error!("Decode stream failed: {}", e),
        }
    }
}

pub struct GzStreamDecoder {
    gz_decoder: GzDecoder<Vec<u8>>,
}

impl GzStreamDecoder {
    pub fn new() -> Self {
        let buffer = Vec::with_capacity(1024 * 8);
        let gz_decoder = GzDecoder::new(buffer);
        Self { gz_decoder }
    }

    pub fn update(&mut self, buff: &[u8]) -> XResult<Vec<u8>> {
        self.gz_decoder.write_all(buff)?;
        let inner = self.gz_decoder.get_mut();
        let result = inner.clone();
        inner.clear();
        Ok(result)
    }

    pub fn finalize(self) -> XResult<Vec<u8>> {
        match self.gz_decoder.finish() {
            Ok(last_buffer) => Ok(last_buffer),
            Err(e) => simple_error!("Decode stream failed: {}", e),
        }
    }
}

#[test]
fn test_gzip_compress() {
    for (compressed, decompressed) in vec![
        ("1f8b0800000000000000f348cdc9c95708cf2fca49010056b1174a0b000000", "Hello World"),
        (
            "1f8b0800000000000000f348cdc9c95708cf2fca49f12081090044f4575937000000",
            "Hello WorldHello WorldHello WorldHello WorldHello World"
        ),
    ] {
        let compressed = hex::decode(compressed).unwrap();
        let mut decoder = GzStreamDecoder::new();
        let mut decompressed_bytes = decoder.update(&compressed).unwrap();
        let last_buffer = decoder.finalize().unwrap();
        decompressed_bytes.extend_from_slice(&last_buffer);
        assert_eq!(decompressed, String::from_utf8(decompressed_bytes).unwrap());
    }
}

#[test]
fn test_gzip_compress_multi_blocks() {
    let compressed = hex::decode("1f8b0800000000000000f348cdc9c95708cf2fca49f12081090044f4575937000000").unwrap();
    let decompressed = "Hello WorldHello WorldHello WorldHello WorldHello World";
    let mut decoder = GzStreamDecoder::new();
    let mut decompressed_bytes = vec![];
    for i in 0..compressed.len() {
        let b = decoder.update(&compressed[i..i + 1]).unwrap();
        decompressed_bytes.extend_from_slice(&b);
    }
    let last_buffer = decoder.finalize().unwrap();
    decompressed_bytes.extend_from_slice(&last_buffer);
    assert_eq!(decompressed, String::from_utf8(decompressed_bytes).unwrap());
}


#[test]
fn test_gzip_decompress() {
    for (compression, message) in vec![
        (Compression::default(), "Hello World"),
        (Compression::default(), "Hello WorldHello WorldHello World"),
        (Compression::default(), "Hello WorldHello WorldHello WorldHello WorldHello World"),
        (Compression::default(), "Hello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello World"),
        (Compression::none(), "Hello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello World"),
        (Compression::fast(), "Hello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello World"),
        (Compression::best(), "Hello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello World"),
    ] {
        let mut encoder = GzStreamEncoder::new(compression);
        let mut compressed_bytes = encoder.update(message.as_bytes()).unwrap();
        let last_compress_buffer = encoder.finalize().unwrap();
        compressed_bytes.extend_from_slice(&last_compress_buffer);

        let mut decoder = GzStreamDecoder::new();
        let mut decompressed_bytes = decoder.update(&compressed_bytes).unwrap();
        let last_decompress_buffer = decoder.finalize().unwrap();
        decompressed_bytes.extend_from_slice(&last_decompress_buffer);

        let decompressed_string = String::from_utf8(decompressed_bytes).unwrap();

        assert_eq!(message, decompressed_string.as_str());
    }
}