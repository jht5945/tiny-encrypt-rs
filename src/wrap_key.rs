use rust_util::{opt_result, simple_error, XResult};
use serde::{Deserialize, Serialize};

use crate::util;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrapKey {
    pub header: WrapKeyHeader,
    pub nonce: Vec<u8>,
    pub encrypted_data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrapKeyHeader {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub enc: String,
    pub e_pub_key: String,
}

impl WrapKeyHeader {
    pub fn from(enc_type: &str, ephemeral_spki: &[u8]) -> Self {
        WrapKeyHeader {
            kid: None,
            enc: enc_type.to_string(),
            e_pub_key: util::encode_base64_url_no_pad(ephemeral_spki),
        }
    }

    pub fn get_e_pub_key_bytes(self) -> XResult<Vec<u8>> {
        Ok(opt_result!(util::decode_base64_url_no_pad(&self.e_pub_key), "Invalid envelop e_pub_key: {}"))
    }
}

impl WrapKey {
    pub fn encode(&self) -> XResult<String> {
        let mut buf = String::with_capacity(512);
        buf.push_str("WK:");
        let header = serde_json::to_string(&self.header)?;
        let header_str = util::encode_base64_url_no_pad(header.as_bytes());
        buf.push_str(&header_str);
        buf.push('.');
        buf.push_str(&util::encode_base64_url_no_pad(&self.nonce));
        buf.push('.');
        buf.push_str(&util::encode_base64_url_no_pad(&self.encrypted_data));
        Ok(buf)
    }

    pub fn parse(wk: &str) -> XResult<WrapKey> {
        if !wk.starts_with("WK:") {
            return simple_error!("Wrap key string must starts with WK:");
        }
        let wks = wk.split('.').collect::<Vec<_>>();
        if wks.len() != 3 {
            return simple_error!("Invalid wrap key.");
        }
        let header = wks[0].chars().skip(3).collect::<String>();
        let header_bytes = opt_result!(util::decode_base64_url_no_pad(&header), "Invalid wrap key header: {}");
        let nonce = wks[1];
        let encrypted_data = wks[2];
        let header_str = opt_result!(String::from_utf8(header_bytes), "Invalid wrap key header: {}");
        let header: WrapKeyHeader = opt_result!(serde_json::from_str(&header_str), "Invalid wrap key header: {}");
        let nonce = opt_result!(util::decode_base64_url_no_pad(nonce), "Invalid wrap key: {}");
        let encrypted_data = opt_result!(util::decode_base64_url_no_pad(encrypted_data), "Invalid wrap key: {}");
        Ok(WrapKey {
            header,
            nonce,
            encrypted_data,
        })
    }
}

#[test]
fn test_parse_wrap_key() {
    let wk = "WK:eyJlUHViS2V5IjoiTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFcExLeXBzU2hKdl\
    ZSeC0xaGZaRjJwOWN6SUZwanBfRExJTE1GOVo4VTlZcUZEVFpNZE5CQ3R5NFJsWG1JaEhaSUxVT1pMWW90bjR0QmF6WndnVk\
    c3alEiLCJlbmMiOiJhZXMyNTYtZ2NtLXAyNTYifQ.bil863KUslf7nzHs.VR24eaonTSZnHs8hWp4QP-5RjFcZH3i7V79DiZ\
    dHuCnxyywfw4daWuJzYgouxCBE";

    let wrap_key = WrapKey::parse(wk).unwrap();
    assert_eq!("aes256-gcm-p256", wrap_key.header.enc);
    assert_eq!("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpLKypsShJvVRx-1hfZF2p9czIFpjp_DLILMF9Z8U9YqFDTZMd\
    NBCty4RlXmIhHZILUOZLYotn4tBazZwgVG7jQ", wrap_key.header.e_pub_key);
    assert_eq!("6e297ceb7294b257fb9f31ec", hex::encode(&wrap_key.nonce));
    assert_eq!("551db879aa274d26671ecf215a9e103fee518c57191f78bb57bf43899747b829f1cb2c1fc3875a5ae273\
    620a2ec42044", hex::encode(&wrap_key.encrypted_data));

    let encoded = wrap_key.encode().unwrap();
    let reparsed_wrap_key = WrapKey::parse(&encoded).unwrap();
    assert_eq!("aes256-gcm-p256", reparsed_wrap_key.header.enc);
    assert_eq!("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpLKypsShJvVRx-1hfZF2p9czIFpjp_DLILMF9Z8U9YqFDTZMd\
    NBCty4RlXmIhHZILUOZLYotn4tBazZwgVG7jQ", reparsed_wrap_key.header.e_pub_key);
    assert_eq!("6e297ceb7294b257fb9f31ec", hex::encode(&reparsed_wrap_key.nonce));
    assert_eq!("551db879aa274d26671ecf215a9e103fee518c57191f78bb57bf43899747b829f1cb2c1fc3875a5ae273\
    620a2ec42044", hex::encode(&reparsed_wrap_key.encrypted_data));
}