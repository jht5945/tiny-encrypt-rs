use std::fs;
use std::path::PathBuf;

use clap::Args;
use p256::{PublicKey, EncodedPoint};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand::random;
use rand::rngs::OsRng;
use rsa::Pkcs1v15Encrypt;
use rust_util::{debugging, failure, opt_result, simple_error, success, XResult};

use crate::config::{TinyEncryptConfig, TinyEncryptConfigEnvelop};
use crate::crypto_rsa::parse_spki;
use crate::spec::{EncMetadata, TinyEncryptEnvelop, TinyEncryptEnvelopType, TinyEncryptMeta};
use crate::util::{encode_base64, TINY_ENC_CONFIG_FILE};

#[derive(Debug, Args)]
pub struct CmdEncrypt {
    /// Files need to be decrypted
    pub paths: Vec<PathBuf>,
    // Comment
    pub comment: Option<String>,
    // Comment
    pub encrypted_comment: Option<String>,
    // Encryption profile
    pub profile: Option<String>,
}

pub fn encrypt(cmd_encrypt: CmdEncrypt) -> XResult<()> {
    let config = TinyEncryptConfig::load(TINY_ENC_CONFIG_FILE)?;
    let envelops = config.find_envelops(&cmd_encrypt.profile);
    if envelops.is_empty() { return simple_error!("Cannot find any valid envelops"); }

    debugging!("Cmd encrypt: {:?}", cmd_encrypt);
    for path in &cmd_encrypt.paths {
        match encrypt_single(path, &envelops) {
            Ok(_) => success!("Encrypt {} succeed", path.to_str().unwrap_or("N/A")),
            Err(e) => failure!("Encrypt {} failed: {}", path.to_str().unwrap_or("N/A"), e),
        }
    }
    Ok(())
}

fn encrypt_single(path: &PathBuf, envelops: &[&TinyEncryptConfigEnvelop]) -> XResult<()> {
    let (key, nonce) = make_key256_and_nonce();
    let envelops = encrypt_envelops(&key, &envelops)?;

    let file_metadata = opt_result!(fs::metadata(path), "Read file: {} meta failed: {}", path.display());
    let enc_metadata = EncMetadata {
        comment: None,
        encrypted_comment: None,
        encrypted_meta: None,
        compress: false,
    };

    let _encrypt_meta = TinyEncryptMeta::new(&file_metadata, &enc_metadata, &nonce, envelops);

    // TODO write to file and do encrypt
    Ok(())
}

fn encrypt_envelops(key: &[u8], envelops: &[&TinyEncryptConfigEnvelop]) -> XResult<Vec<TinyEncryptEnvelop>> {
    let mut encrypted_envelops = vec![];
    for envelop in envelops {
        match envelop.r#type {
            TinyEncryptEnvelopType::Pgp => {
                encrypted_envelops.push(encrypt_envelop_pgp(key, envelop)?);
            }
            TinyEncryptEnvelopType::Ecdh => {
                encrypted_envelops.push(encrypt_envelop_ecdh(key, envelop)?);
            }
            _ => return simple_error!("Not supported type: {:?}", envelop.r#type),
        }
    }
    Ok(encrypted_envelops)
}

fn encrypt_envelop_ecdh(key: &[u8], envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let public_key_point_hex = &envelop.public_part;
    let public_key_point_bytes = opt_result!(hex::decode(public_key_point_hex), "Parse public key point hex failed: {}");
    let encoded_point = opt_result!(EncodedPoint::from_bytes(&public_key_point_bytes), "Parse public key point failed: {}");
    let public_key = PublicKey::from_encoded_point(&encoded_point).unwrap();

    let esk = EphemeralSecret::random(&mut OsRng);
    let epk = esk.public_key();
    let epk_bytes = EphemeralKeyBytes::from_public_key(&epk);
    let public_key_encoded_point = public_key.to_encoded_point(false);
    let shared_secret = esk.diffie_hellman(&public_key);

    // PORT Java Implementation
    //    public static WrapKey encryptEcdhP256(String kid, PublicKey publicKey, byte[] data) {
    //         AssertUtil.isTrue(publicKey instanceof ECPublicKey, "Public key must be EC public key");
    //         if (data == null || data.length == 0) {
    //             return null;
    //         }
    //         final Tuple2<PublicKey, byte[]> ecdh = ECUtil.ecdh(ECUtil.CURVE_SECP256R1, publicKey);
    //         final byte[] ePublicKeyBytes = ecdh.getVal1().getEncoded();
    //         final byte[] key = KdfUtil.simpleKdf256(ecdh.getVal2());
    //
    //         final byte[] nonce = RandomTool.secureRandom().nextbytes(AESCryptTool.GCM_NONCE_LENGTH);
    //         final byte[] encryptedData = AESCryptTool.gcmEncrypt(key, nonce).from(Bytes.from(data)).toBytes().bytes();
    //         final WrapKey wrapKey = new WrapKey();
    //         final WrapKeyHeader wrapKeyHeader = new WrapKeyHeader();
    //         wrapKeyHeader.setKid(kid);
    //         wrapKeyHeader.setEnc(ENC_AES256_GCM_P256);
    //         wrapKeyHeader.setePubKey(Base64s.uriCompatible().encode(ePublicKeyBytes));
    //         wrapKey.setHeader(wrapKeyHeader);
    //         wrapKey.setNonce(nonce);
    //         wrapKey.setEncrytpedData(encryptedData);
    //         return wrapKey;
    //     }

    Ok(TinyEncryptEnvelop {
        r#type: envelop.r#type,
        kid: envelop.kid.clone(),
        desc: envelop.desc.clone(),
        encrypted_key: "".to_string(), // TODO ...
    })
}


fn encrypt_envelop_pgp(key: &[u8], envelop: &TinyEncryptConfigEnvelop) -> XResult<TinyEncryptEnvelop> {
    let pgp_public_key = opt_result!(parse_spki(&envelop.public_part), "Parse PGP public key failed: {}");
    let mut rng = rand::thread_rng();
    let encrypted_key = opt_result!(pgp_public_key.encrypt(&mut rng, Pkcs1v15Encrypt, key), "PGP public key encrypt failed: {}");
    Ok(TinyEncryptEnvelop {
        r#type: envelop.r#type,
        kid: envelop.kid.clone(),
        desc: envelop.desc.clone(),
        encrypted_key: encode_base64(&encrypted_key),
    })
}

fn make_key256_and_nonce() -> (Vec<u8>, Vec<u8>) {
    let key: [u8; 32] = random();
    let nonce: [u8; 12] = random();
    (key.into(), nonce.into())
}

#[derive(Debug)]
pub struct EphemeralKeyBytes(EncodedPoint);

impl EphemeralKeyBytes {
    fn from_public_key(epk: &PublicKey) -> Self {
        EphemeralKeyBytes(epk.to_encoded_point(true))
    }

    fn decompress(&self) -> EncodedPoint {
        // EphemeralKeyBytes is a valid compressed encoding by construction.
        let p = PublicKey::from_encoded_point(&self.0).unwrap();
        p.to_encoded_point(false)
    }
}
