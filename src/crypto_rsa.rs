use rsa::{BigUint, RsaPublicKey};
use rust_util::{opt_result, XResult};
use x509_parser::prelude::FromDer;
use x509_parser::public_key::RSAPublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::util;

/// Parse RSA Subject Public Key Info(SPKI) to Rsa Public Key
pub fn parse_spki(pem: &str) -> XResult<RsaPublicKey> {
    let der = util::parse_pem(pem)?;
    let spki = opt_result!(SubjectPublicKeyInfo::from_der(&der), "Parse SKPI failed: {}").1;
    let public_key_der = spki.subject_public_key.data;
    let public_key = opt_result!(RSAPublicKey::from_der(&public_key_der), "Parse RSA public key failed: {}").1;
    let rsa_public_key = opt_result!(RsaPublicKey::new(
        BigUint::from_bytes_be(public_key.modulus),
        BigUint::from_bytes_be(public_key.exponent),
    ), "Parse RSA public key failed: {}");
    Ok(rsa_public_key)
}

#[test]
fn test_parse_spki() {
    use rsa::traits::PublicKeyParts;
    let public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgK\
    CAgEApUM8M+QRMUw0dIvXISFx\n43j4h9CK38Y9HD6kPcc3Z0dCGPiFy7Ze0OQebPWHyUZ2YmqsdyzFuOQuV9P2pxxj\n/W\
    LIgRqZV8Jk8tWhtAjOOvm0MTc2rg+EJHfa+zhX4eFEMsj4DvQBMJDXiKnpXTM/\nj7oMKpIUQHqfXBwsEJHLmHZTLeEBEYK\
    cZXTAmuu3WdxK5jvEc02Xt2hZ1fBs0M9e\n/2EMe3t69aH4/rabiBjF2h9Jde15wrJMxXaCCWJqYhbBS0CJ3BdjkAqOIpcq\
    PXva\nxiJN1pNpK8ejA9Q4Nmx7pxnvfv+hCPkWXZS3r/BWZ9lFZc8uErQEbB4gLgko8jOl\nfQF7cYqtZEs69qY8nnIUBsq\
    ZYfAp+bQd2xCFSbEZAl+OrtGzfVjD9YFMPy02+xRg\nv2N3KT3KHHvuU7WxrvffrshP2fwDuG2MBlmcq1suAKxA0cYPSyaj\
    ceEqw/3ogSp7\n7SYx41rT8EWLmTvU0CHzCsuf/O7sDWZRfxatAzWhBBhnKCPqzizpOQOqm8XhCt74\nFfnabPpHM9XUjoQ\
    IPrTssyS3eWqynzJiAqez6v2LK2fhL7IkcLtvt5p59Y+KY4I6\nYQ09iUh7lKJHRhkgTomUurJHieVHMWFGIHofEC+nU6pG\
    IUh0P7Nr0Gz45GJTwWGd\nhW53WfImja+b5kwwyqUikyMCAwEAAQ==\n-----END PUBLIC KEY-----";
    let public_key = parse_spki(public_key_pem).unwrap();

    assert_eq!("a5433c33e411314c34748bd7212171e378f887d08adfc63d1c3ea43dc73767474218f885cbb65ed0e41\
    e6cf587c94676626aac772cc5b8e42e57d3f6a71c63fd62c8811a9957c264f2d5a1b408ce3af9b4313736ae0f842477\
    dafb3857e1e14432c8f80ef4013090d788a9e95d333f8fba0c2a9214407a9f5c1c2c1091cb9876532de10111829c657\
    4c09aebb759dc4ae63bc4734d97b76859d5f06cd0cf5eff610c7b7b7af5a1f8feb69b8818c5da1f4975ed79c2b24cc5\
    768209626a6216c14b4089dc1763900a8e22972a3d7bdac6224dd693692bc7a303d438366c7ba719ef7effa108f9165\
    d94b7aff05667d94565cf2e12b4046c1e202e0928f233a57d017b718aad644b3af6a63c9e721406ca9961f029f9b41d\
    db108549b119025f8eaed1b37d58c3f5814c3f2d36fb1460bf6377293dca1c7bee53b5b1aef7dfaec84fd9fc03b86d8\
    c06599cab5b2e00ac40d1c60f4b26a371e12ac3fde8812a7bed2631e35ad3f0458b993bd4d021f30acb9ffceeec0d66\
    517f16ad0335a10418672823eace2ce93903aa9bc5e10adef815f9da6cfa4733d5d48e84083eb4ecb324b7796ab29f3\
    26202a7b3eafd8b2b67e12fb22470bb6fb79a79f58f8a63823a610d3d89487b94a2474619204e8994bab24789e54731\
    6146207a1f102fa753aa462148743fb36bd06cf8e46253c1619d856e7759f2268daf9be64c30caa5229323",
               public_key.n().to_str_radix(16));
    assert_eq!("10001", public_key.e().to_str_radix(16));
}

#[test]
fn test_parse_spki_and_test() {
    use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
    use rsa::pkcs1::der::Decode;
    use rsa::pkcs8::PrivateKeyInfo;
    let private_key_pem = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCsuTaS34xvrgr5
ZXEuE8lYDYuLxATq1ds6/8YlNOeKReCGwRkObfKl0uyj79WLka2RCZELDiHyQcDG
OMJZLnLhU/PmQXkp7UR+a8HrRWBa2kiuGoF/IpBHlFM7bFLqYlcPe1lFDlYlYLN0
fhkxmB9jKJBvsnkXi2fNypi0/kbJM5GANlfvUG30SV9flNjKSKAs6UIVN9vJrzpC
pDMw0lcXRZa1F0kj8gFX4AdUvoiQog2QYlX1cpkznYz2G4F8K5GwUfsgEUUTqqLC
d/lfnI2poKhCy5G2ejAYrOttV2Ke6R3XCPQuQG7Pag0wHeqxfKrtC07GIVO4qQw6
hA1SIIQpAgMBAAECggEAH7SH3gIHB2ENRqZmVizvoqgp22gJ9wl2iqf0uVOyxOD6
zAGaFdn81o+XPKiDrHD7SUpWQ48+j/ed6UT19+Tc1ZvRg4y1LwsMraAeIo/DlinH
eZ4H80xm65zAgoHp3nhavs7HnjN5gLb1egbDnSTtbgg+KyK5s6a1UUNFMMQUPk5Z
wdjOwJwPG6AYBqbHXsaCJHy4RBY3dI4RCM1d5QsFgmDvGoaIuFSrD2iCdnUlxbvj
62QvWuaW22hhIRZm6GQxHE0OqBbkzgJn/g8q8I57IzonET+k5wYzI8jRNRyHKR4z
fB71rYaeW36qHx/NjY2zLeEmva85r01F8/gcfIv9+QKBgQDZ0l78S4Q10S5j5IVI
tZsPjjfV2SlVKCzwspnYSPLyrgM0Fyg4F62Qm0J9Rm3mKSFNarCdcd7HcUqTRgUI
AjsG9rdTBISeUU6t98UcllfWtS0Q4u4y+Wa9nijnNiF3AirqgHWv+iPOX3fvgsC6
wfkpCNMW8BTopaCwRnTWvCrhWwKBgQDK/0ohWDxqBkQ7DMUf29zUcJT5/FVw6KMn
EgLOnk8Z5qHmxy610qddB52gjLot0B+M4J3fLZtbkbyOUdOnrg1zbx6+TLdSAKRE
HT2sOxY+0D9y3tlziUyaJSQFnyX/PXbQa9iPDoZZURFdAulorqAMu2WzqzDn5HOK
s13P9X9DywKBgQCjviMtYc9nbXKEIVuYhvyjuvN6TJ9npqXx4zEHh/8qM2mxFN9l
G1ecZzqaVgFzjeO9AMD3+ovQPfgjsfVCSfr5hynUvIa9RL3yxVll3hb2DohsM0uB
Aj8bt/NjrCuH/Rcp5ZuSyGV2VAojAJXFTt/w2vNkQOJW6XtcR/q5GgbaFQKBgQCW
PQsoUp2j+q9U5MagJaDyucAIpHC39/WIXRQmx5PTn5YDrzcq6pVjjNdkk8LXVUmE
gllVa/Oned0LmBQF7hOWc49VWIH09vScVOfoKHL2WjobUkOt9tfy3bojTv5YQa1F
5AuLFTzprc4kAJuvFk7uHWPP7ctsVPAOn2G3IALosQKBgHzBvorOX4CeUn38mz3E
OjiPbL8hCS1DYx1ZteOds1JWwrA9ja745TPT4eMtuqduvQpz93HcjXly09KPN+i2
Ogl/tEm7GQh6C9uXm3XbEnFGO/y9JQcef3eWWJTy4+mwKpq37SyWht65UYjE7adb
WrYun0ReUIgfONrtJaCxpgf/
-----END PRIVATE KEY-----";
    let public_key_pem = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArLk2kt+Mb64K+WVxLhPJ
WA2Li8QE6tXbOv/GJTTnikXghsEZDm3ypdLso+/Vi5GtkQmRCw4h8kHAxjjCWS5y
4VPz5kF5Ke1EfmvB60VgWtpIrhqBfyKQR5RTO2xS6mJXD3tZRQ5WJWCzdH4ZMZgf
YyiQb7J5F4tnzcqYtP5GyTORgDZX71Bt9ElfX5TYykigLOlCFTfbya86QqQzMNJX
F0WWtRdJI/IBV+AHVL6IkKINkGJV9XKZM52M9huBfCuRsFH7IBFFE6qiwnf5X5yN
qaCoQsuRtnowGKzrbVdinukd1wj0LkBuz2oNMB3qsXyq7QtOxiFTuKkMOoQNUiCE
KQIDAQAB
-----END PUBLIC KEY-----";
    let public_key = parse_spki(public_key_pem).unwrap();
    let private_key_der = util::parse_pem(&private_key_pem).unwrap();
    let private_key_info = PrivateKeyInfo::from_der(&private_key_der).unwrap();
    let private_key = RsaPrivateKey::try_from(private_key_info).unwrap();
    let mut rng = rand::thread_rng();
    let data = b"hello world";
    let enc_data = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).unwrap();
    let decrypted_data = private_key.decrypt(Pkcs1v15Encrypt, &enc_data).unwrap();
    assert_eq!(&data[..], &decrypted_data[..]);
}