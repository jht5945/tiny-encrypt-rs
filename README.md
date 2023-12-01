# tiny-encrypt-rs

**IMPORTANT**: To use tiny-encrypt, a Yubikey(https://www.yubico.com/products/) is
required, the key MUST support PIV or OpenPGP.

![](https://cdn.hatter.ink/doc/7684_4DB4452911E2A25AB993429AA7FFCD65/yubikey-5-family.png)

Tiny encrypt for Rust

Specification: [Tiny Encrypt Spec V1.1](https://github.com/OpenWebStandard/tiny-encrypt-format-spec/blob/main/TinyEncryptSpecv1.1.md)

> Tiny encrypt rs is a Rust implementation of Tiny encrypt java https://git.hatter.ink/hatter/tiny-encrypt-java <br>
> Tiny encrypt spec see: https://github.com/OpenWebStandard/tiny-encrypt-format-spec

Repository address: https://git.hatter.ink/hatter/tiny-encrypt-rs mirror https://github.com/jht5945/tiny-encrypt-rs

Set default encryption algorithm:
```shell
export TINY_ENCRYPT_DEFAULT_ALGORITHM='AES' # or CHACHA20
```

Compile only encrypt:
```shell
cargo build --release --no-default-features
```

<br>

Encrypt config `~/.tinyencrypt/config-rs.json`:

```json
{
  "envelops": [
    {
      "type": "pgp",
      "kid": "KID-1",
      "desc": "this is key 001",
      "publicPart": "----- BEGIN PUBLIC KEY ..."
    },
    {
      "type": "ecdh",
      "kid": "KID-2",
      "desc": "this is key 002",
      "publicPart": "04..."
    }
  ],
  "profiles": {
    "default": [
      "KID-1",
      "KID-2"
    ],
    "l2,leve2": [
      "KID-2"
    ]
  }
}
```

Supported PKI encryption types:

| Type       | Algorithm       | Description            |
|------------|-----------------|------------------------|
| pgp        | PKCS1-v1.5      | OpenPGP Encryption Key |
| pgp-x25519 | ECDH(X25519)    | OpenPGP Encryption Key |
| ecdh       | ECDH(secp256r1) | PIV Slot               |
| ecdh-p384  | ECDH(secp384r1) | PIV Slot               |

Smart Card(Yubikey) protected ECDH Encryption description:

```text
┌───────────────────┐                     ┌───────────────────────────┐
│Tiny Encrypt       │                     │Smart Card (Yubikey)       │
│                   │  Get Public Key(P)  │                           │
│                   │ ◄───────────────────┤ Private Key(d)            │
│                   │                     │ P = dG                    │
│                   │ Temp Private Key(k) │                           │
└───────────────────┘ Q = kG              └───────────────────────────┘

                      Shared Secret = kP = kdG

                      Store Q, Encrypt using derived key from Shared Secret


                      Send Q to Smart Card
                      ───────────────────►
                                          Shared Secret = dQ = kdG

                               Decrypt using derived key from restored Shared Secret
```

