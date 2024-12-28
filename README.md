# tiny-encrypt-rs

> [!IMPORTANT]  
> To use tiny-encrypt, a Yubikey(https://www.yubico.com/products/) or MacBook with Secure Enclave get the
best security effect, the key MUST support PIV or OpenPGP.


![](https://cdn.hatter.ink/doc/7684_4DB4452911E2A25AB993429AA7FFCD65/yubikey-5-family.png)

Tiny Encrypt written in Rust Programming Language

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

Install from git:

```shell
cargo install --git https://git.hatter.ink/hatter/tiny-encrypt-rs.git --features full-features
```

Edit encrypted file:

```shell
tiny-encrypt decrypt --edit-file sample.txt.tinyenc 
```

Read environment `EDITOR` or `SECURE_EDITOR` to edit file, `SECURE_EDITOR` write encrypted file to temp file.

Secure editor command format:

```shell
$SECURE_EDITOR <temp-file-name> "aes-256-gcm" <temp-key-hex> <temp-nonce-hex>
```

<br>

Encrypt config `~/.tinyencrypt/config-rs.json`:

```json
{
  "environment": {
    "TINY_ENCRYPT_DEFAULT_ALGORITHM": "AES or CHACHA20"
  },
  "namespaces": {
    "name": "/Users/example/.name"
  },
  "envelops": [
    {
      "type": "pgp-rsa",
      "kid": "KID-1",
      "desc": "this is key 001",
      "publicPart": "----- BEGIN PUBLIC KEY ..."
    },
    {
      "type": "piv-p256",
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

<br>

Kyber1024 usage:
Generate `static-kyber1024` keypair:

```shell
$ tiny-encrypt -K -a kyber1024 -n keyname
[OK   ] Keychain name: keyname
[OK   ] Public key   : a731b5032194c3d2ad01f36d64e859ca9738595c21aa19c852dac22f4...
[INFO ] Config envelop:
{
  "type": "static-kyber1024",
  "sid": "keyname",
  "kid": "keychain:a731b5032194c3d2ad01f36d64e859ca9738595c21aa19c852dac22f411036c7",
  "desc": "Keychain static",
  "args": [
    "keychain::tiny-encrypt:keyname"
  ],
  "publicPart": "a731b5032194c3d2ad01f36d64e859ca9738595c21aa19c852dac22f411036c..."
}
```

Then write file `~/.tinyencrypt/config-rs.json`.

Last, config key id to profile.

Supported PKI encryption types:

| Type             | Algorithm       | Description                             |
|------------------|-----------------|-----------------------------------------|
| pgp-rsa          | PKCS1-v1.5      | OpenPGP Encryption Key (Previous `pgp`) |
| pgp-x25519       | ECDH(X25519)    | OpenPGP Encryption Key                  |
| gpg              | OpenPGP         | GnuPG Command                           |
| static-x25519    | ECDH(X25519)    | Key Stored in macOS Keychain Access     |
| static-kyber1024 | Kyber1024       | Key Stored in macOS Keychain Access     |
| piv-p256         | ECDH(secp256r1) | PIV Slot (Previous `ecdh`)              |
| piv-p384         | ECDH(secp384r1) | PIV Slot (Previous `ecdh-p384`)         |
| key-p256         | ECDH(secp256r1) | Key Stored in macOS Secure Enclave      |
| piv-rsa          | PKCS1-v1.5      | PIV Slot                                |

Smart Card(Yubikey) protected ECDH Encryption description as below:

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

Environment

| KEY                              | Comment                                     |
|----------------------------------|---------------------------------------------|
| TINY_ENCRYPT_DEFAULT_ALGORITHM   | Encryption algorithm, `aes` or `chacha20`   |
| TINY_ENCRYPT_DEFAULT_COMPRESS    | File compress, `1` or `on`, default `false` |
| TINY_ENCRYPT_NO_PROGRESS         | Do not display progress bar                 |
| TINY_ENCRYPT_NO_DEFAULT_PIN_HINT | Do not display default PIN hint             |
| TINY_ENCRYPT_USE_DIALOGUER       | Use dialoguer                               |
| TINY_ENCRYPT_PIN                 | PIV Card PIN                                |
| TINY_ENCRYPT_KEY_ID              | Default Key ID                              |
| TINY_ENCRYPT_AUTO_SELECT_KEY_IDS | Auto select Key IDs                         |
| TINY_ENCRYPT_AUTO_COMPRESS_EXTS  | Auto compress file exts                     |
| TINY_ENCRYPT_PIN_ENTRY           | PIN entry command cli                       |
| SECURE_EDITOR                    | Secure Editor                               |
| EDITOR                           | Editor (Plaintext)                          |


