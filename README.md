# tiny-encrypt-rs

Tiny encrypt for Rust

> Tiny encrypt rs is a Rust implementation of Tiny encrypt java https://git.hatter.ink/hatter/tiny-encrypt-java
> Tiny encrypt spec see: https://github.com/OpenWebStandard/tiny-encrypt-format-spec

Repository address: https://git.hatter.ink/hatter/tiny-encrypt-rs mirror https://github.com/jht5945/tiny-encrypt-rs

TODOs:

* Encrypt subcommand

<br>

Encrypt config `~/.tinyencrypt/config-rs.json`:

```json
{
  "envelops": [
    {
      "type": "pgp",
      "kid": "KID-1",
      "desc": "this is key 001",
      "publicPart": "----- BEGIN OPENPGP ..."
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
    "leve2": [
      "KID-2"
    ]
  }
}
```
