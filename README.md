# tiny-encrypt-rs

Tiny encrypt for Rust

> Tiny encrypt spec see: https://git.hatter.ink/hatter/tiny-encrypt-java

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
