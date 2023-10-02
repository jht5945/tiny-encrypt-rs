# Tiny-Encrypt-rs Usage

## 1. Install

### 1.1 Install Rust

Install Rust from Official site (https://rustup.rs/):

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Or, Install from Chinese mirror site (https://rsproxy.cn/):

```shell
export RUSTUP_DIST_SERVER="https://rsproxy.cn"
export RUSTUP_UPDATE_ROOT="https://rsproxy.cn/rustup"

curl --proto '=https' --tlsv1.2 -sSf https://rsproxy.cn/rustup-init.sh | sh
```

### 1.2 Install tiny-encrypt-rs

Install from Cargo:

```shell
cargo install tiny-encrypt
```

Or, Install from source code:

```shell
git clone https://git.hatter.ink/hatter/tiny-encrypt-rs.git
cd tiny-encrypt-rs
cargo install --path .
```

> You also can clone from GitHub mirror: https://github.com/jht5945/tiny-encrypt-rs

## 2 Get help

```shell
$ tiny-encrypt --help
A tiny encrypt client in Rust

Usage: tiny-encrypt <COMMAND>

Commands:
  encrypt, -e  Encrypt file(s)
  decrypt, -d  Decrypt file(s)
  info, -I     Show file info
  help         Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Or, get help for encrypt:

```shell
$ tiny-encrypt -e --help
Encrypt file(s)

Usage: tiny-encrypt {encrypt|-e} [OPTIONS] [PATHS]...

Arguments:
  [PATHS]...  Files need to be decrypted

Options:
  -c, --comment <COMMENT>
          Comment
  -C, --encrypted-comment <ENCRYPTED_COMMENT>
          Encrypted comment
  -p, --profile <PROFILE>
          Encryption profile
  -x, --compress
          Compress before encrypt
  -L, --compress-level <COMPRESS_LEVEL>
          Compress level (from 0[none], 1[fast] .. 6[default] .. to 9[best])
  -1, --compatible-with-1-0
          Compatible with 1.0
  -R, --remove-file
          Remove source file
  -h, --help
          Print help
```

## 3 Edit config-rs.json

tiny-encrypt-rs's config file is located at `~/.tinyencrypt/config-rs.json`

A sample config is like this:

```json
{
  "envelops": [
    {
      "type": "pgp",
      "kid": "6FAFC0E0170985AA71545483C794B1646A886CD6",
      "desc": "Card serial no. = 0006 04139321",
      "publicPart": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApUM8M+QRMUw0dIvXISFx\n43j4h9CK38Y9HD6kPcc3Z0dCGPiFy7Ze0OQebPWHyUZ2YmqsdyzFuOQuV9P2pxxj\n/WLIgRqZV8Jk8tWhtAjOOvm0MTc2rg+EJHfa+zhX4eFEMsj4DvQBMJDXiKnpXTM/\nj7oMKpIUQHqfXBwsEJHLmHZTLeEBEYKcZXTAmuu3WdxK5jvEc02Xt2hZ1fBs0M9e\n/2EMe3t69aH4/rabiBjF2h9Jde15wrJMxXaCCWJqYhbBS0CJ3BdjkAqOIpcqPXva\nxiJN1pNpK8ejA9Q4Nmx7pxnvfv+hCPkWXZS3r/BWZ9lFZc8uErQEbB4gLgko8jOl\nfQF7cYqtZEs69qY8nnIUBsqZYfAp+bQd2xCFSbEZAl+OrtGzfVjD9YFMPy02+xRg\nv2N3KT3KHHvuU7WxrvffrshP2fwDuG2MBlmcq1suAKxA0cYPSyajceEqw/3ogSp7\n7SYx41rT8EWLmTvU0CHzCsuf/O7sDWZRfxatAzWhBBhnKCPqzizpOQOqm8XhCt74\nFfnabPpHM9XUjoQIPrTssyS3eWqynzJiAqez6v2LK2fhL7IkcLtvt5p59Y+KY4I6\nYQ09iUh7lKJHRhkgTomUurJHieVHMWFGIHofEC+nU6pGIUh0P7Nr0Gz45GJTwWGd\nhW53WfImja+b5kwwyqUikyMCAwEAAQ==\n-----END PUBLIC KEY-----"
    },
    {
      "type": "ecdh",
      "kid": "02dd3eebd906c9cf00b08ec29f7ed61804d1cc1d1352d9257b628191e08fc3717c",
      "desc": "PIV --slot 82",
      "publicPart": "04dd3eebd906c9cf00b08ec29f7ed61804d1cc1d1352d9257b628191e08fc3717c4fae3298cd5c4829cec8bf3a946e7db60b7857e1287f6a0bae6b3f2342f007d0"
    }
  ],
  "profiles": {
    "default": [
      "6FAFC0E0170985AA71545483C794B1646A886CD6",
      "02dd3eebd906c9cf00b08ec29f7ed61804d1cc1d1352d9257b628191e08fc3717c"
    ],
    "dh": [
      "02dd3eebd906c9cf00b08ec29f7ed61804d1cc1d1352d9257b628191e08fc3717c"
    ]
  }
}
```

## 4 Encrypt/Decrypt file(s)

### 4.1 Encrypt file(s)

```shell
tiny-encrypt -e [-p Profile] [-x] [-L 6] [-1] [-R] [-c Comment] [-C EncryptedComment] FILENAMES
```

### 4.2 Decrypt file(s)

```shell
tiny-encrypt -d [-p PIN] [-s Slot] [-R] FILENAMES
```



