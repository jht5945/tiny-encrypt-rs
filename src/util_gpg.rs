// Command encrypt use GnuPG(GPG)
/*
echo message | gpg -r KEY_ID -e -a --no-comment --comment "tiny-encrypt-1.6.0 - KEY_ID"

Success message:
-----BEGIN PGP MESSAGE-----
Comment: tiny-encrypt-1.6.0 - C0FAD5E563B80E819603B0D9FFC2A910806894FD

hF4DcCBclRkzzAMSAQdA6nLd40IPxZF62Q54t2bpwvFXsG0Wy6SYxGEp1/K6rWgw
jgSx2ZiCntadkFrH35MJAYOx/DVW6ngxIic8hO+liBZfqI1lv7vlvVfs4sAe1bqK
0kcBDqp5SGNx2ENiDA4IbqDAp7JppQpEZrWJd2FGdbKviRyprVYgGILGJcMZQVNJ
agJfGGj7HPf5IbffrWWWyfE7oNCkSDZ2bw==
=tANz
-----END PGP MESSAGE-----

Failed message:
gpg: C0FAD5E563B80E819603B0D9FFC2A910806894FF: skipped: No public key
gpg: [stdin]: encryption failed: No public key
*/

// Command decrypt use GnuPG(GPG)
/*
echo '-----BEGIN PGP MESSAGE-----
Comment: tiny-encrypt-1.6.0

hF4DcCBclRkzzAMSAQdAESdgetyKsgdAR6kps5ThpP2TcZB0hyGrmDqGj/1+lXIw
c9cam+BxFkDT7mZafuls0tV4MwHwKi2z1gQFNgTWuC45rpXyK7BFg74Rua+qLzvJ
0kcBpKSZIvQ/lX8JQ4hM41k6ymeYBQMC2nzmhwl/g9NBFyn5+dlEzDiZvL8YyQFT
IDGbLcEBW7a0B02ZKZ4ELyIDp94hdcbhrg==
=QEBj
-----END PGP MESSAGE-----' | gpg -d

Failed message:
gpg: encrypted with 256-bit ECDH key, ID 70205C951933CC03, created 2023-10-05
      "Hatter Jiang (2023) <jht5945@gmail.com>"
gpg: public key decryption failed: Operation cancelled
gpg: decryption failed: No secret key
 */

use std::io::Write;
use std::process::{Command, Stdio};

use rust_util::{opt_result, opt_value_result, simple_error, XResult};

use crate::util_env;

pub fn gpg_encrypt(key_id: &str, message: &[u8]) -> XResult<String> {
    let message_hex = hex::encode(message);

    let mut cmd = Command::new(get_gpg_cmd());
    let gpg_encrypt_result = cmd
        .args([
            "-e", "-a", "--no-comment",
            "-r", key_id,
            "--comment", &format!("tiny-encrypt-v{} - {}", env!("CARGO_PKG_VERSION"), key_id)
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let gpg_encrypt = opt_result!(gpg_encrypt_result, "Run GPG encrypt failed: {}");
    let mut gpg_encrypt_stdin = opt_value_result!(gpg_encrypt.stdin.as_ref(), "Get GPG encrypt stdin failed.");
    opt_result!(gpg_encrypt_stdin.write_all(message_hex.as_bytes()), "Write GPG encrypt stdin failed: {}");
    let encrypt_result = gpg_encrypt.wait_with_output();

    let encrypt_output = opt_result!(encrypt_result, "GPG encrypt failed: {}");
    let stdout = String::from_utf8_lossy(&encrypt_output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&encrypt_output.stderr).to_string();
    if !encrypt_output.status.success() {
        return simple_error!(
            "GPG encrypt failed: {:?}\n- stdout: {}\n- stderr: {}",
            encrypt_output.status.code(), stdout, stderr
        );
    }
    Ok(stdout)
}

pub fn gpg_decrypt(message: &str) -> XResult<Vec<u8>> {
    let mut cmd = Command::new(get_gpg_cmd());
    let gpg_decrypt_result = cmd
        .arg("-d")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let gpg_encrypt = opt_result!(gpg_decrypt_result, "Run GPG decrypt failed: {}");
    let mut gpg_encrypt_stdin = opt_value_result!(gpg_encrypt.stdin.as_ref(), "Get GPG decrypt stdin failed.");
    opt_result!(gpg_encrypt_stdin.write_all(message.as_bytes()), "Write GPG decrypt stdin failed: {}");
    let decrypt_result = gpg_encrypt.wait_with_output();

    let decrypt_output = opt_result!(decrypt_result, "GPG decrypt failed: {}");
    let stdout = String::from_utf8_lossy(&decrypt_output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&decrypt_output.stderr).to_string();
    if !decrypt_output.status.success() {
        return simple_error!(
            "GPG decrypt failed: {:?}\n- stdout: {}\n- stderr: {}",
            decrypt_output.status.code(), stdout, stderr
        );
    }
    let decrypted = opt_result!(hex::decode(stdout.trim()), "Decode decrypted message failed: {}");
    Ok(decrypted)
}

fn get_gpg_cmd() -> String {
    util_env::get_gpg_cmd().unwrap_or("gpg".to_string())
}
