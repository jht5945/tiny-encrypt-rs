use std::fs::File;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use clap::Args;
use rust_util::{debugging, iff, opt_result, simple_error, util_cmd, util_msg, warning, XResult};
use serde_json::Value;
use zeroize::Zeroize;

use crate::{config, consts, util, util_env};
use crate::cmd_decrypt::{decrypt_limited_content_to_vec, select_envelop, try_decrypt_key};
use crate::config::TinyEncryptConfig;
use crate::consts::TINY_ENC_CONFIG_FILE;
use crate::crypto_cryptor::{Cryptor, KeyNonce};
use crate::util::SecVec;
use crate::util_enc_file;

#[derive(Debug, Args)]
pub struct CmdExecEnv {
    /// PGP or PIV PIN
    #[arg(long, short = 'p')]
    pub pin: Option<String>,

    /// KeyID
    #[arg(long, short = 'k')]
    pub key_id: Option<String>,

    /// PIV slot
    #[arg(long, short = 's')]
    pub slot: Option<String>,

    /// Tiny encrypt file name
    pub file_name: String,

    /// Command and arguments
    pub command_arguments: Vec<String>,
}

impl Drop for CmdExecEnv {
    fn drop(&mut self) {
        if let Some(p) = self.pin.as_mut() { p.zeroize(); }
    }
}

pub fn exec_env(cmd_exec_env: CmdExecEnv) -> XResult<()> {
    util_msg::set_logger_std_out(false);
    debugging!("Cmd exec env: {:?}", cmd_exec_env);
    let config = TinyEncryptConfig::load(TINY_ENC_CONFIG_FILE).ok();
    if cmd_exec_env.command_arguments.is_empty() {
        return simple_error!("No commands assigned.");
    }

    let start = Instant::now();
    let pin = cmd_exec_env.pin.clone().or_else(util_env::get_pin);
    let key_id = cmd_exec_env.key_id.clone().or_else(util_env::get_key_id);

    let path = PathBuf::from(&cmd_exec_env.file_name);
    let path = config::resolve_path_namespace(&config, &path, true);
    let path_display = format!("{}", &path.display());
    util::require_tiny_enc_file_and_exists(&path)?;

    let mut file_in = opt_result!(File::open(&path), "Open file: {} failed: {}", &path_display);
    let (_, _, meta) = opt_result!(
        util_enc_file::read_tiny_encrypt_meta_and_normalize(&mut file_in), "Read file: {}, failed: {}", &path_display);
    util_msg::when_debug(|| {
        debugging!("Found meta: {}", serde_json::to_string_pretty(&meta).unwrap());
    });

    let encryption_algorithm = meta.encryption_algorithm.as_deref()
        .unwrap_or(consts::TINY_ENC_AES_GCM);
    let cryptor = Cryptor::from(encryption_algorithm)?;

    let selected_envelop = select_envelop(&meta, &key_id, &config, true)?;

    let key = SecVec(try_decrypt_key(&config, selected_envelop, &pin, &cmd_exec_env.slot, true)?);
    let nonce = SecVec(opt_result!(util::decode_base64(&meta.nonce), "Decode nonce failed: {}"));
    let key_nonce = KeyNonce { k: key.as_ref(), n: nonce.as_ref() };

    let decrypted_content = decrypt_limited_content_to_vec(&mut file_in, &meta, cryptor, &key_nonce)?;
    let exit_code = if let Some(output) = decrypted_content {
        debugging!("Outputs: {}", output);
        let arguments = &cmd_exec_env.command_arguments;
        let envs = parse_output_to_env(&output);

        let mut command = Command::new(&arguments[0]);
        arguments.iter().skip(1).for_each(|a| { command.arg(a); });
        envs.iter().for_each(|(k, v)| { command.env(k, v); });

        debugging!("Run cmd: {:?}", command);
        let run_cmd_result = util_cmd::run_command_and_wait(&mut command)?;
        debugging!("Run cmd result: {}", run_cmd_result);
        iff!(run_cmd_result.success(), 0, run_cmd_result.code().unwrap_or(-2))
    } else {
        -1
    };

    debugging!("Finished, cost: {}ms", start.elapsed().as_millis());
    std::process::exit(exit_code);
}

// supports format:
// JSON:
// {
//   "KEY": "value",
//   "KEY2": "value2"
// }
// ----OR----
// [
//    "KEY": "value",
//    "KEY2": "value2"
// ]
// ENV:
// KEY=value
// KEY2=value2
fn parse_output_to_env(output: &str) -> Vec<(String, String)> {
    let mut env = vec![];
    if let Ok(json) = serde_json::from_str::<Value>(output) {
        match &json {
            Value::Array(array) => {
                for a in array {
                    match a {
                        Value::String(s) => { env.push((s.to_string(), "".to_string())); }
                        Value::Array(a2) => if a2.len() == 2 {
                            env.push((a2[0].to_string(), a2[1].to_string()));
                        } else {
                            warning!("Invalid array object: {:?}", a2);
                        }
                        Value::Object(object) => {
                            object.iter().for_each(|(k, v)| {
                                env.push((k.to_string(), v.to_string()));
                            });
                        }
                        _ => { warning!("Invalid array object: {}", a); }
                    }
                }
            }
            Value::Object(object) => {
                object.iter().for_each(|(k, v)| {
                    env.push((k.to_string(), v.to_string()));
                });
            }
            _ => { warning!("Parse to env failed: {}", json); }
        }
    } else {
        let lines = output.split('\n');
        lines.filter(|ln| !ln.trim().is_empty()).for_each(|ln| {
            if ln.starts_with('#') {
                debugging!("Found comment: {}", ln);
            } else if ln.contains('=') {
                let k = ln.chars().take_while(|c| c != &'=').collect::<String>();
                let v = ln.chars().skip_while(|c| c != &'=').skip(1).collect::<String>();
                env.push((k, v));
            } else {
                env.push((ln.to_string(), "".to_string()));
            }
        });
    }

    debugging!("Parsed env: {:?}", env);
    env
}
