use std::cmp::max;
use std::fs::File;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use clap::Args;
use rust_util::{opt_result, simple_error, success, util_time, warning, XResult};
use rust_util::util_time::UnixEpochTime;
use simpledateformat::format_human2;

use crate::{util_enc_file, util_envelop};
use crate::config::TinyEncryptConfig;
use crate::consts::{DATE_TIME_FORMAT, TINY_ENC_AES_GCM, TINY_ENC_CONFIG_FILE, TINY_ENC_FILE_EXT};

#[derive(Debug, Args)]
pub struct CmdInfo {
    /// File
    pub paths: Vec<PathBuf>,
    /// Show raw meta
    #[arg(long, default_value_t = false)]
    pub raw_meta: bool,
}

pub fn info(cmd_info: CmdInfo) -> XResult<()> {
    for (i, path) in cmd_info.paths.iter().enumerate() {
        if i > 0 { println!("{}", "-".repeat(88)); }
        if let Err(e) = info_single(path, &cmd_info) {
            warning!("Parse Tiny Encrypt file info failed: {}", e);
        }
    }
    println!();
    Ok(())
}

pub fn info_single(path: &PathBuf, cmd_info: &CmdInfo) -> XResult<()> {
    let path_display = format!("{}", path.display());
    if !path_display.ends_with(TINY_ENC_FILE_EXT) {
        return simple_error!("Not a Tiny Encrypt file: {}", path_display);
    }

    let config = TinyEncryptConfig::load(TINY_ENC_CONFIG_FILE).ok();
    let mut file_in = opt_result!(File::open(path), "Open file: {} failed: {}", &path_display);
    let meta = opt_result!(
        util_enc_file::read_tiny_encrypt_meta_and_normalize(&mut file_in), "Read file: {}, failed: {}", &path_display
    );

    if cmd_info.raw_meta {
        println!("{}", serde_json::to_string_pretty(&meta).expect("SHOULD NOT HAPPEN"));
        return Ok(());
    }

    let mut infos = vec![];
    infos.push("Tiny Encrypt File Info".to_string());
    let compressed = if meta.compress { " [compressed]" } else { "" };
    infos.push(format!("{}: {}{}", header("File name"), path_display, compressed));
    infos.push(format!("{}: {} bytes", header("File size"), meta.file_length));
    infos.push(format!("{}: Version: {}, Agent: {}",
                       header("File summary"), meta.version, meta.user_agent)
    );

    let now_millis = util_time::get_current_millis() as u64;
    let fmt = simpledateformat::fmt(DATE_TIME_FORMAT).unwrap();
    infos.push(format!("{}: {}, {} ago",
                       header("Last modified"),
                       fmt.format_local(SystemTime::from_millis(meta.file_last_modified)),
                       format_human2(Duration::from_millis(now_millis - meta.file_last_modified))
    ));
    infos.push(format!("{}: {}, {} ago",
                       header("Created"),
                       fmt.format_local(SystemTime::from_millis(meta.created)),
                       format_human2(Duration::from_millis(now_millis - meta.created))
    ));

    if let Some(envelops) = meta.envelops.as_ref() {
        envelops.iter().enumerate().for_each(|(i, envelop)| {
            infos.push(format!("{}: {}",
                               header(&format!("Envelop #{}", i + 1)),
                               util_envelop::format_envelop(envelop, &config)
            ));
        })
    }

    if let Some(fingerprint) = meta.pgp_fingerprint {
        infos.push(format!("{}: {}", header("PGP fingerprint"), fingerprint));
    }
    if let Some(comment) = meta.comment {
        infos.push(format!("{}: {}", header("Comment"), comment));
    }
    infos.push(format!("{}: {}", header("Encrypted comment"), to_yes_or_no(&meta.encrypted_comment)));
    infos.push(format!("{}: {}", header("Encrypted meta"), to_yes_or_no(&meta.encrypted_meta)));
    let encryption_algorithm = if let Some(encryption_algorithm) = &meta.encryption_algorithm {
        encryption_algorithm.to_string()
    } else {
        format!("{} (default)", TINY_ENC_AES_GCM)
    };
    infos.push(format!("{}: {}", header("Encryption algorithm"), encryption_algorithm));

    success!("{}", infos.join("\n"));
    Ok(())
}

fn header(h: &str) -> String {
    let width = 21;
    h.to_string() + ".".repeat(max(width - h.len(), 0)).as_str()
}

fn to_yes_or_no(opt: &Option<String>) -> String {
    opt.as_ref().map(|_| "YES".to_string()).unwrap_or_else(|| "NO".to_string())
}