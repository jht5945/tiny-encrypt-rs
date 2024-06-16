use std::cmp::max;
use std::fs::File;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use clap::Args;
use rust_util::{
    debugging, failure, iff, opt_result, simple_error, success,
    util_msg, util_size, util_time, XResult,
};
use rust_util::util_time::UnixEpochTime;
use simpledateformat::format_human2;

use crate::{config, util, util_enc_file, util_envelop};
use crate::config::TinyEncryptConfig;
use crate::consts::{DATE_TIME_FORMAT, TINY_ENC_AES_GCM, TINY_ENC_CONFIG_FILE};
use crate::util::is_tiny_enc_file;
use crate::wrap_key::WrapKey;

#[derive(Debug, Args)]
pub struct CmdInfo {
    /// Show raw meta
    #[arg(long, short = 'M', default_value_t = false)]
    pub raw_meta: bool,

    /// File
    pub paths: Vec<PathBuf>,
}

pub fn info(cmd_info: CmdInfo) -> XResult<()> {
    let config = TinyEncryptConfig::load(TINY_ENC_CONFIG_FILE).ok();
    for (i, path) in cmd_info.paths.iter().enumerate() {
        let path = config::resolve_path_namespace(&config, path, true);
        if i > 0 { println!("{}", "-".repeat(88)); }
        if let Err(e) = info_single(&path, &cmd_info, &config) {
            failure!("Parse Tiny Encrypt file info failed: {}", e);
        }
    }
    println!();
    Ok(())
}

pub fn info_single(path: &PathBuf, cmd_info: &CmdInfo, config: &Option<TinyEncryptConfig>) -> XResult<()> {
    let path_display = format!("{}", path.display());
    if !is_tiny_enc_file(&path_display) {
        return simple_error!("Not a Tiny Encrypt file: {}", path_display);
    }

    let mut file_in = opt_result!(File::open(path), "Open file: {} failed: {}", &path_display);
    let file_in_len = file_in.metadata().map(|m| m.len()).unwrap_or(0);

    let (meta_len, _, meta) = opt_result!(
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

    if meta.compress && file_in_len > (2 + 4 + meta_len as u64) {
        let actual_file_in_len = file_in_len - 2 - 4 - meta_len as u64;
        infos.push(format!("{}: {}, after compressed {}, ratio: {}%",
                           header("File size"),
                           util_size::get_display_size(meta.file_length as i64),
                           util_size::get_display_size(actual_file_in_len as i64),
                           util::ratio(actual_file_in_len, meta.file_length)
        ));
    } else {
        infos.push(format!("{}: {}", header("File size"),
                           util_size::get_display_size(meta.file_length as i64)
        ));
    }
    infos.push(format!("{}: {}",
                       header("Meta size"), util_size::get_display_size(meta_len as i64))
    );

    infos.push(format!("{}: Version: {}, Agent: {}",
                       header("File summary"), meta.version, meta.user_agent)
    );
    if let Some(latest_user_agent) = meta.latest_user_agent {
        infos.push(format!("{}: {}", header("Latest user agent"), latest_user_agent))
    }

    let now_millis = util_time::get_current_millis() as u64;
    let fmt = simpledateformat::fmt(DATE_TIME_FORMAT).unwrap();
    infos.push(format!("{}: {}, {} ago",
                       header("Created"),
                       fmt.format_local(SystemTime::from_millis(meta.created)),
                       format_human2(Duration::from_millis(now_millis - meta.created))
    ));
    infos.push(format!("{}: {}, {} ago",
                       header("Last modified"),
                       fmt.format_local(SystemTime::from_millis(meta.file_last_modified)),
                       format_human2(Duration::from_millis(now_millis - meta.file_last_modified))
    ));
    if let Some(file_edit_count) = meta.file_edit_count {
        infos.push(format!("{}: {} time(s)",
                           header("Edit count"),
                           file_edit_count
        ));
    }

    if let Some(envelops) = meta.envelops.as_ref() {
        envelops.iter().enumerate().for_each(|(i, envelop)| {
            infos.push(format!("{}: {}",
                               header(&format!("Envelop #{}", i + 1)),
                               util_envelop::format_envelop(envelop, config)
            ));
            util_msg::when_debug(|| {
                if let Ok(wrap_key) = WrapKey::parse(&envelop.encrypted_key) {
                    debugging!("Wrap key: {}", serde_json::to_string(&wrap_key).expect("SHOULD NOT HAPPEN"));
                }
            });
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
    let encryption_algorithm = meta.encryption_algorithm.clone()
        .unwrap_or_else(|| format!("{} (default)", TINY_ENC_AES_GCM));
    infos.push(format!("{}: {}", header("Encryption algorithm"), encryption_algorithm));

    success!("{}", infos.join("\n"));
    Ok(())
}

fn header(h: &str) -> String {
    let width = 21;
    h.to_string() + ".".repeat(max(width - h.len(), 0)).as_str()
}

fn to_yes_or_no(opt: &Option<String>) -> String {
    iff!(opt.is_some(), "YES", "NO").to_string()
}