use std::cmp::max;
use std::fs::File;
use std::ops::Add;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use clap::Args;
use rust_util::{iff, opt_result, success, util_time, XResult};
use simpledateformat::format_human2;

use crate::{file, util};

#[derive(Debug, Args)]
pub struct CmdInfo {
    /// File
    pub path: PathBuf,
    /// Show raw meta
    #[arg(long, default_value_t = false)]
    pub raw_meta: bool,
}

pub fn info(cmd_info: CmdInfo) -> XResult<()> {
    let path_display = format!("{}", cmd_info.path.display());
    let mut file_in = opt_result!(File::open(&cmd_info.path), "Open file: {} failed: {}", &path_display);
    let meta = opt_result!(
        file::read_tiny_encrypt_meta_and_normalize(&mut file_in), "Read file: {}, failed: {}", &path_display
    );

    if cmd_info.raw_meta {
        success!("Meta data:\n{}", serde_json::to_string_pretty(&meta).expect("SHOULD NOT HAPPEN"));
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
    let fmt = simpledateformat::fmt("EEE MMM dd HH:mm:ss z yyyy").unwrap();
    infos.push(format!("{}: {}, {} ago",
                       header("Last modified"),
                       fmt.format_local(from_unix_epoch(meta.file_last_modified)),
                       format_human2(Duration::from_millis(now_millis - meta.file_last_modified))
    ));
    infos.push(format!("{}: {}, {} ago",
                       header("Created"),
                       fmt.format_local(from_unix_epoch(meta.created)),
                       format_human2(Duration::from_millis(now_millis - meta.created))
    ));

    meta.envelops.as_ref().map(|envelops|
        envelops.iter().enumerate().for_each(|(i, envelop)| {
            let kid = iff!(envelop.kid.is_empty(), "".into(), format!(", Kid: {}", envelop.kid));
            let desc = iff!(envelop.desc.is_none(), "".into(), format!(", Desc: {}", envelop.desc.as_ref().unwrap()));
            infos.push(format!("{}: {}{}{}",
                               header(&format!("Envelop #{}", i + 1)),
                               envelop.r#type.get_upper_name(),
                               kid,
                               desc
            ));
        })
    );
    meta.pgp_fingerprint.map(|fingerprint| {
        infos.push(format!("{}: {}", header("PGP fingerprint"), fingerprint));
    });
    meta.comment.map(|comment| {
        infos.push(format!("{}: {}", header("Comment"), comment));
    });
    infos.push(format!("{}: {}", header("Encrypted comment"), to_yes_or_no(&meta.encrypted_comment)));
    infos.push(format!("{}: {}", header("Encrypted meta"), to_yes_or_no(&meta.encrypted_meta)));
    let encryption_algorithm = if let Some(encryption_algorithm) = &meta.encryption_algorithm {
        encryption_algorithm.to_string()
    } else {
        format!("{} (default)", util::TINY_ENC_AES_GCM)
    };
    infos.push(format!("{}: {}", header("Encryption algorithm"), encryption_algorithm));

    success!("{}\n", infos.join("\n"));
    Ok(())
}

fn from_unix_epoch(t: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH.add(Duration::from_millis(t))
}

fn header(h: &str) -> String {
    let width = 21;
    h.to_string() + ".".repeat(max(width - h.len(), 0)).as_str()
}

fn to_yes_or_no(opt: &Option<String>) -> String {
    opt.as_ref().map(|_| "YES".to_string()).unwrap_or_else(|| "NO".to_string())
}