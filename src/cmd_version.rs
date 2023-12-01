use clap::Args;
use rust_util::XResult;

use crate::util;

#[derive(Debug, Args)]
pub struct CmdVersion {}

pub fn version(_cmd_version: CmdVersion) -> XResult<()> {
    let mut features: Vec<&str> = vec![];
    #[cfg(feature = "smartcard")]
    features.push("smartcard");
    if features.is_empty() { features.push("-"); }
    println!(
        "User-Agent: {} [ with features: {} ]\n{}",
        util::get_user_agent(),
        features.join(", "),
        env!("CARGO_PKG_DESCRIPTION")
    );
    Ok(())
}