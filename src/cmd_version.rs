use clap::Args;
use rust_util::{iff, XResult};

use crate::util;
use crate::util_keychainkey;

#[derive(Debug, Args)]
pub struct CmdVersion {}

pub fn version(_cmd_version: CmdVersion) -> XResult<()> {
    let mut features: Vec<String> = vec![];
    #[cfg(feature = "decrypt")]
    features.push("decrypt".to_string());
    #[cfg(feature = "macos")]
    features.push("macos".to_string());
    #[cfg(feature = "smartcard")]
    features.push("smartcard".to_string());
    if features.is_empty() { features.push("-".to_string()); }
    println!(
        "User-Agent: {} [with features: {}]{}\n{}",
        util::get_user_agent(),
        features.join(", "),
        iff!(util_keychainkey::is_support_se(), " with Secure Enclave Supported", ""),
        env!("CARGO_PKG_DESCRIPTION")
    );
    Ok(())
}