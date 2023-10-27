use clap::Args;
use rust_util::XResult;

use crate::util;

#[derive(Debug, Args)]
pub struct CmdVersion {}

pub fn version(_cmd_version: CmdVersion) -> XResult<()> {
    println!(
        "User-Agent: {}\n{}",
        util::get_user_agent(),
        env!("CARGO_PKG_DESCRIPTION"),
    );
    Ok(())
}