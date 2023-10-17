use clap::Args;
use rust_util::XResult;

#[derive(Debug, Args)]
pub struct CmdVersion {}

pub fn version(_cmd_version: CmdVersion) -> XResult<()> {
    println!(
        "{} - v{}\n{}\n",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_DESCRIPTION")
    );
    Ok(())
}