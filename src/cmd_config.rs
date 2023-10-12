use std::cmp::Ordering;
use std::collections::HashMap;

use clap::Args;
use rust_util::XResult;
use tabled::{Table, Tabled};
use tabled::settings::Style;

use crate::config::TinyEncryptConfig;
use crate::util::TINY_ENC_CONFIG_FILE;

#[derive(Tabled, Ord, Eq)]
struct ConfigProfile {
    profiles: String,
    keys: String,
}

impl PartialEq<Self> for ConfigProfile {
    fn eq(&self, other: &Self) -> bool {
        self.profiles.eq(&other.profiles)
    }
}

impl PartialOrd for ConfigProfile {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.profiles.partial_cmp(&other.profiles)
    }
}

#[derive(Debug, Args)]
pub struct CmdConfig {}

pub fn config(_cmd_version: CmdConfig) -> XResult<()> {
    let config = TinyEncryptConfig::load(TINY_ENC_CONFIG_FILE)?;

    let mut reverse_map = HashMap::new();
    for (p, v) in &config.profiles {
        let p = p;
        let mut v2 = v.clone();
        v2.sort();
        let vs = v2.join(",");
        match reverse_map.get_mut(&vs) {
            None => { reverse_map.insert(vs, vec![(p, v)]); }
            Some(vec) => { vec.push((p, v)); }
        }
    }

    let mut config_profiles = vec![];
    for pvs in reverse_map.values() {
        let mut ps: Vec<_> = pvs.iter().map(|pv| pv.0).collect();
        ps.sort();
        let pp = ps.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ");
        let kids = pvs[0].1;
        let mut ks = Vec::with_capacity(kids.len());
        for kid in kids {
            match config.find_by_kid(kid) {
                None => {
                    ks.push(format!("[ERROR] Key not found: {}", kid));
                }
                Some(envelop) => {
                    let desc = envelop.desc.as_ref()
                        .map(|desc| format!(", Desc: {}", desc))
                        .unwrap_or_else(|| "".to_string());
                    ks.push(format!("{}{}", envelop.kid, desc));
                }
            }
        }
        config_profiles.push(ConfigProfile {
            profiles: pp,
            keys: ks.join("\n"),
        });
    }
    config_profiles.sort();

    let mut table = Table::new(config_profiles);
    table.with(Style::modern());
    println!("{}", table.to_string());

    Ok(())
}