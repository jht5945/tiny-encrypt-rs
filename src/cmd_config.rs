use std::cmp::Ordering;
use std::collections::HashMap;

use clap::Args;
use rust_util::{iff, information, warning, XResult};
use tabled::{Table, Tabled};
use tabled::settings::Style;

use crate::config::TinyEncryptConfig;
use crate::consts::TINY_ENC_CONFIG_FILE;
use crate::util_envelop;

#[derive(Tabled, Eq)]
struct ConfigProfile {
    profiles: String,
    keys: String,
}

impl PartialEq<Self> for ConfigProfile {
    fn eq(&self, other: &Self) -> bool {
        self.profiles.eq(&other.profiles)
    }
}

impl Ord for ConfigProfile {
    fn cmp(&self, other: &Self) -> Ordering {
        self.profiles.cmp(&other.profiles)
    }
}

impl PartialOrd for ConfigProfile {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Tabled)]
pub struct ConfigEnvelop {
    pub r#type: String,
    pub sid: String,
    pub kid: String,
    pub desc: String,
    pub args: String,
}

#[derive(Debug, Args)]
pub struct CmdConfig {
    /// Show KID
    #[arg(long)]
    pub show_kid: bool,
    /// Encryption profile (use default when --key-filter is assigned)
    #[arg(long, short = 'p')]
    pub profile: Option<String>,
    /// Encryption key filter (key_id or type:TYPE(e.g. type:piv-p256, type:piv-p384, type:pgp-*), multiple joined by ',', ALL for all)
    #[arg(long, short = 'k')]
    pub key_filter: Option<String>,
}

pub fn config(cmd_version: CmdConfig) -> XResult<()> {
    let config = TinyEncryptConfig::load(TINY_ENC_CONFIG_FILE)?;

    if cmd_version.profile.is_some() || cmd_version.key_filter.is_some() {
        return config_key_filter(&cmd_version, &config);
    }
    config_profiles(&cmd_version, &config)
}

fn config_key_filter(cmd_version: &CmdConfig, config: &TinyEncryptConfig) -> XResult<()> {
    let envelops = config.find_envelops(&cmd_version.profile, &cmd_version.key_filter)?;
    if envelops.is_empty() { warning!("Found no envelops"); }
    information!("Found {} envelops", envelops.len());
    let mut config_envelops = vec![];
    for envelop in envelops {
        config_envelops.push(ConfigEnvelop {
            r#type: format!("{}{}", envelop.r#type.get_name(), iff!(envelop.r#type.is_hardware_security(), " *", "")),
            sid: strip_field(&envelop.sid.as_ref().map(ToString::to_string).unwrap_or_else(|| "-".to_string()), 25),
            kid: strip_field(&envelop.kid, 40),
            desc: strip_field(&envelop.desc.as_ref().map(ToString::to_string).unwrap_or_else(|| "-".to_string()), 40),
            args: strip_field(&envelop.args.as_ref().map(|a| format!("[{}]", a.join(", "))).unwrap_or_else(|| "-".to_string()), 20),
        });
    }
    let mut table = Table::new(config_envelops);
    table.with(Style::sharp());
    println!("{}", table);
    println!("> Type with * is hardware security");
    Ok(())
}

fn strip_field(kid: &str, max_len: usize) -> String {
    if kid.len() <= max_len {
        kid.to_string()
    } else {
        kid.chars().enumerate()
            .filter(|(i, _c)| *i < max_len)
            .map(|(i, c)| iff!(i >= (max_len - 3), '.', c)).collect()
    }
}

fn config_profiles(cmd_version: &CmdConfig, config: &TinyEncryptConfig) -> XResult<()> {
    let mut reverse_map = HashMap::new();
    for (p, v) in &config.profiles {
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
                    let kid = if cmd_version.show_kid {
                        format!("Kid: {}", envelop.kid)
                    } else {
                        envelop.sid.as_ref()
                            .map(|sid| format!("Sid: {}", sid))
                            .unwrap_or_else(|| format!("Kid: {}", envelop.kid))
                    };
                    let desc = envelop.desc.as_ref()
                        .map(|desc| format!(", Desc: {}", desc))
                        .unwrap_or_else(|| "".to_string());
                    ks.push(format!(
                        "{}, {}{}",
                        util_envelop::with_width_type(envelop.r#type.get_name()), kid, desc
                    ));
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
    println!("{}", table);

    Ok(())
}