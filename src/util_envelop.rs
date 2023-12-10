use rust_util::iff;

use crate::config::{TinyEncryptConfig, TinyEncryptConfigEnvelop};
use crate::spec::TinyEncryptEnvelop;

pub fn format_envelop(envelop: &TinyEncryptEnvelop, config: &Option<TinyEncryptConfig>) -> String {
    let config_envelop = config.as_ref().and_then(|c| c.find_by_kid(&envelop.kid));
    let envelop_kid = config_envelop.and_then(|e| e.sid.as_ref())
        .map(|sid| format!(", Sid: {}", sid))
        .unwrap_or_else(|| format!(", Kid: {}", envelop.kid));
    let envelop_desc = get_envelop_desc(envelop, &config_envelop);
    let desc = envelop_desc.as_ref()
        .map(|desc| format!(", Desc: {}", desc))
        .unwrap_or_default();
    format!("{}{}{}", with_width_type(&envelop.r#type.get_upper_name()), envelop_kid, desc)
}

fn get_envelop_desc(envelop: &TinyEncryptEnvelop, config_envelop: &Option<&TinyEncryptConfigEnvelop>) -> Option<String> {
    if let Some(desc) = &envelop.desc {
        return Some(desc.to_string());
    }
    if let Some(config_envelop) = config_envelop {
        return config_envelop.desc.clone();
    }
    None
}

pub fn with_width_type(s: &str) -> String {
    with_width(s, 13)
}

pub fn with_width(s: &str, width: usize) -> String {
    iff!(s.len() < width, format!("{}{}", s, " ".repeat(width - s.len())), s.to_string())
}
