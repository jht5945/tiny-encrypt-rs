use rust_util::iff;

use crate::config::TinyEncryptConfig;
use crate::spec::TinyEncryptEnvelop;

pub fn format_envelop(envelop: &TinyEncryptEnvelop, config: &Option<TinyEncryptConfig>) -> String {
    let kid = iff!(envelop.kid.is_empty(), "".into(), format!(", Kid: {}", envelop.kid));
    let envelop_desc = get_envelop_desc(&kid, envelop, &config);
    let desc = envelop_desc.as_ref()
        .map(|desc| format!(", Desc: {}", desc))
        .unwrap_or_else(|| "".to_string());
    format!("{}{}{}", envelop.r#type.get_upper_name(), kid, desc)
}

pub fn get_envelop_desc(kid: &str, envelop: &TinyEncryptEnvelop, config: &Option<TinyEncryptConfig>) -> Option<String> {
    if let Some(desc) = &envelop.desc {
        return Some(desc.to_string());
    }
    if let Some(config) = config {
        if let Some(config_envelop) = config.find_by_kid(kid) {
            return config_envelop.desc.clone();
        }
    }
    None
}
