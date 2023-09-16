use std::collections::HashMap;
use std::fs;
use rust_util::{opt_result, XResult};
use rust_util::util_file::resolve_file_path;

use serde::{Deserialize, Serialize};

use crate::spec::TinyEncryptEnvelopType;

/// Config file sample:
/// ~/.tinyencrypt/config-rs.json
/// {
///     "envelops": [
///         {
///             "type": "pgp",
///             "kid": "KID-1",
///             "desc": "this is key 001",
///             "public_key": "----- BEGIN OPENPGP ..."
///         },
///         {
///             "type": "ecdh",
///             "kid": "KID-2",
///             "desc": "this is key 002",
///             "publicPart": "04..."
///         }
///     ],
///     "profiles": {
///         "default": ["KID-1", "KID-2"],
///         "leve2": ["KID-2"]
///     }
/// }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TinyEncryptConfig {
    pub envelops: Vec<TinyEncryptConfigEnvelop>,
    pub profiles: HashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TinyEncryptConfigEnvelop {
    pub r#type: TinyEncryptEnvelopType,
    pub kid: String,
    pub desc: Option<String>,
    pub public_part: String,
}

impl TinyEncryptConfig {
    pub fn load(file: &str) -> XResult<Self> {
        let resolved_file = resolve_file_path(file);
        let config_contents = opt_result!(fs::read_to_string(&resolved_file), "Read file: {}, failed: {}", file);
        // TODO replace with Human JSON
        Ok(opt_result!(serde_json::from_str(&config_contents), "Parse file: {}, failed: {}", file))
    }

    pub fn find_envelops(&self, profile: &Option<String>) -> Vec<&TinyEncryptConfigEnvelop> {
        let profile = profile.as_ref().map(String::as_str).unwrap_or("default");
        let mut matched_envelops_map = HashMap::new();
        if let Some(key_ids) = self.profiles.get(profile) {
            for key_id in key_ids {
                self.envelops.iter().for_each(|envelop| {
                    let is_matched = (&envelop.kid == key_id)
                        || key_id == &format!("type:{}", &envelop.r#type.get_name());
                    if is_matched {
                        matched_envelops_map.insert(&envelop.kid, envelop);
                    }
                });
            }
        }
        matched_envelops_map.values().map(|envelop| *envelop).collect()
    }
}
