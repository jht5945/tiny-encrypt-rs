use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs;

use rust_util::{debugging, opt_result, simple_error, XResult};
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
///             "publicPart": "----- BEGIN OPENPGP ..."
///         },
///         {
///             "type": "ecdh",
///             "kid": "KID-2",
///             "desc": "this is key 002",
///             "publicPart": "04..."
///         }
///     ],
///     "profiles": {
///         "default": ["KID-1", "KID-2", "type:pgp"],
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
    pub args: Option<Vec<String>>,
    pub public_part: String,
}

impl TinyEncryptConfig {
    pub fn load(file: &str) -> XResult<Self> {
        let resolved_file = resolve_file_path(file);
        let config_contents = opt_result!(
            fs::read_to_string(&resolved_file), "Read file: {}, failed: {}", file
        );
        let mut config: TinyEncryptConfig = opt_result!(
            serde_json::from_str(&config_contents),"Parse file: {}, failed: {}", file);
        let mut splitted_profiles = HashMap::new();
        for (k, v) in config.profiles.into_iter() {
            if !k.contains(',') {
                splitted_profiles.insert(k, v);
            } else {
                k.split(',')
                    .map(|k| k.trim())
                    .filter(|k| !k.is_empty())
                    .for_each(|k| {
                        splitted_profiles.insert(k.to_string(), v.clone());
                    });
            }
        }
        config.profiles = splitted_profiles;
        Ok(config)
    }

    pub fn find_first_arg_by_kid(&self, kid: &str) -> Option<&String> {
        self.find_args_by_kid(kid).and_then(|a| a.iter().next())
    }

    pub fn find_args_by_kid(&self, kid: &str) -> Option<&Vec<String>> {
        self.find_by_kid(kid).and_then(|e| e.args.as_ref())
    }

    pub fn find_by_kid(&self, kid: &str) -> Option<&TinyEncryptConfigEnvelop> {
        self.envelops.iter().find(|e| e.kid == kid)
    }

    pub fn find_envelops(&self, profile: &Option<String>) -> XResult<Vec<&TinyEncryptConfigEnvelop>> {
        let profile = profile.as_ref().map(String::as_str).unwrap_or("default");
        debugging!("Profile: {}", profile);
        let mut matched_envelops_map = HashMap::new();
        if let Some(key_ids) = self.profiles.get(profile) {
            if key_ids.is_empty() {
                return simple_error!("Profile: {} contains no valid envelopes", profile);
            }
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
        let mut envelops: Vec<_> = matched_envelops_map.values()
            .copied()
            .collect();
        if envelops.is_empty() {
            return simple_error!("Profile: {} has no valid envelopes found", profile);
        }
        envelops.sort_by(|e1, e2| {
            if e1.r#type < e2.r#type { return Ordering::Greater; }
            if e1.r#type > e2.r#type { return Ordering::Less; }
            if e1.kid < e2.kid { return Ordering::Greater; }
            if e1.kid > e2.kid { return Ordering::Less; }
            Ordering::Equal
        });
        Ok(envelops)
    }
}
