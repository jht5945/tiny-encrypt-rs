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
    pub sid: Option<String>,
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
        let config_envelops = self.find_by_kid_or_filter(kid, |_| false);
        if config_envelops.is_empty() {
            None
        } else {
            Some(config_envelops[0])
        }
    }

    pub fn find_by_kid_or_type(&self, k_filter: &str) -> Vec<&TinyEncryptConfigEnvelop> {
        self.find_by_kid_or_filter(k_filter, |e| {
            k_filter == "ALL" || k_filter == format!("type:{}", &e.r#type.get_name())
        })
    }

    pub fn find_by_kid_or_filter<F>(&self, kid: &str, f: F) -> Vec<&TinyEncryptConfigEnvelop>
        where F: Fn(&TinyEncryptConfigEnvelop) -> bool {
        self.envelops.iter().filter(|e| {
            if e.kid == kid {
                return true;
            }
            if let Some(sid) = &e.sid {
                return sid == kid;
            }
            f(e)
        }).collect()
    }

    pub fn find_envelops(&self, profile: &Option<String>, key_filter: &Option<String>) -> XResult<Vec<&TinyEncryptConfigEnvelop>> {
        debugging!("Profile: {:?}", profile);
        debugging!("Key filter: {:?}", key_filter);
        let mut matched_envelops_map = HashMap::new();
        let mut key_ids = vec![];
        if key_filter.is_none() || profile.is_some() {
            let profile = profile.as_ref().map(String::as_str).unwrap_or("default");
            if let Some(kids) = self.profiles.get(profile) {
                kids.iter().for_each(|k| key_ids.push(k.to_string()));
            }
        }
        if let Some(key_filter) = key_filter {
            key_filter.split(',').for_each(|k| {
                let k = k.trim();
                if !k.is_empty() {
                    key_ids.push(k.to_string());
                }
            });
        }
        if key_ids.is_empty() {
            return simple_error!("Profile or key filter cannot find valid envelopes");
        }
        for key_id in &key_ids {
            for envelop in self.find_by_kid_or_type(key_id) {
                matched_envelops_map.insert(&envelop.kid, envelop);
            }
        }

        let mut envelops: Vec<_> = matched_envelops_map.values().copied().collect();
        if envelops.is_empty() {
            return simple_error!("Profile or key filter cannot find valid envelopes");
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
