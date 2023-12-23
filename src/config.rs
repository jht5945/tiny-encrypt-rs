use std::{env, fs};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

use rust_util::{debugging, opt_result, simple_error, warning, XResult};
use rust_util::util_file::resolve_file_path;
use serde::{Deserialize, Serialize};

use crate::consts::TINY_ENC_FILE_EXT;
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
///             "sid": "SHORT-ID-1",
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
    pub environment: Option<HashMap<String, StringOrVecString>>,
    pub namespaces: Option<HashMap<String, String>>,
    pub envelops: Vec<TinyEncryptConfigEnvelop>,
    pub profiles: HashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrVecString {
    String(String),
    Vec(Vec<String>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TinyEncryptConfigEnvelop {
    pub r#type: TinyEncryptEnvelopType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    pub public_part: String,
}

impl TinyEncryptConfig {
    pub fn load(file: &str) -> XResult<Self> {
        let resolved_file = resolve_file_path(file);
        let config_contents = opt_result!(
            fs::read_to_string(resolved_file), "Read config file: {}, failed: {}", file
        );
        let mut config: TinyEncryptConfig = opt_result!(
            serde_json::from_str(&config_contents),"Parse config file: {}, failed: {}", file);
        let mut splited_profiles = HashMap::new();
        for (k, v) in config.profiles.into_iter() {
            if !k.contains(',') {
                splited_profiles.insert(k, v);
            } else {
                k.split(',')
                    .map(|k| k.trim())
                    .filter(|k| !k.is_empty())
                    .for_each(|k| {
                        splited_profiles.insert(k.to_string(), v.clone());
                    });
            }
        }
        config.profiles = splited_profiles;

        if let Some(environment) = &config.environment {
            for (k, v) in environment {
                let v = match v {
                    StringOrVecString::String(s) => { s.to_string() }
                    StringOrVecString::Vec(vs) => { vs.join(",") }
                };
                debugging!("Set env: {}={}", k, v);
                env::set_var(k, v);
            }
        }

        Ok(config)
    }

    pub fn resolve_path_namespace(&self, path: &Path, append_te: bool) -> PathBuf {
        if let Some(path_str) = path.to_str() {
            if path_str.starts_with(':') {
                let namespace = path_str.chars().skip(1)
                    .take_while(|c| *c != ':').collect::<String>();
                let mut filename = path_str.chars().skip(1)
                    .skip_while(|c| *c != ':').skip(1).collect::<String>();
                if append_te && !filename.ends_with(TINY_ENC_FILE_EXT) {
                    filename.push_str(TINY_ENC_FILE_EXT);
                }

                match self.find_namespace(&namespace) {
                    None => warning!("Namespace: {} not found", &namespace),
                    Some(dir) => return PathBuf::from(dir).join(&filename),
                }
            }
        }
        path.to_path_buf()
    }

    pub fn find_namespace(&self, prefix: &str) -> Option<&String> {
        self.namespaces.as_ref().and_then(|m| m.get(prefix))
    }

    pub fn find_first_arg_by_kid(&self, kid: &str) -> Option<&String> {
        self.find_args_by_kid(kid).and_then(|a| a.iter().next())
    }

    pub fn find_args_by_kid(&self, kid: &str) -> Option<&Vec<String>> {
        self.find_by_kid(kid).and_then(|e| e.args.as_ref())
    }

    pub fn find_by_kid(&self, kid: &str) -> Option<&TinyEncryptConfigEnvelop> {
        self.find_by_kid_or_filter(kid, |_| false).first().copied()
    }

    pub fn find_by_kid_or_type(&self, k_filter: &str) -> Vec<&TinyEncryptConfigEnvelop> {
        self.find_by_kid_or_filter(k_filter, |e| {
            let envelop_type = format!("type:{}", &e.r#type.get_name());
            if k_filter == "ALL" || k_filter == "*" || k_filter == envelop_type {
                return true;
            }
            if k_filter.ends_with('*') {
                let new_k_filter = k_filter.chars().collect::<Vec<_>>();
                let new_k_filter = new_k_filter.iter().take(new_k_filter.len() - 1).collect::<String>();
                if e.kid.starts_with(&new_k_filter) || envelop_type.starts_with(&new_k_filter) {
                    return true;
                }
            }
            false
        })
    }

    pub fn find_by_kid_or_filter<F>(&self, kid: &str, f: F) -> Vec<&TinyEncryptConfigEnvelop>
        where F: Fn(&TinyEncryptConfigEnvelop) -> bool {
        self.envelops.iter().filter(|e| {
            if e.kid == kid { return true; }
            if let Some(sid) = &e.sid {
                if sid == kid { return true; }
            }
            f(e)
        }).collect()
    }

    pub fn find_envelops(&self, profile: &Option<String>, key_filter: &Option<String>)
                         -> XResult<Vec<&TinyEncryptConfigEnvelop>> {
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
            return simple_error!("Profile or key filter cannot find any valid envelopes");
        }
        for key_id in &key_ids {
            for envelop in self.find_by_kid_or_type(key_id) {
                matched_envelops_map.insert(&envelop.kid, envelop);
            }
        }

        let mut envelops: Vec<_> = matched_envelops_map.values().copied().collect();
        if envelops.is_empty() {
            return simple_error!("Profile or key filter cannot find any valid envelopes");
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

pub fn resolve_path_namespace(config: &Option<TinyEncryptConfig>, path: &Path, append_te: bool) -> PathBuf {
    match config {
        None => path.to_path_buf(),
        Some(config) => config.resolve_path_namespace(path, append_te),
    }
}
