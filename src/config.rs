use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::{env, fs};
use rust_util::util_env as rust_util_env;
use rust_util::util_file::resolve_file_path;
use rust_util::{debugging, opt_result, simple_error, warning, XResult};
use serde::{Deserialize, Serialize};
use crate::consts::{ENV_TINY_ENC_CONFIG_FILE, TINY_ENC_CONFIG_FILE, TINY_ENC_CONFIG_FILE_2, TINY_ENC_CONFIG_FILE_3, TINY_ENC_FILE_EXT};
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
    pub includes: Option<String>, // find all *.tinyencrypt.json
    pub envelops: Vec<TinyEncryptConfigEnvelop>,
    pub profiles: Option<HashMap<String, Vec<String>>>,
}

impl TinyEncryptConfig {
    fn get_profile(&self, profile: &str) -> Option<&Vec<String>> {
        match &self.profiles {
            Some(profiles) => profiles.get(profile),
            None => None,
        }
    }
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
    pub fn load_default() -> XResult<Self> {
        let resolved_file0 = rust_util_env::env_var(ENV_TINY_ENC_CONFIG_FILE);
        let resolved_file_1 = resolve_file_path(TINY_ENC_CONFIG_FILE);
        let resolved_file_2 = resolve_file_path(TINY_ENC_CONFIG_FILE_2);
        let resolved_file_3 = resolve_file_path(TINY_ENC_CONFIG_FILE_3);
        if let Some(resolved_file) = resolved_file0 {
            debugging!("Found tiny encrypt config file: {}", &resolved_file);
            return Self::load(&resolved_file)
        }
        let config_file = if fs::metadata(&resolved_file_1).is_ok() {
            debugging!("Load config from: {resolved_file_1}");
            resolved_file_1
        } else if fs::metadata(&resolved_file_2).is_ok() {
            debugging!("Load config from: {resolved_file_2}");
            resolved_file_2
        }  else if fs::metadata(&resolved_file_3).is_ok() {
            debugging!("Load config from: {resolved_file_3}");
            resolved_file_3
        } else {
            warning!("Cannot find config file from:\n- {resolved_file_1}\n- {resolved_file_2}\n- {resolved_file_3}");
            resolved_file_1
        };
        Self::load(&config_file)
    }

    pub fn load(file: &str) -> XResult<Self> {
        let resolved_file = resolve_file_path(file);
        let config_contents = opt_result!(
            fs::read_to_string(resolved_file),
            "Read config file: {}, failed: {}",
            file
        );
        let config: TinyEncryptConfig = opt_result!(
            serde_json::from_str(&config_contents),
            "Parse config file: {}, failed: {}",
            file
        );
        debugging!("Config: {:#?}", config);
        let mut config = load_includes_and_merge(config);
        debugging!("Final config: {:#?}", config);

        if let Some(profiles) = config.profiles {
            let mut splited_profiles = HashMap::new();
            for (k, v) in profiles.into_iter() {
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
            config.profiles = Some(splited_profiles);
        }

        if let Some(environment) = &config.environment {
            for (k, v) in environment {
                let v = match v {
                    StringOrVecString::String(s) => s.to_string(),
                    StringOrVecString::Vec(vs) => vs.join(","),
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
                let namespace = path_str
                    .chars()
                    .skip(1)
                    .take_while(|c| *c != ':')
                    .collect::<String>();
                let mut filename = path_str
                    .chars()
                    .skip(1)
                    .skip_while(|c| *c != ':')
                    .skip(1)
                    .collect::<String>();
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
                let new_k_filter = new_k_filter
                    .iter()
                    .take(new_k_filter.len() - 1)
                    .collect::<String>();
                if e.kid.starts_with(&new_k_filter) || envelop_type.starts_with(&new_k_filter) {
                    return true;
                }
            }
            false
        })
    }

    pub fn find_by_kid_or_filter<F>(&self, kid: &str, f: F) -> Vec<&TinyEncryptConfigEnvelop>
    where
        F: Fn(&TinyEncryptConfigEnvelop) -> bool,
    {
        self.envelops
            .iter()
            .filter(|e| {
                if e.kid == kid {
                    return true;
                }
                if let Some(sid) = &e.sid {
                    if sid == kid {
                        return true;
                    }
                }
                f(e)
            })
            .collect()
    }

    pub fn find_envelops(
        &self,
        profile: &Option<String>,
        key_filter: &Option<String>,
    ) -> XResult<Vec<&TinyEncryptConfigEnvelop>> {
        debugging!("Profile: {:?}", profile);
        debugging!("Key filter: {:?}", key_filter);
        let mut matched_envelops_map = HashMap::new();
        let mut key_ids = vec![];
        if key_filter.is_none() || profile.is_some() {
            let profile = profile.as_ref().map(String::as_str).unwrap_or("default");
            if profile == "ALL" {
                self.envelops.iter().for_each(|e| {
                    key_ids.push(e.kid.to_string());
                });
            } else if let Some(kids) = self.get_profile(profile) {
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
            if e1.r#type < e2.r#type {
                return Ordering::Greater;
            }
            if e1.r#type > e2.r#type {
                return Ordering::Less;
            }
            if e1.kid < e2.kid {
                return Ordering::Greater;
            }
            if e1.kid > e2.kid {
                return Ordering::Less;
            }
            Ordering::Equal
        });
        Ok(envelops)
    }
}

pub fn resolve_path_namespace(
    config: &Option<TinyEncryptConfig>,
    path: &Path,
    append_te: bool,
) -> PathBuf {
    match config {
        None => path.to_path_buf(),
        Some(config) => config.resolve_path_namespace(path, append_te),
    }
}

pub fn load_includes_and_merge(mut config: TinyEncryptConfig) -> TinyEncryptConfig {
    debugging!("Config includes: {:?}", &config.includes);
    if let Some(includes) = &config.includes {
        let sub_configs = search_include_configs(includes);
        debugging!(
            "Found {} sub configs, detail {:?}",
            sub_configs.len(),
            sub_configs
        );
        for sub_config in &sub_configs {
            // merge environment
            if let Some(sub_environment) = &sub_config.environment {
                match &mut config.environment {
                    None => {
                        config.environment = Some(sub_environment.clone());
                    }
                    Some(env) => {
                        for (k, v) in sub_environment {
                            match env.get_mut(k) {
                                None => {
                                    env.insert(k.clone(), v.clone());
                                }
                                Some(env_val) => {
                                    match (env_val, v) {
                                        (StringOrVecString::Vec(env_value_vec), StringOrVecString::Vec(v_vec)) => {
                                            for vv in v_vec {
                                                if !env_value_vec.contains(vv) {
                                                    env_value_vec.push(vv.clone());
                                                }
                                            }
                                        }
                                        _ => {
                                            warning!("Duplicate or mis-match environment value, key: {}", k);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // merge profiles
            for sub_envelop in &sub_config.envelops {
                let filter_envelops = config.envelops.iter().filter(|e| {
                    e.kid == sub_envelop.kid || (e.sid.is_some() && e.sid == sub_envelop.sid)
                }).collect::<Vec<_>>();
                if !filter_envelops.is_empty() {
                    warning!("Duplication kid: {} or sid: {:?}", sub_envelop.kid, sub_envelop.sid);
                    continue;
                }
                config.envelops.push(sub_envelop.clone());
            }
            // merge profiles
            if let Some(sub_profiles) = &sub_config.profiles {
                match &mut config.profiles {
                    None => {
                        config.profiles = Some(sub_profiles.clone());
                    }
                    Some(profiles) => {
                        for (k, v) in sub_profiles {
                            match profiles.get_mut(k) {
                                None => {
                                    profiles.insert(k.clone(), v.clone());
                                }
                                Some(env_val) => {
                                    for vv in v {
                                        env_val.push(vv.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(profiles) = &mut config.profiles {
        let all_key_ids = config.envelops.iter().map(|e| e.kid.clone()).collect::<Vec<_>>();
        if profiles.contains_key("__all__") {
            warning!("Key __all__ in profiles exists")
        } else {
            profiles.insert("__all__".to_string(), all_key_ids);
        }
    }
    config
}

pub fn search_include_configs(includes_path: &str) -> Vec<TinyEncryptConfig> {
    let includes_path = if includes_path.starts_with("$") {
        let includes_path_env_var = includes_path.chars().skip(1).collect::<String>();
        match rust_util_env::env_var(&includes_path_env_var) {
            Some(includes_path) => includes_path,
            None => {
                warning!("Cannot find env var: {}", &includes_path_env_var);
                return vec![];
            }
        }
    } else {
        includes_path.to_string()
    };

    let includes_path = &includes_path;
    let mut sub_configs = vec![];
    let read_dir = match fs::read_dir(includes_path) {
        Ok(read_dir) => read_dir,
        Err(e) => {
            warning!("Read dir: {}, failed: {}", includes_path, e);
            return sub_configs;
        }
    };
    for entry in read_dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                warning!("Read dir: {} entry, failed: {}", includes_path, e);
                continue;
            }
        };
        let file_name = entry.file_name();
        let file_name = file_name.to_str();
        let file_name = match file_name {
            Some(file_name) => file_name,
            None => continue,
        };
        if file_name.ends_with(".tinyencrypt.json") {
            debugging!("Matches config file: {}", file_name);
            let file_path = entry.path();
            let content = match fs::read_to_string(entry.path()) {
                Ok(content) => content,
                Err(e) => {
                    warning!("Read config file: {:?}, failed: {}", file_path, e);
                    continue;
                }
            };
            let config = match serde_json::from_str::<TinyEncryptConfig>(&content) {
                Ok(config) => config,
                Err(e) => {
                    warning!("Parse config file: {:?}, failed: {}", file_path, e);
                    continue;
                }
            };
            sub_configs.push(config);
        }
    }
    sub_configs
}
