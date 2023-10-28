use std::time::SystemTime;

use fs_set_times::SystemTimeSpec;
use rust_util::{information, warning};
use rust_util::util_time::UnixEpochTime;

use crate::spec::EncEncryptedMeta;

pub fn update_file_time(enc_meta: Option<EncEncryptedMeta>, path: &str) {
    if let Some(enc_meta) = &enc_meta {
        let create_time = enc_meta.c_time.map(SystemTime::from_millis);
        let modify_time = enc_meta.m_time.map(SystemTime::from_millis);
        if create_time.is_some() || modify_time.is_some() {
            let set_times_result = fs_set_times::set_times(
                path,
                create_time.map(SystemTimeSpec::Absolute),
                modify_time.map(SystemTimeSpec::Absolute),
            );
            match set_times_result {
                Ok(_) => information!("Set file time succeed."),
                Err(e) => warning!("Set file time failed: {}", e),
            }
        }
    }
}