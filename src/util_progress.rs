use indicatif::{ProgressBar, ProgressStyle};
use rust_util::{debugging, util_msg};

use crate::util_env;

const PB_PROGRESS: &str = "#-";
const PB_TEMPLATE: &str = "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} {bytes_per_sec} ({eta})";


pub enum Progress {
    NoProgress,
    Progress(ProgressBar),
}

impl Progress {
    pub fn new(total: u64) -> Self {
        let no_progress = util_env::get_no_progress();
        let is_atty = util_msg::is_atty();

        if no_progress || !is_atty {
            debugging!("No progress: [{}, {}]", no_progress, is_atty);
            Self::NoProgress
        } else {
            let progress_bar = ProgressBar::new(total);
            progress_bar.set_style(ProgressStyle::default_bar()
                .template(PB_TEMPLATE).expect("SHOULD NOT FAIL")
                .progress_chars(PB_PROGRESS)
            );
            Self::Progress(progress_bar)
        }
    }

    pub fn position(&self, position: u64) {
        match self {
            Progress::NoProgress => {}
            Progress::Progress(progress_bar) => progress_bar.set_position(position),
        }
    }

    pub fn finish(&self) {
        match self {
            Progress::NoProgress => {}
            Progress::Progress(progress_bar) => progress_bar.finish_and_clear(),
        }
    }
}