use indicatif::{ProgressBar, ProgressStyle};

const PB_PROGRESS: &str = "#-";
const PB_TEMPLATE: &str = "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})";


pub struct Progress {
    progress_bar: ProgressBar,
}

impl Progress {
    pub fn new(total: u64) -> Self {
        let progress_bar = ProgressBar::new(total);
        progress_bar.set_style(ProgressStyle::default_bar()
            .template(PB_TEMPLATE).expect("SHOULD NOT FAIL")
            .progress_chars(PB_PROGRESS)
        );
        Self { progress_bar }
    }

    pub fn position(&self, position: u64) {
        self.progress_bar.set_position(position)
    }

    pub fn finish(&self) {
        self.progress_bar.finish_and_clear()
    }
}