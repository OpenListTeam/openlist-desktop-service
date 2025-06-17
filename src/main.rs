mod openlistcore;

use log::{LevelFilter, info};
use log4rs::{
    append::file::FileAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use std::path::PathBuf;

const SERVICE_NAME: &str = "OpenList Desktop Service";
const LOG_FILE_NAME: &str = "openlist-desktop-service.log";

fn setup_log_file() -> Result<(), Box<dyn std::error::Error>> {
    let log_paths = [
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|p| p.join(LOG_FILE_NAME))),
        Some(PathBuf::from(LOG_FILE_NAME)),
        Some(std::env::temp_dir().join(LOG_FILE_NAME)),
    ];

    for log_path in log_paths.iter().flatten() {
        if let Ok(file_appender) = FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new(
                "[{d(%Y-%m-%d %H:%M:%S)}] [{l}] {m}{n}",
            )))
            .build(log_path)
        {
            if let Ok(config) = Config::builder()
                .appender(Appender::builder().build("file", Box::new(file_appender)))
                .build(Root::builder().appender("file").build(LevelFilter::Info))
            {
                if log4rs::init_config(config).is_ok() {
                    info!("Log file: {:?}", log_path);
                    return Ok(());
                }
            }
        }
    }

    Err("Failed to initialize logging".into())
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    let _ = setup_log_file();
    info!("Starting {}", SERVICE_NAME);
    openlistcore::main()
}

#[cfg(not(windows))]
fn main() {
    let _ = setup_log_file();
    info!("Starting {}", SERVICE_NAME);
    openlistcore::main();
}
