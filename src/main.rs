mod openlistcore;
mod utils;

use log::{LevelFilter, info};
use log4rs::{
    append::rolling_file::{
        RollingFileAppender,
        policy::compound::{
            CompoundPolicy, roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger,
        },
    },
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use openlistcore::get_service_log_file_path;
use std::path::PathBuf;

const SERVICE_NAME: &str = "OpenList Desktop Service";

fn setup_log_file() -> Result<(), Box<dyn std::error::Error>> {
    let log_paths = [
        get_service_log_file_path().ok(),
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|p| p.join("openlist-desktop-service.log"))),
        Some(PathBuf::from("openlist-desktop-service.log")),
        Some(std::env::temp_dir().join("openlist-desktop-service.log")),
    ];
    for log_path in log_paths.iter().flatten() {
        if let Some(parent) = log_path.parent() {
            if let Err(_) = std::fs::create_dir_all(parent) {
                continue;
            }
        }

        let log_pattern = format!("{}.{{}}", log_path.display());

        let size_trigger = SizeTrigger::new(10 * 1024 * 1024);
        if let Ok(fixed_window_roller) = FixedWindowRoller::builder().build(&log_pattern, 3) {
            let compound_policy =
                CompoundPolicy::new(Box::new(size_trigger), Box::new(fixed_window_roller));

            if let Ok(rolling_appender) = RollingFileAppender::builder()
                .encoder(Box::new(PatternEncoder::new(
                    "[{d(%Y-%m-%d %H:%M:%S)}] [{l}] {m}{n}",
                )))
                .build(log_path, Box::new(compound_policy))
            {
                if let Ok(config) = Config::builder()
                    .appender(Appender::builder().build("rolling_file", Box::new(rolling_appender)))
                    .build(
                        Root::builder()
                            .appender("rolling_file")
                            .build(LevelFilter::Info),
                    )
                {
                    if log4rs::init_config(config).is_ok() {
                        info!(
                            "Rolling log file configured: {:?} (max size: 10MB, keep: 3 files)",
                            log_path
                        );
                        return Ok(());
                    }
                }
            }
        }
    }

    Err("Failed to initialize rolling file logging".into())
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
