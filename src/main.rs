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
use std::path::PathBuf;

const SERVICE_NAME: &str = "OpenList Desktop Service";

// Get user data directory for log files, consistent with desktop main repo
fn get_user_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME").ok().map(|home| {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("io.github.openlistteam.openlist.service.bundle")
                .join("Contents")
                .join("MacOS")
        })
    }

    #[cfg(target_os = "linux")]
    {
        std::env::var("HOME").ok().map(|home| {
            PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("OpenList Desktop")
        })
    }

    #[cfg(target_os = "windows")]
    {
        // Get the actual logged-in user's APPDATA path
        // Use WTS API to find active user session and expand environment variables in that context
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Environment::ExpandEnvironmentStringsForUserW;
        use windows::Win32::System::RemoteDesktop::{
            WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW,
            WTSFreeMemory, WTSQueryUserToken,
        };
        use windows::core::PWSTR;

        unsafe {
            let mut session_info_ptr = std::ptr::null_mut();
            let mut session_count = 0u32;

            // Enumerate all sessions to find active user session
            if WTSEnumerateSessionsW(
                Some(WTS_CURRENT_SERVER_HANDLE),
                0,
                1,
                &mut session_info_ptr,
                &mut session_count,
            )
            .is_ok()
            {
                let sessions = std::slice::from_raw_parts(
                    session_info_ptr as *const WTS_SESSION_INFOW,
                    session_count as usize,
                );

                // Find the first active session
                for session in sessions {
                    if session.State == WTSActive {
                        let mut token = HANDLE::default();

                        // Get user token for this session
                        if WTSQueryUserToken(session.SessionId, &mut token).is_ok() {
                            // Expand %APPDATA% in the context of this user
                            let template = "%APPDATA%\\OpenList Desktop\0";
                            let template_wide: Vec<u16> = template.encode_utf16().collect();
                            let mut buffer = vec![0u16; 512];

                            let result = ExpandEnvironmentStringsForUserW(
                                Some(token),
                                PWSTR(template_wide.as_ptr() as *mut u16),
                                &mut buffer,
                            );

                            let _ = windows::Win32::Foundation::CloseHandle(token);

                            if result.is_ok() {
                                // Find the null terminator
                                if let Some(null_pos) = buffer.iter().position(|&c| c == 0) {
                                    let path_str = String::from_utf16_lossy(&buffer[..null_pos]);
                                    WTSFreeMemory(session_info_ptr as _);
                                    return Some(PathBuf::from(path_str));
                                }
                            }
                        }
                    }
                }

                WTSFreeMemory(session_info_ptr as _);
            }

            // Fallback: try environment variable (works for non-service context)
            std::env::var("APPDATA")
                .ok()
                .map(|appdata| PathBuf::from(appdata).join("OpenList Desktop"))
        }
    }
}

fn setup_log_file() -> Result<(), Box<dyn std::error::Error>> {
    let log_paths = [
        get_user_data_dir().map(|dir| dir.join("openlist-desktop-service.log")),
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|p| p.join("openlist-desktop-service.log"))),
        Some(PathBuf::from("openlist-desktop-service.log")),
        Some(std::env::temp_dir().join("openlist-desktop-service.log")),
    ];
    for log_path in log_paths.iter().flatten() {
        if let Some(parent) = log_path.parent()
            && std::fs::create_dir_all(parent).is_err()
        {
            continue;
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
                && let Ok(config) = Config::builder()
                    .appender(Appender::builder().build("rolling_file", Box::new(rolling_appender)))
                    .build(
                        Root::builder()
                            .appender("rolling_file")
                            .build(LevelFilter::Info),
                    )
                && log4rs::init_config(config).is_ok()
            {
                info!("Rolling log file configured: {log_path:?} (max size: 10MB, keep: 3 files)");
                return Ok(());
            }
        }
    }

    Err("Failed to initialize rolling file logging".into())
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    let _ = setup_log_file();
    info!("Starting {SERVICE_NAME}");
    openlistcore::main()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    let _ = setup_log_file();
    info!("Starting {SERVICE_NAME}");
    openlistcore::main();
}
