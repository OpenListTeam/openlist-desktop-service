use std::{
    io::{self, Write},
    path::Path,
    process::Command,
};

use log::{error, info, warn};

#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
#[cfg(target_os = "windows")]
use windows::Win32::Security::{
    DuplicateTokenEx, SECURITY_ATTRIBUTES, SecurityImpersonation, TOKEN_ALL_ACCESS,
    TOKEN_ASSIGN_PRIMARY, TokenPrimary,
};
#[cfg(target_os = "windows")]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
#[cfg(target_os = "windows")]
use windows::Win32::System::RemoteDesktop::{
    WTS_SESSION_INFOA, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSGetActiveConsoleSessionId, WTSQueryUserToken,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, NORMAL_PRIORITY_CLASS,
    PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOW,
};
#[cfg(target_os = "windows")]
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
#[cfg(target_os = "windows")]
use windows::core::{PCWSTR, PWSTR};

#[cfg(target_os = "windows")]
pub fn get_active_session_id() -> io::Result<u32> {
    unsafe {
        let session_id = WTSGetActiveConsoleSessionId();
        if session_id != u32::MAX && session_id != 0 {
            return Ok(session_id);
        }
        let mut p_sessions = ptr::null_mut();
        let mut count = 0;
        if WTSEnumerateSessionsW(None, 0, 1, &mut p_sessions, &mut count).is_ok() {
            let sessions =
                std::slice::from_raw_parts(p_sessions as *const WTS_SESSION_INFOA, count as usize);
            for info in sessions {
                if info.State == WTSActive {
                    let sid = info.SessionId;
                    WTSFreeMemory(p_sessions as _);
                    return Ok(sid);
                }
            }
            WTSFreeMemory(p_sessions as _);
        }
        log::warn!("No active session found, defaulting to session 1");
        Ok(1)
    }
}

#[cfg(target_os = "windows")]
pub fn spawn_process_as_user(
    command: &str,
    args: &[&str],
    working_dir: &std::path::Path,
    log_file: std::fs::File,
) -> io::Result<u32> {
    unsafe {
        use windows::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
        let session_id = get_active_session_id()?;
        log::info!("Starting process in session {session_id}");

        let mut user_token: HANDLE = HANDLE::default();
        let ok = WTSQueryUserToken(session_id, &mut user_token);
        if ok.is_err() {
            let err = io::Error::last_os_error();
            log::error!("WTSQueryUserToken failed: {err}");
            return Err(err);
        }

        let mut primary_token: HANDLE = HANDLE::default();
        let sa: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: false.into(),
        };
        let dup_ok = DuplicateTokenEx(
            user_token,
            TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS,
            Some(&sa),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_token,
        );
        let _ = CloseHandle(user_token);
        if dup_ok.is_err() {
            let err = io::Error::last_os_error();
            log::error!("DuplicateTokenEx failed: {err}");
            return Err(err);
        }

        let mut env_block: *mut core::ffi::c_void = ptr::null_mut();
        if CreateEnvironmentBlock(&mut env_block, Some(primary_token), false).is_err() {
            let err_code = GetLastError();
            log::warn!(
                "CreateEnvironmentBlock failed (error {}), proceeding without custom env",
                err_code.0
            );
            env_block = ptr::null_mut();
        }

        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let log_handle = HANDLE(log_file.as_raw_handle() as _);
        let _ = SetHandleInformation(log_handle, 1u32, HANDLE_FLAG_INHERIT);
        let working_dir_w: Vec<u16> = working_dir
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0)) // null terminator
            .collect();
        let nul_str: Vec<u16> = OsStr::new("NUL")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let nul_handle = CreateFileW(
            PCWSTR(nul_str.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&sa),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        );
        match nul_handle {
            Ok(handle) => {
                startup_info.hStdInput = handle;
            }
            Err(_) => {
                startup_info.hStdInput = HANDLE::default();
            }
        }
        startup_info.hStdOutput = log_handle;
        startup_info.hStdError = log_handle;
        startup_info.dwFlags |= STARTF_USESTDHANDLES;
        startup_info.dwFlags |= STARTF_USESHOWWINDOW;
        startup_info.wShowWindow = SW_HIDE.0 as u16;

        let mut cmdline = format!("\"{command}\"");
        for arg in args {
            if arg.contains(' ') {
                cmdline.push_str(&format!(" \"{arg}\"",));
            } else {
                cmdline.push_str(&format!(" {arg}"));
            }
        }
        let mut cmdline_w: Vec<u16> = OsStr::new(&cmdline)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();
        let create_ok = CreateProcessAsUserW(
            Some(primary_token),
            None,
            Some(PWSTR(cmdline_w.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS,
            Some(env_block as *mut _),
            PCWSTR(working_dir_w.as_ptr()),
            &startup_info,
            &mut proc_info,
        );
        if !env_block.is_null() {
            let _ = DestroyEnvironmentBlock(env_block);
        }
        let _ = CloseHandle(primary_token);

        if create_ok.is_err() {
            let err = io::Error::last_os_error();
            log::error!("CreateProcessAsUserW failed: {err}");
            return Err(err);
        }
        let pid = proc_info.dwProcessId;
        let _ = CloseHandle(proc_info.hProcess);
        let _ = CloseHandle(proc_info.hThread);
        log::info!("Process started successfully in session {session_id}, PID: {pid}");
        Ok(pid)
    }
}

#[cfg(target_os = "windows")]
pub fn is_process_running(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let check_output = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}")])
        .output();

    match check_output {
        Ok(output) => {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                output_str.contains(&pid.to_string())
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn is_process_running(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let check_process = Command::new("ps").args(["-p", &pid.to_string()]).output();

    match check_process {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn ensure_executable_permissions(binary_path: &str) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let path = Path::new(binary_path);
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Binary not found: {binary_path}"),
        ));
    }

    let metadata = std::fs::metadata(path)?;
    let permissions = metadata.permissions();
    let current_mode = permissions.mode();

    if current_mode & 0o100 == 0 {
        info!("Binary {binary_path} does not have execute permissions, adding them");

        let new_mode = current_mode | 0o755;
        let mut new_permissions = permissions;
        new_permissions.set_mode(new_mode);

        std::fs::set_permissions(path, new_permissions)?;
        info!("Successfully added execute permissions to {binary_path}");
    } else {
        info!("Binary {binary_path} already has execute permissions");
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn ensure_executable_permissions(_binary_path: &str) -> io::Result<()> {
    Ok(())
}

fn get_working_directory(command: &str) -> &Path {
    let command_path = Path::new(command);
    if command_path.is_absolute()
        && let Some(parent) = command_path.parent()
    {
        info!(
            "Using working directory from command path: {}",
            parent.display()
        );
        return parent;
    }

    warn!("Could not determine working directory from command path, using current directory");
    Path::new(".")
}

pub fn spawn_process_with_privileges(
    command: &str,
    args: &[&str],
    mut log: std::fs::File,
    run_as_admin: bool,
) -> io::Result<u32> {
    let _ = writeln!(
        log,
        "Spawning process: {} {} (admin: {})",
        command,
        args.join(" "),
        run_as_admin
    );
    log.flush()?;

    info!(
        "Starting process: {} {} (admin: {})",
        command,
        args.join(" "),
        run_as_admin
    );

    let working_dir = get_working_directory(command);
    info!("Setting working directory to: {}", working_dir.display());

    #[cfg(target_os = "windows")]
    {
        if run_as_admin {
            info!("Running process with administrator privileges on Windows");
            let escaped_args = args
                .iter()
                .map(|arg| format!("'{}'", arg.replace("'", "''")))
                .collect::<Vec<_>>()
                .join(", ");

            let ps_command = if args.is_empty() {
                format!(
                    "$process = Start-Process -FilePath '{command}' -Verb RunAs -WindowStyle Hidden -PassThru; $process.Id"
                )
            } else {
                format!(
                    "$process = Start-Process -FilePath '{command}' -ArgumentList @({escaped_args}) -Verb RunAs -WindowStyle Hidden -PassThru; $process.Id"
                )
            };

            let output = Command::new("powershell")
                .args(["-Command", &ps_command])
                .current_dir(working_dir)
                .output()?;

            if output.status.success() {
                let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                match pid_str.parse::<u32>() {
                    Ok(pid) => {
                        info!(
                            "Child process started successfully with admin privileges, PID: {}, working dir: {}",
                            pid,
                            working_dir.display()
                        );

                        let _ =
                            writeln!(log, "Process started with elevated privileges, PID: {pid}");
                        log.flush()?;

                        Ok(pid)
                    }
                    Err(e) => {
                        error!("Failed to parse PID from PowerShell output '{pid_str}': {e}");
                        let _ = writeln!(log, "Failed to parse PID from PowerShell output: {e}");
                        log.flush()?;
                        Err(io::Error::other(format!("Failed to parse PID: {e}")))
                    }
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!("Failed to start process with admin privileges: {stderr}");
                let _ = writeln!(
                    log,
                    "Failed to start process with admin privileges: {stderr}"
                );
                log.flush()?;
                Err(io::Error::other(format!(
                    "Failed to start elevated process: {stderr}"
                )))
            }
        } else {
            info!("Running process as logged-in user on Windows (avoiding SYSTEM context)");
            spawn_process_as_user(command, args, working_dir, log)
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Stdio;
        let mut command_to_run = command.to_string();
        let mut args_to_run = args.to_vec();
        let log_for_stderr = log.try_clone()?;

        if run_as_admin {
            info!("Running process with root privileges on Linux using sudo");
            // Check if sudo is available
            if Command::new("which")
                .arg("sudo")
                .output()
                .is_ok_and(|o| o.status.success())
            {
                args_to_run.insert(0, command);
                command_to_run = "sudo".to_string();
            } else {
                warn!("sudo not available, running without elevated privileges");
            }
        } else {
            info!("Running process without elevated privileges on Linux");
        }
        let child = Command::new(&command_to_run)
            .args(&args_to_run)
            .current_dir(working_dir)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_for_stderr))
            .spawn()?;

        let pid = child.id();
        info!(
            "Child process started successfully, PID: {}, working dir: {}",
            pid,
            working_dir.display()
        );

        Ok(pid)
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Stdio;
        let mut command_to_run = command.to_string();
        let mut args_to_run = args.to_vec();
        let log_for_stderr = log.try_clone()?;
        if run_as_admin {
            info!("Running process with administrator privileges on macOS using sudo");
            // Check if sudo is available
            if Command::new("which")
                .arg("sudo")
                .output()
                .is_ok_and(|o| o.status.success())
            {
                args_to_run.insert(0, command);
                command_to_run = "sudo".to_string();
            } else {
                warn!("sudo not available, running without elevated privileges");
            }
        } else {
            info!("Running process without elevated privileges on macOS");
        }

        let child = Command::new(&command_to_run)
            .args(&args_to_run)
            .current_dir(working_dir)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_for_stderr))
            .spawn()?;

        let pid = child.id();
        info!(
            "Child process started successfully, PID: {}, working dir: {}",
            pid,
            working_dir.display()
        );

        std::thread::spawn(move || {
            let _ = child.wait_with_output();
        });

        Ok(pid)
    }
}

#[cfg(target_os = "windows")]
pub fn kill_process(pid: u32) -> io::Result<()> {
    info!("Attempting to terminate process PID {pid} with administrator privileges");
    let check_output = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}")])
        .output()?;

    if !check_output.status.success() {
        info!("Process PID {pid} does not exist, skipping termination");
        return Ok(());
    }

    let output_str = String::from_utf8_lossy(&check_output.stdout);
    if !output_str.contains(&pid.to_string()) {
        info!("Process PID {pid} does not exist, skipping termination");
        return Ok(());
    }

    let ps_command = format!(
        "Start-Process -FilePath 'taskkill' -ArgumentList @('/F', '/PID', '{pid}') -Verb RunAs -WindowStyle Hidden -Wait"
    );

    let output = Command::new("powershell")
        .args(["-Command", &ps_command])
        .output()?;
    info!("output: {output:?}");

    if output.status.success() {
        info!("Successfully terminated process PID {pid} with administrator privileges");
        Ok(())
    } else {
        error!("Failed to terminate process PID {pid} with administrator privileges:");
        Err(io::Error::other(format!(
            "Process termination with admin privileges failed: {pid}"
        )))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn kill_process(pid: u32) -> io::Result<()> {
    info!("Attempting to terminate process PID {pid} with elevated privileges");

    let check_process = Command::new("ps").args(["-p", &pid.to_string()]).output()?;
    if !check_process.status.success() {
        info!("Process PID {pid} does not exist, skipping termination");
        return Ok(());
    }

    info!("Sending SIGINT signal to process PID {pid} with sudo");
    let kill_int_args = &["-2", &pid.to_string()];
    let output = Command::new("sudo")
        .arg("kill")
        .args(kill_int_args)
        .output()?;

    if output.status.success() {
        info!("Successfully sent SIGINT signal to process PID {pid} with sudo");
        std::thread::sleep(std::time::Duration::from_millis(1000));

        let check_process = Command::new("ps").args(["-p", &pid.to_string()]).output()?;

        if !check_process.status.success() {
            return Ok(());
        }

        warn!(
            "Process {pid} did not terminate after receiving SIGINT, attempting to send SIGKILL with sudo"
        );
    } else {
        warn!(
            "Failed to send SIGINT to process PID {pid} with sudo, attempting to send SIGKILL with sudo"
        );
    }

    info!("Sending SIGKILL signal to process PID {pid} with sudo");
    let kill_kill_args = &["-9", &pid.to_string()];
    let output = Command::new("sudo")
        .arg("kill")
        .args(kill_kill_args)
        .output()?;

    let stderr = if !output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from("")
    };

    if output.status.success() {
        info!("Successfully terminated process PID {pid} using SIGKILL with sudo");
        Ok(())
    } else {
        error!(
            "Failed to terminate process PID {pid} using SIGKILL with sudo: {}",
            stderr.trim()
        );
        Err(io::Error::other(format!(
            "Kill command with sudo failed: {}",
            stderr.trim()
        )))
    }
}
