use std::{
    io::{self, Write},
    path::Path,
    process::{Command, Stdio},
};

use log::{error, info, warn};

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
    if command_path.is_absolute() {
        if let Some(parent) = command_path.parent() {
            info!(
                "Using working directory from command path: {}",
                parent.display()
            );
            return parent;
        }
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

    let log_for_stderr = log.try_clone()?;
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
            info!("Running process without administrator privileges on Windows");
            let child = Command::new(command)
                .args(args)
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
    }
    #[cfg(target_os = "linux")]
    {
        let mut command_to_run = command.to_string();
        let mut args_to_run = args.to_vec();

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
        let mut command_to_run = command.to_string();
        let mut args_to_run = args.to_vec();

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
