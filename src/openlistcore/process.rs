use std::{
    io::{self, Write},
    path::Path,
    process::{Command, Stdio},
};

use log::{debug, error, info, warn};

#[cfg(not(target_os = "windows"))]
pub fn ensure_executable_permissions(binary_path: &str) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let path = Path::new(binary_path);
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Binary not found: {}", binary_path),
        ));
    }

    let metadata = std::fs::metadata(path)?;
    let permissions = metadata.permissions();
    let current_mode = permissions.mode();

    if current_mode & 0o100 == 0 {
        info!(
            "Binary {} does not have execute permissions, adding them",
            binary_path
        );

        let new_mode = current_mode | 0o755;
        let mut new_permissions = permissions;
        new_permissions.set_mode(new_mode);

        std::fs::set_permissions(path, new_permissions)?;
        info!("Successfully added execute permissions to {}", binary_path);
    } else {
        debug!("Binary {} already has execute permissions", binary_path);
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

pub fn spawn_process(command: &str, args: &[&str], mut log: std::fs::File) -> io::Result<u32> {
    let _ = writeln!(log, "Spawning process: {} {}", command, args.join(" "));
    log.flush()?;

    info!("Starting process: {} {}", command, args.join(" "));

    let working_dir = get_working_directory(command);

    info!("Setting working directory to: {}", working_dir.display());

    let log_for_stderr = log.try_clone()?;

    #[cfg(target_os = "macos")]
    {
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

        std::thread::spawn(move || {
            let _ = child.wait_with_output();
        });

        Ok(pid)
    }

    #[cfg(not(target_os = "macos"))]
    {
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

#[cfg(target_os = "windows")]
pub fn kill_process(pid: u32) -> io::Result<()> {
    info!("Attempting to terminate process PID {}", pid);

    let taskkill_args = &["/F", "/PID", &pid.to_string()];

    let output = Command::new("taskkill").args(taskkill_args).output()?;

    let stderr = if !output.stderr.is_empty() {
        let (cow, _encoding_used, _had_errors) = encoding_rs::GBK.decode(&output.stderr);
        cow.into_owned()
    } else {
        String::from("")
    };

    if output.status.success() {
        info!("Successfully terminated process PID {}", pid);
        Ok(())
    } else {
        error!("Failed to terminate process PID {}: {}", pid, stderr.trim());
        Err(io::Error::other(format!(
            "Process termination failed: {}",
            stderr.trim()
        )))
    }
}

#[cfg(target_os = "windows")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    debug!("Searching for process: {}", process_name);

    let output = Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()?;

    let output_str = if !output.stdout.is_empty() {
        let (cow, _encoding_used, _had_errors) = encoding_rs::GBK.decode(&output.stdout);
        cow.into_owned()
    } else {
        String::from("")
    };

    let mut pids = Vec::new();

    for line in output_str.lines() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 2 {
            let name = parts[0].trim_matches('"');
            if name.to_lowercase().contains(&process_name.to_lowercase()) {
                if let Some(pid_str) = parts[1].trim_matches('"').split_whitespace().next() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        pids.push(pid);
                    }
                }
            }
        }
    }

    info!("Found {} matching processes: {}", pids.len(), process_name);

    Ok(pids)
}

#[cfg(target_os = "linux")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    debug!("Searching for process: {}", process_name);

    let output = Command::new("pgrep").arg("-f").arg(process_name).output()?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();

    for line in output_str.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            pids.push(pid);
        }
    }

    info!("Found {} matching processes: {}", pids.len(), process_name);

    Ok(pids)
}

#[cfg(target_os = "macos")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    debug!("Searching for process: {}", process_name);

    let output = Command::new("pgrep").arg("-f").arg(process_name).output()?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();

    for line in output_str.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            pids.push(pid);
        }
    }

    info!("Found {} matching processes: {}", pids.len(), process_name);

    Ok(pids)
}

#[cfg(not(target_os = "windows"))]
pub fn kill_process(pid: u32) -> io::Result<()> {
    info!(
        "Attempting to send SIGINT (kill -2) signal to process PID {}",
        pid
    );

    // SIGINT
    let kill_int_args = &["-2", &pid.to_string()];
    let output = Command::new("kill").args(kill_int_args).output()?;

    if output.status.success() {
        info!("Successfully sent SIGINT signal to process PID {}", pid);
        std::thread::sleep(std::time::Duration::from_millis(1000));

        let check_process = Command::new("ps")
            .args(&["-p", &pid.to_string()])
            .output()?;

        if !check_process.status.success() {
            return Ok(());
        }

        warn!(
            "Process {} did not terminate after receiving SIGINT, attempting to send SIGKILL",
            pid
        );
    } else {
        warn!(
            "Failed to send SIGINT to process PID {}, attempting to send SIGKILL",
            pid
        );
    }

    // SIGKILL
    let kill_kill_args = &["-9", &pid.to_string()];
    let output = Command::new("kill").args(kill_kill_args).output()?;

    let stderr = if !output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from("")
    };

    if output.status.success() {
        info!("Successfully terminated process PID {} using SIGKILL", pid);
        Ok(())
    } else {
        error!(
            "Failed to terminate process PID {} using SIGKILL: {}",
            pid,
            stderr.trim()
        );
        Err(io::Error::other(format!(
            "Kill command failed: {}",
            stderr.trim()
        )))
    }
}
