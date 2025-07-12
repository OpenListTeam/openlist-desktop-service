use std::{
    io::{self, Write},
    path::Path,
    process::Command,
};

use log::{error, info, warn};

#[cfg(target_os = "windows")]
pub fn get_current_user_session() -> io::Result<String> {
    let output = Command::new("powershell")
        .args(["-Command", r#"
            try {
                Add-Type -TypeDefinition @'
                    using System;
                    using System.Runtime.InteropServices;
                    public class WTS {
                        [DllImport("kernel32.dll")]
                        public static extern uint WTSGetActiveConsoleSessionId();
                    }
'@
                $sessionId = [WTS]::WTSGetActiveConsoleSessionId()
                if ($sessionId -gt 0 -and $sessionId -ne 0xFFFFFFFF) {
                    Write-Output $sessionId
                    exit 0
                }
            } catch {
                # Ignore API errors and continue to fallback
            }
            
            try {
                $explorerProcesses = Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -gt 0 }
                if ($explorerProcesses) {
                    # Get the session with the most recent explorer process
                    $latestExplorer = $explorerProcesses | Sort-Object StartTime -Descending | Select-Object -First 1
                    Write-Output $latestExplorer.SessionId
                    exit 0
                }
            } catch {
            }
            
            try {
                $queryOutput = query user 2>$null
                if ($queryOutput) {
                    $lines = $queryOutput -split "`n"
                    foreach ($line in $lines) {
                        if ($line -match '\s+(\d+)\s+Active') {
                            $sessionId = $matches[1]
                            if ([int]$sessionId -gt 0) {
                                Write-Output $sessionId
                                exit 0
                            }
                        }
                    }
                }
            } catch {
            }
            
            Write-Output 1
        "#])
        .output()?;

    if output.status.success() {
        let session_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !session_id.is_empty() && session_id != "0" {
            return Ok(session_id);
        }
    }

    let output = Command::new("query").args(["user"]).output()?;

    if output.status.success() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3
                && let Ok(session_id) = parts[2].parse::<u32>()
                && session_id > 0
            {
                return Ok(session_id.to_string());
            }
        }
    }

    warn!("Could not determine user session ID, using default session 1");
    Ok("1".to_string())
}

#[cfg(target_os = "windows")]
fn spawn_process_as_user(
    command: &str,
    args: &[&str],
    working_dir: &Path,
    mut log: std::fs::File,
) -> io::Result<u32> {
    let session_id = get_current_user_session().unwrap_or_else(|_| {
        warn!("Could not determine user session, using default session");
        "1".to_string()
    });

    info!("Attempting to start process in user session: {session_id}");

    let escaped_command = command;
    let escaped_args = args.join(" ");
    let escaped_working_dir = working_dir.display().to_string();

    let ps_command = format!(
        r#"
        Add-Type -TypeDefinition @'
            using System;
            using System.Runtime.InteropServices;
            using System.Diagnostics;
            using System.Security;
            using System.ComponentModel;
            
            public class ProcessStarter {{
                [DllImport("advapi32.dll", SetLastError = true)]
                public static extern bool CreateProcessAsUser(
                    IntPtr hToken,
                    string lpApplicationName,
                    string lpCommandLine,
                    IntPtr lpProcessAttributes,
                    IntPtr lpThreadAttributes,
                    bool bInheritHandles,
                    uint dwCreationFlags,
                    IntPtr lpEnvironment,
                    string lpCurrentDirectory,
                    ref STARTUPINFO lpStartupInfo,
                    out PROCESS_INFORMATION lpProcessInformation);
                
                [DllImport("kernel32.dll", SetLastError = true)]
                public static extern bool CloseHandle(IntPtr hObject);
                
                [DllImport("wtsapi32.dll", SetLastError = true)]
                public static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);
                
                [DllImport("advapi32.dll", SetLastError = true)]
                public static extern bool DuplicateTokenEx(
                    IntPtr hExistingToken,
                    uint dwDesiredAccess,
                    IntPtr lpTokenAttributes,
                    int ImpersonationLevel,
                    int TokenType,
                    out IntPtr phNewToken);
                
                [DllImport("userenv.dll", SetLastError = true)]
                public static extern bool CreateEnvironmentBlock(
                    out IntPtr lpEnvironment,
                    IntPtr hToken,
                    bool bInherit);
                
                [DllImport("userenv.dll", SetLastError = true)]
                public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
                
                private const uint TOKEN_DUPLICATE = 0x0002;
                private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
                private const uint TOKEN_QUERY = 0x0008;
                private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
                private const uint TOKEN_ADJUST_SESSIONID = 0x0100;
                private const int SecurityImpersonation = 2;
                private const int TokenPrimary = 1;
                private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
                private const uint NORMAL_PRIORITY_CLASS = 0x00000020;
                
                [StructLayout(LayoutKind.Sequential)]
                public struct STARTUPINFO {{
                    public int cb;
                    public string lpReserved;
                    public string lpDesktop;
                    public string lpTitle;
                    public int dwX;
                    public int dwY;
                    public int dwXSize;
                    public int dwYSize;
                    public int dwXCountChars;
                    public int dwYCountChars;
                    public int dwFillAttribute;
                    public int dwFlags;
                    public short wShowWindow;
                    public short cbReserved2;
                    public IntPtr lpReserved2;
                    public IntPtr hStdInput;
                    public IntPtr hStdOutput;
                    public IntPtr hStdError;
                }}
                
                [StructLayout(LayoutKind.Sequential)]
                public struct PROCESS_INFORMATION {{
                    public IntPtr hProcess;
                    public IntPtr hThread;
                    public int dwProcessId;
                    public int dwThreadId;
                }}
                
                public static int StartProcessInSession(uint sessionId, string executable, string arguments, string workingDirectory) {{
                    IntPtr userToken = IntPtr.Zero;
                    IntPtr duplicatedToken = IntPtr.Zero;
                    IntPtr environment = IntPtr.Zero;
                    
                    try {{
                        Console.WriteLine("Session ID: " + sessionId);
                        Console.WriteLine("Executable: " + executable);
                        Console.WriteLine("Arguments: " + arguments);
                        Console.WriteLine("Working Directory: " + workingDirectory);
                        
                        if (!System.IO.File.Exists(executable)) {{
                            throw new System.IO.FileNotFoundException("Executable not found: " + executable);
                        }}
                        
                        if (!WTSQueryUserToken(sessionId, out userToken)) {{
                            int error = Marshal.GetLastWin32Error();
                            throw new Win32Exception(error, "Failed to get user token for session " + sessionId + ". Error: " + error);
                        }}
                        
                        if (!DuplicateTokenEx(
                            userToken,
                            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_SESSIONID,
                            IntPtr.Zero,
                            SecurityImpersonation,
                            TokenPrimary,
                            out duplicatedToken)) {{
                            int error = Marshal.GetLastWin32Error();
                            throw new Win32Exception(error, "Failed to duplicate token. Error: " + error);
                        }}
                        
                        if (!CreateEnvironmentBlock(out environment, duplicatedToken, false)) {{
                            int error = Marshal.GetLastWin32Error();
                            throw new Win32Exception(error, "Failed to create environment block. Error: " + error);
                        }}
                        
                        STARTUPINFO startInfo = new STARTUPINFO();
                        startInfo.cb = Marshal.SizeOf(startInfo);
                        startInfo.lpDesktop = "winsta0\\default";
                        startInfo.wShowWindow = 0; // SW_HIDE
                        startInfo.dwFlags = 1; // STARTF_USESHOWWINDOW
                        
                        PROCESS_INFORMATION procInfo;
                        
                        string commandLine = string.IsNullOrEmpty(arguments) ? 
                            "\"" + executable + "\"" : 
                            "\"" + executable + "\" " + arguments;
                        
                        bool success = CreateProcessAsUser(
                            duplicatedToken,
                            executable,
                            commandLine,
                            IntPtr.Zero,
                            IntPtr.Zero,
                            false,
                            CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS,
                            environment,
                            workingDirectory,
                            ref startInfo,
                            out procInfo);
                        
                        if (!success) {{
                            int error = Marshal.GetLastWin32Error();
                            throw new Win32Exception(error, "Failed to create process as user. Executable: " + executable + ", Arguments: " + arguments + ", Working Dir: " + workingDirectory + ", Error: " + error);
                        }}
                        
                        int processId = procInfo.dwProcessId;
                        CloseHandle(procInfo.hProcess);
                        CloseHandle(procInfo.hThread);
                        
                        return processId;
                    }}
                    finally {{
                        if (environment != IntPtr.Zero) {{
                            DestroyEnvironmentBlock(environment);
                        }}
                        if (duplicatedToken != IntPtr.Zero) {{
                            CloseHandle(duplicatedToken);
                        }}
                        if (userToken != IntPtr.Zero) {{
                            CloseHandle(userToken);
                        }}
                    }}
                }}
            }}
'@
        
        try {{
            $executable = '{escaped_command}'
            $arguments = '{escaped_args}'
            $workingDir = '{escaped_working_dir}'
            $sessionId = {session_id}

            Write-Host "Debug: Executable path: $executable"
            Write-Host "Debug: Arguments: $arguments"
            Write-Host "Debug: Working directory: $workingDir"
            Write-Host "Debug: Session ID: $sessionId"
            
            if (-not (Test-Path $executable)) {{
                throw "Executable not found: $executable"
            }}
            
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            
            if (-not $isAdmin) {{
                Write-Warning "Running without administrator privileges - WTS API method will likely fail"
            }}
            
            $processId = [ProcessStarter]::StartProcessInSession($sessionId, $executable, $arguments, $workingDir)
            Write-Output $processId
            exit 0
        }}
        catch {{
            Write-Warning "Primary method failed: $($_.Exception.Message)"
            try {{
                $explorerProcess = Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object {{ $_.SessionId -eq $sessionId }} | Select-Object -First 1
                
                if (-not $explorerProcess) {{
                    Write-Host "No explorer in session $sessionId, looking for any interactive session..."
                    $explorerProcess = Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object {{ $_.SessionId -gt 0 }} | Select-Object -First 1
                    if ($explorerProcess) {{
                        Write-Host "Found explorer in session $($explorerProcess.SessionId), using that session"
                        $sessionId = $explorerProcess.SessionId
                    }}
                }}
                
                if (-not $explorerProcess) {{
                    throw "No explorer process found in any interactive session"
                }}
                
                $executable = '{escaped_command}'
                $arguments = '{escaped_args}'
                $workingDir = '{escaped_working_dir}'
                
                # Verify executable exists for fallback too
                if (-not (Test-Path $executable)) {{
                    throw "Executable not found: $executable"
                }}
                
                Write-Host "Using explorer session fallback method in session $sessionId"
                
                # Parse arguments into array for Start-Process, handling quoted arguments properly
                $argumentArray = @()
                if ($arguments) {{
                    # Simple split for now - could be improved to handle quoted arguments with spaces
                    $argumentArray = $arguments -split ' '
                }}
                
                $process = Start-Process -FilePath $executable -ArgumentList $argumentArray -WorkingDirectory $workingDir -WindowStyle Hidden -PassThru
                Write-Output $process.Id
                exit 0
            }}
            catch {{
                Write-Warning "Explorer session method failed: $($_.Exception.Message)"
                try {{
                    $executable = '{escaped_command}'
                    $arguments = '{escaped_args}'
                    $workingDir = '{escaped_working_dir}'
                    
                    if (-not (Test-Path $executable)) {{
                        throw "Executable not found: $executable"
                    }}
                    
                    Write-Host "Using simple fallback method (may run in current session context)"
                    
                    # Parse arguments into array for Start-Process, handling quoted arguments properly
                    $argumentArray = @()
                    if ($arguments) {{
                        # Simple split for now - could be improved to handle quoted arguments with spaces
                        $argumentArray = $arguments -split ' '
                    }}
                    
                    $process = Start-Process -FilePath $executable -ArgumentList $argumentArray -WorkingDirectory $workingDir -WindowStyle Hidden -PassThru
                    Write-Warning "Started process using simple fallback method - may run in service context"
                    Write-Output $process.Id
                    exit 0
                }}
                catch {{
                    throw "All methods failed to start process: $($_.Exception.Message)"
                }}
            }}
        }}
        "#
    );
    info!("Executing PowerShell command to start process in user session {session_id}");

    let timeout_ps_command = format!(
        r#"
        $timeoutSeconds = 30
        $job = Start-Job -ScriptBlock {{
            {ps_command}
        }}
        
        if (Wait-Job $job -Timeout $timeoutSeconds) {{
            $result = Receive-Job $job
            Remove-Job $job
            Write-Output $result
        }} else {{
            Remove-Job $job -Force
            throw "PowerShell command timed out after $timeoutSeconds seconds"
        }}
        "#
    );

    let output = Command::new("powershell")
        .args(["-Command", &timeout_ps_command])
        .current_dir(working_dir)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    info!("PowerShell stdout: {stdout}");
    if !stderr.is_empty() {
        info!("PowerShell stderr: {stderr}");
    }

    if output.status.success() {
        let output_text = String::from_utf8_lossy(&output.stdout);
        info!("Raw PowerShell output: {output_text}");

        let pid_str = output_text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.starts_with("WARNING:") || line.is_empty() {
                    return None;
                }
                if line.chars().all(|c| c.is_ascii_digit()) {
                    Some(line)
                } else {
                    None
                }
            })
            .next()
            .unwrap_or("")
            .to_string();

        match pid_str.parse::<u32>() {
            Ok(pid) => {
                info!(
                    "Process started successfully in user session {}, PID: {}, working dir: {}",
                    session_id,
                    pid,
                    working_dir.display()
                );

                let _ = writeln!(
                    log,
                    "Process started in user session {session_id}, PID: {pid}"
                );
                log.flush()?;

                match verify_process_user_context(pid) {
                    Ok(context_info) => {
                        info!("Process context verified: {context_info}");
                        let _ = writeln!(log, "Process context: {context_info}");
                    }
                    Err(e) => {
                        warn!("Could not verify process context: {e}");
                        let _ = writeln!(log, "Warning: Could not verify process context: {e}");
                    }
                }
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
        let stdout = String::from_utf8_lossy(&output.stdout);
        error!("Failed to start process in user session. Stderr: {stderr}");
        error!("PowerShell stdout: {stdout}");
        let _ = writeln!(
            log,
            "Failed to start process in user session. Stderr: {stderr}"
        );
        let _ = writeln!(log, "PowerShell stdout: {stdout}");
        log.flush()?;
        Err(io::Error::other(format!(
            "Failed to start process in user session. Stderr: {stderr}"
        )))
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

#[cfg(target_os = "windows")]
pub fn verify_process_user_context(pid: u32) -> io::Result<String> {
    let ps_command = format!(
        "
        try {{
            # Get process information using Get-Process
            $process = Get-Process -Id {pid} -ErrorAction Stop
            
            # Get owner information using WMI
            $wmiProcess = Get-WmiObject -Class Win32_Process -Filter \"ProcessId = {pid}\" -ErrorAction Stop
            $owner = $wmiProcess.GetOwner()
            $ownerInfo = \"Unknown\"
            if ($owner.ReturnValue -eq 0) {{
                $ownerInfo = \"$($owner.Domain)\\$($owner.User)\"
            }}
            
            Write-Output \"PID: {pid} | Owner: $ownerInfo | Session: $($process.SessionId) | Process: $($process.ProcessName)\"
        }}
        catch {{
            Write-Output \"Error getting process info: $($_.Exception.Message)\"
        }}
        "
    );

    let output = Command::new("powershell")
        .args(["-Command", &ps_command])
        .output()?;

    if output.status.success() {
        let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
        info!("Process context verification: {result}");
        Ok(result)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to verify process context: {stderr}");
        Err(io::Error::other(format!(
            "Failed to verify process context: {stderr}"
        )))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn verify_process_user_context(pid: u32) -> io::Result<String> {
    let output = Command::new("ps")
        .args(["-o", "pid,user,uid", "-p", &pid.to_string()])
        .output()?;

    if output.status.success() {
        let result = String::from_utf8_lossy(&output.stdout);
        info!("Process context verification: {}", result);
        Ok(result.to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to verify process context: {}", stderr);
        Err(io::Error::other(format!(
            "Failed to verify process context: {stderr}"
        )))
    }
}
