use anyhow::Error;
use std::fmt::Write;

const COLOR_BLUE: &str = "\x1b[34m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";
const COLOR_YELLOW: &str = "\x1b[33m";
const COLOR_CYAN: &str = "\x1b[36m";
const COLOR_RESET: &str = "\x1b[0m";
const COLOR_BOLD: &str = "\x1b[1m";

fn should_use_colors() -> bool {
    std::env::var("NO_COLOR").is_err()
        && std::env::var("CI").is_err()
        && std::env::var("TERM").unwrap_or_default() != "dumb"
}

#[inline]
fn get_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[inline]
fn format_duration_ms(duration: std::time::Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn print_box_header(title: &str, color: &str, use_colors: bool) {
    if use_colors {
        println!("\n{}{}╭─ {} ─{}", COLOR_BOLD, color, title, COLOR_RESET);
    } else {
        println!("\n╭─ {} ─", title);
    }
}

fn print_box_footer(color: &str, use_colors: bool) {
    if use_colors {
        println!(
            "{}{}╰─────────────────────────────────────{}",
            color, COLOR_BOLD, COLOR_RESET
        );
    } else {
        println!("╰─────────────────────────────────────");
    }
}

fn print_box_line(
    icon: &str,
    label: &str,
    value: &str,
    color: &str,
    value_color: &str,
    use_colors: bool,
) {
    if use_colors {
        println!(
            "{}{}│ {} {}: {}{}{}{}",
            color, COLOR_BOLD, icon, label, value_color, value, color, COLOR_RESET
        );
    } else {
        println!("│ {}: {}", label, value);
    }
}

pub fn run_command(cmd: &str, args: &[&str]) -> Result<(), Error> {
    let command_str = format_command(cmd, args);

    print_command_start(&command_str);

    let start_time = std::time::Instant::now();
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute '{}': {}", cmd, e))?;
    let execution_time = start_time.elapsed();

    if !output.status.success() {
        handle_command_failure(&output, &command_str, execution_time)
    } else {
        print_command_success(&command_str, execution_time);
        Ok(())
    }
}

#[inline]
fn format_command(cmd: &str, args: &[&str]) -> String {
    if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{} {}", cmd, args.join(" "))
    }
}

fn print_command_start(command_str: &str) {
    let timestamp = get_timestamp();
    let use_colors = should_use_colors();

    print_box_header("COMMAND EXECUTION START", COLOR_BLUE, use_colors);
    print_box_line(
        "🕒",
        "Timestamp",
        &timestamp.to_string(),
        COLOR_BLUE,
        COLOR_BLUE,
        use_colors,
    );
    print_box_line(
        "📋",
        "Command",
        command_str,
        COLOR_BLUE,
        COLOR_CYAN,
        use_colors,
    );
    print_box_footer(COLOR_BLUE, use_colors);
}

fn print_command_success(command_str: &str, execution_time: std::time::Duration) {
    let timestamp = get_timestamp();
    let duration_ms = format_duration_ms(execution_time);
    let use_colors = should_use_colors();

    print_box_header("COMMAND SUCCESS", COLOR_GREEN, use_colors);
    print_box_line(
        "🕒",
        "Timestamp",
        &timestamp.to_string(),
        COLOR_GREEN,
        COLOR_GREEN,
        use_colors,
    );
    print_box_line(
        "⚡",
        "Duration",
        &format!("{:.3}ms", duration_ms),
        COLOR_GREEN,
        COLOR_GREEN,
        use_colors,
    );
    print_box_line(
        "✅",
        "Command",
        command_str,
        COLOR_GREEN,
        COLOR_CYAN,
        use_colors,
    );
    print_box_footer(COLOR_GREEN, use_colors);
}

fn handle_command_failure(
    output: &std::process::Output,
    command_str: &str,
    execution_time: std::time::Duration,
) -> Result<(), Error> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    print_command_failure_debug(
        command_str,
        &output.status,
        &stdout,
        &stderr,
        execution_time,
    );

    let mut error_msg = String::with_capacity(256);
    let _ = writeln!(error_msg, "Command execution failed:");
    let _ = writeln!(error_msg, "Command: {}", command_str);
    let _ = writeln!(error_msg, "Status: {}", output.status);
    let _ = writeln!(
        error_msg,
        "Duration: {:.3}ms",
        execution_time.as_secs_f64() * 1000.0
    );
    let _ = writeln!(error_msg, "stdout: {}", stdout);
    let _ = write!(error_msg, "stderr: {}", stderr);

    Err(anyhow::anyhow!(error_msg))
}

fn print_command_failure_debug(
    command_str: &str,
    status: &std::process::ExitStatus,
    stdout: &str,
    stderr: &str,
    execution_time: std::time::Duration,
) {
    let timestamp = get_timestamp();
    let duration_ms = format_duration_ms(execution_time);
    let use_colors = should_use_colors();

    print_box_header("COMMAND EXECUTION FAILED", COLOR_RED, use_colors);
    print_box_line(
        "🕒",
        "Timestamp",
        &timestamp.to_string(),
        COLOR_RED,
        COLOR_RED,
        use_colors,
    );
    print_box_line(
        "⚡",
        "Duration",
        &format!("{:.3}ms", duration_ms),
        COLOR_RED,
        COLOR_RED,
        use_colors,
    );
    print_box_line(
        "📋",
        "Command",
        command_str,
        COLOR_RED,
        COLOR_CYAN,
        use_colors,
    );
    print_box_line(
        "❌",
        "Exit Code",
        &status.to_string(),
        COLOR_RED,
        COLOR_YELLOW,
        use_colors,
    );

    if use_colors {
        eprintln!(
            "{}{}├─────────────────────────────────────{}",
            COLOR_RED, COLOR_BOLD, COLOR_RESET
        );
    } else {
        eprintln!("├─────────────────────────────────────");
    }

    if !stdout.is_empty() {
        print_output_section("📤 STDOUT OUTPUT", stdout, COLOR_GREEN, use_colors);
    }

    if !stderr.is_empty() {
        print_output_section("📥 STDERR OUTPUT", stderr, COLOR_RED, use_colors);
    }

    print_debug_hints_section(status, stderr, use_colors);

    if use_colors {
        eprintln!(
            "{}{}╰─────────────────────────────────────{}\n",
            COLOR_RED, COLOR_BOLD, COLOR_RESET
        );
    } else {
        eprintln!("╰─────────────────────────────────────\n");
    }
}

fn print_output_section(title: &str, output: &str, color: &str, use_colors: bool) {
    if use_colors {
        eprintln!("{}{}│ {}:{}", color, COLOR_BOLD, title, COLOR_RESET);
    } else {
        eprintln!("│ {}:", title);
    }

    for (i, line) in output.lines().enumerate() {
        let line_num = format!("{:>3}", i + 1);
        if use_colors {
            eprintln!(
                "{}{}│ {} │ {}{}{}",
                color, COLOR_BOLD, line_num, COLOR_RESET, line, color
            );
        } else {
            eprintln!("│ {} │ {}", line_num, line);
        }
    }

    if use_colors {
        eprintln!(
            "{}{}├─────────────────────────────────────{}",
            COLOR_RED, COLOR_BOLD, COLOR_RESET
        );
    } else {
        eprintln!("├─────────────────────────────────────");
    }
}

fn print_debug_hints_section(status: &std::process::ExitStatus, stderr: &str, use_colors: bool) {
    if use_colors {
        eprintln!(
            "{}{}│ 💡 DEBUGGING HINTS:{}",
            COLOR_YELLOW, COLOR_BOLD, COLOR_RESET
        );
    } else {
        eprintln!("│ DEBUGGING HINTS:");
    }

    print_debug_hints(status, stderr, use_colors);
}

fn print_debug_hints(status: &std::process::ExitStatus, stderr: &str, use_colors: bool) {
    let hint_prefix = if use_colors {
        format!("{}{}│    • ", COLOR_YELLOW, COLOR_BOLD)
    } else {
        "│    • ".to_string()
    };
    let reset = if use_colors { COLOR_RESET } else { "" };

    if let Some(code) = status.code() {
        let hint = match code {
            1 => "General error",
            2 => "Misuse of shell builtins",
            126 => "Command cannot execute",
            127 => "Command not found",
            130 => "Script terminated by Ctrl+C",
            _ => {
                return eprintln!(
                    "{}Exit code {}: Check command documentation{}",
                    hint_prefix, code, reset
                );
            }
        };
        eprintln!("{}{}{}", hint_prefix, hint, reset);
    }

    let error_hints = [
        (
            ["permission denied", "Permission denied"],
            "Try running with elevated privileges",
        ),
        (
            ["not found", "No such file"],
            "Check if the command/file exists and is in PATH",
        ),
        (
            ["timeout", "Timeout"],
            "Command timed out - consider increasing timeout or optimizing",
        ),
        (
            ["network", "connection"],
            "Network connectivity issue - check internet connection",
        ),
    ];

    for (patterns, hint) in error_hints {
        if patterns.iter().any(|pattern| stderr.contains(pattern)) {
            eprintln!("{}{}{}", hint_prefix, hint, reset);
        }
    }
}

#[cfg(target_os = "macos")]
pub fn uninstall_old_service() -> Result<(), Error> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn detect_linux_init_system() -> &'static str {
    use std::path::Path;

    if Path::new("/sbin/openrc").exists() || Path::new("/usr/bin/rc-update").exists() {
        "openrc"
    } else if Path::new("/bin/systemctl").exists() || Path::new("/usr/bin/systemctl").exists() {
        "systemd"
    } else {
        "unknown"
    }
}
