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
