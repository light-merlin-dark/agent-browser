//! Stale daemon entry reaper.
//!
//! Every daemon writes a `<session>.pid` file into the socket directory and,
//! on unix, binds `<session>.sock` (plus optional `.stream`/`.port` files).
//! When a daemon dies without cleanup (crash, `kill -9`, machine reboot) its
//! entries linger forever. This module sweeps them. It runs automatically on
//! every daemon startup and on every client `ensure_daemon` call, and is
//! exposed manually via `agent-browser reap`.
//!
//! Safety rule: an entry is only removed when its recorded PID is verifiably
//! dead, or when the PID is alive but verifiably belongs to a different
//! program (PID reuse). Any doubt means the entry is kept.

use std::fs;
use std::path::Path;

/// File extensions a daemon session can leave in the socket directory.
const ENTRY_EXTENSIONS: [&str; 4] = ["pid", "sock", "stream", "port"];

/// Outcome of a sweep, for reporting by the `reap` command.
#[derive(Default)]
pub struct ReapReport {
    /// Session names whose entries were removed (stale or PID-reused).
    pub removed: Vec<String>,
    /// Session names with a verified live agent-browser daemon (untouched).
    pub kept: Vec<String>,
    /// Non-fatal problems encountered while sweeping.
    pub errors: Vec<String>,
}

/// Remove all stale daemon entries in `socket_dir`. Missing directory is not
/// an error (nothing to sweep). Never removes entries owned by a live process.
pub fn sweep_socket_dir(socket_dir: &Path) -> ReapReport {
    let mut report = ReapReport::default();

    let entries = match fs::read_dir(socket_dir) {
        Ok(e) => e,
        Err(_) => return report,
    };

    // Collect the session stems present in the directory.
    let mut stems: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        for ext in ENTRY_EXTENSIONS {
            if let Some(stem) = name.strip_suffix(&format!(".{}", ext)) {
                if !stem.is_empty() && !stems.iter().any(|s| s == stem) {
                    stems.push(stem.to_string());
                }
            }
        }
    }
    stems.sort();

    for stem in stems {
        if entry_is_live(socket_dir, &stem) {
            report.kept.push(stem);
            continue;
        }
        let mut removed_any = false;
        for ext in ENTRY_EXTENSIONS {
            let path = socket_dir.join(format!("{}.{}", stem, ext));
            if path.exists() {
                match fs::remove_file(&path) {
                    Ok(_) => removed_any = true,
                    Err(e) => {
                        report
                            .errors
                            .push(format!("failed to remove {}: {}", path.display(), e))
                    }
                }
            }
        }
        if removed_any {
            report.removed.push(stem);
        }
    }

    report
}

/// True when the pid file for `stem` exists, parses, and names a live process
/// that is verifiably (or plausibly) an agent-browser binary.
fn entry_is_live(socket_dir: &Path, stem: &str) -> bool {
    let pid_path = socket_dir.join(format!("{}.pid", stem));
    let pid_str = match fs::read_to_string(&pid_path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pid = match pid_str.trim().parse::<i32>() {
        Ok(p) if p > 0 => p,
        _ => return false,
    };
    if !pid_alive(pid) {
        return false;
    }
    // PID-reuse guard: a live process with the recorded PID is only trusted
    // if it is actually an agent-browser binary.
    process_is_agent_browser(pid)
}

#[cfg(unix)]
fn pid_alive(pid: i32) -> bool {
    unsafe {
        if libc::kill(pid, 0) == 0 {
            return true;
        }
        // EPERM means the process exists but we lack permission to signal it.
        // Only ESRCH means the process is genuinely gone.
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }
}

#[cfg(windows)]
fn pid_alive(pid: i32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
        if handle != 0 {
            CloseHandle(handle);
            true
        } else {
            false
        }
    }
}

/// Best-effort check that `pid` is an agent-browser process. Returns true when
/// the executable path cannot be inspected (fail-safe: never delete entries
/// that might belong to a live daemon).
#[cfg(target_os = "macos")]
fn process_is_agent_browser(pid: i32) -> bool {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let ret =
        unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
    if ret <= 0 {
        return true;
    }
    let path = String::from_utf8_lossy(&buf[..ret as usize]);
    path_looks_like_agent_browser(&path)
}

/// Linux: inspect the /proc/<pid>/exe symlink.
#[cfg(target_os = "linux")]
fn process_is_agent_browser(pid: i32) -> bool {
    match fs::read_link(format!("/proc/{}/exe", pid)) {
        Ok(path) => path_looks_like_agent_browser(&path.to_string_lossy()),
        Err(_) => true,
    }
}

/// Other platforms: no cheap executable-path check; trust kill(pid, 0).
#[cfg(all(unix, not(target_os = "macos"), not(target_os = "linux")))]
fn process_is_agent_browser(_pid: i32) -> bool {
    true
}

#[cfg(windows)]
fn process_is_agent_browser(_pid: i32) -> bool {
    true
}

/// Match both the released binary name (`agent-browser`) and the Cargo test
/// binary name (`agent_browser-<hash>`) so unit tests exercise the real check.
fn path_looks_like_agent_browser(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    file.contains("agent-browser") || file.contains("agent_browser")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "agent-browser-reap-test-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_entries(dir: &Path, stem: &str, pid_contents: Option<&str>) {
        if let Some(contents) = pid_contents {
            fs::write(dir.join(format!("{}.pid", stem)), contents).unwrap();
        }
        fs::write(dir.join(format!("{}.sock", stem)), "").unwrap();
    }

    #[cfg(unix)]
    fn dead_pid() -> i32 {
        // Spawn a child that exits immediately and reap it so the PID is
        // genuinely gone (not a zombie).
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id() as i32;
        child.wait().unwrap();
        pid
    }

    #[test]
    #[cfg(unix)]
    fn removes_entries_with_dead_pid() {
        let dir = temp_dir("dead");
        let pid = dead_pid();
        assert!(!pid_alive(pid), "test requires a genuinely dead pid");
        write_entries(&dir, "stale-session", Some(&pid.to_string()));

        let report = sweep_socket_dir(&dir);

        assert_eq!(report.removed, vec!["stale-session".to_string()]);
        assert!(report.kept.is_empty());
        assert!(!dir.join("stale-session.pid").exists());
        assert!(!dir.join("stale-session.sock").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn preserves_entries_with_live_agent_browser_pid() {
        let dir = temp_dir("live");
        // Our own test binary is named agent_browser-<hash>, which
        // path_looks_like_agent_browser accepts.
        let pid = std::process::id() as i32;
        write_entries(&dir, "live-session", Some(&pid.to_string()));

        let report = sweep_socket_dir(&dir);

        assert_eq!(report.kept, vec!["live-session".to_string()]);
        assert!(report.removed.is_empty());
        assert!(dir.join("live-session.pid").exists());
        assert!(dir.join("live-session.sock").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn removes_entries_when_pid_reused_by_other_program() {
        let dir = temp_dir("reuse");
        // A live process that is definitely not agent-browser.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        write_entries(&dir, "reused-session", Some(&pid.to_string()));

        let report = sweep_socket_dir(&dir);

        assert_eq!(report.removed, vec!["reused-session".to_string()]);
        assert!(!dir.join("reused-session.pid").exists());
        // The foreign process itself must never be harmed.
        assert!(pid_alive(pid));
        assert!(child.try_wait().unwrap().is_none());
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn removes_entries_with_unparseable_pid_file() {
        let dir = temp_dir("garbage");
        write_entries(&dir, "garbage-session", Some("not-a-pid"));

        let report = sweep_socket_dir(&dir);

        assert_eq!(report.removed, vec!["garbage-session".to_string()]);
        assert!(!dir.join("garbage-session.pid").exists());
        assert!(!dir.join("garbage-session.sock").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn removes_socket_file_without_pid_file() {
        let dir = temp_dir("orphan-sock");
        write_entries(&dir, "orphan-session", None);

        let report = sweep_socket_dir(&dir);

        assert_eq!(report.removed, vec!["orphan-session".to_string()]);
        assert!(!dir.join("orphan-session.sock").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_directory_is_not_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "agent-browser-reap-test-{}-nonexistent",
            std::process::id()
        ));
        let report = sweep_socket_dir(&dir);
        assert!(report.removed.is_empty());
        assert!(report.kept.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn ignores_unrelated_files() {
        let dir = temp_dir("unrelated");
        fs::write(dir.join("config.json"), "{}").unwrap();
        fs::write(dir.join(".write_test"), "").unwrap();

        let report = sweep_socket_dir(&dir);

        assert!(report.removed.is_empty());
        assert!(dir.join("config.json").exists());
        assert!(dir.join(".write_test").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
