use std::path::PathBuf;

/// Resolve the colmena home directory.
/// Priority: COLMENA_HOME env > directory containing the running binary > ~/colmena fallback
pub fn colmena_home() -> PathBuf {
    if let Ok(home) = std::env::var("COLMENA_HOME") {
        return PathBuf::from(home);
    }
    if let Ok(exe) = std::env::current_exe() {
        // Binary is at <colmena_home>/target/{release,debug}/colmena
        if let Some(target_dir) = exe.parent() {
            if let Some(target) = target_dir.parent() {
                if let Some(project_root) = target.parent() {
                    if project_root.join("config/trust-firewall.yaml").exists() {
                        return project_root.to_path_buf();
                    }
                }
            }
        }
    }
    // Fix 10 (DREAD 7.2): fail explicitly if HOME is not set instead of falling back to /tmp
    let home = std::env::var("HOME").unwrap_or_else(|_| {
        eprintln!("ERROR: HOME environment variable is not set. Set HOME or COLMENA_HOME.");
        std::process::exit(1);
    });
    PathBuf::from(home).join("colmena")
}

/// Default config directory: <colmena_home>/config
pub fn default_config_dir() -> PathBuf {
    colmena_home().join("config")
}
