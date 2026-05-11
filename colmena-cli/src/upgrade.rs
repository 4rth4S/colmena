use anyhow::{Context, Result};

use crate::doctor;

const CRATES_IO_API: &str = "https://crates.io/api/v1/crates";
const USER_AGENT: &str = concat!("colmena-upgrade/", env!("CARGO_PKG_VERSION"));

pub fn run_upgrade(verbose: bool) -> Result<()> {
    println!("Colmena Upgrade Check");
    println!("{}", "=".repeat(22));
    println!();

    let installed_version = env!("CARGO_PKG_VERSION");

    // Check colmena CLI
    check_crate_version("colmena", installed_version, "colmena", verbose)?;

    // Check colmena-mcp
    let (mcp_version, mcp_found) = get_installed_mcp_version();
    if mcp_found {
        check_crate_version("colmena-mcp", &mcp_version, "colmena-mcp", verbose)?;
    } else {
        println!("  colmena-mcp: {} [NOT FOUND]", installed_version);
        println!("    Install: cargo install colmena-mcp");
        if verbose {
            println!(
                "    (binary not found next to colmena — it may be at ~/.cargo/bin/colmena-mcp)"
            );
        }
    }

    // Suggest upgrade path
    println!();
    if doctor::detect_mode_label().starts_with("repo:") {
        println!("Repo mode detected.");
        println!(
            "To update: git pull && cargo build --release && cp target/release/colmena-mcp ~/.cargo/bin/"
        );
    } else {
        println!("Standalone installation detected.");
        println!("To update: cargo install --force colmena colmena-mcp");
    }

    Ok(())
}

fn check_crate_version(
    crate_name: &str,
    installed: &str,
    label: &str,
    verbose: bool,
) -> Result<()> {
    let latest = match fetch_latest_version(crate_name) {
        Ok(v) => v,
        Err(e) => {
            println!("  {}: {} [UNABLE TO CHECK — {}]", label, installed, e);
            return Ok(());
        }
    };

    let up_to_date = version_ge(installed, &latest);
    let tag = if up_to_date {
        "UP-TO-DATE"
    } else {
        "UPDATE AVAILABLE"
    };

    println!("  {}: {} → {} [{}]", label, installed, latest, tag);

    if !up_to_date {
        match crate_name {
            "colmena" => println!("    Run: cargo install --force colmena"),
            "colmena-mcp" => println!("    Run: cargo install --force colmena-mcp"),
            _ => {}
        }
    }

    if verbose {
        println!("    crates.io: {}/{}/{}", CRATES_IO_API, crate_name, latest);
    }

    Ok(())
}

fn fetch_latest_version(crate_name: &str) -> Result<String> {
    let url = format!("{}/{}", CRATES_IO_API, crate_name);
    let mut response = ureq::get(&url)
        .header("User-Agent", USER_AGENT)
        .call()
        .with_context(|| format!("HTTP request to crates.io failed for {crate_name}"))?;

    let body_str = response
        .body_mut()
        .read_to_string()
        .context("Failed to read response body")?;
    let parsed: serde_json::Value =
        serde_json::from_str(&body_str).context("Failed to parse crates.io API response")?;

    parsed["crate"]["max_version"]
        .as_str()
        .map(|s| s.to_string())
        .with_context(|| format!("crates.io response missing max_version for {crate_name}"))
}

fn get_installed_mcp_version() -> (String, bool) {
    if let Some(mcp_path) = doctor::find_mcp_binary() {
        if let Some(ver) = doctor::get_mcp_version(&mcp_path) {
            return (ver, true);
        }
    }
    (env!("CARGO_PKG_VERSION").to_string(), false)
}

/// True if `a >= b` using simple component-wise semver comparison.
/// Returns true if parsing fails (conservative: assume up-to-date).
fn version_ge(a: &str, b: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<u32>().ok())
            .collect()
    };

    let va = parse(a);
    let vb = parse(b);

    if va.is_empty() || vb.is_empty() {
        return true; // can't parse — don't alarm
    }

    for i in 0..std::cmp::max(va.len(), vb.len()) {
        let na = va.get(i).copied().unwrap_or(0);
        let nb = vb.get(i).copied().unwrap_or(0);
        match na.cmp(&nb) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_ge() {
        assert!(version_ge("0.14.3", "0.14.2"));
        assert!(version_ge("0.14.3", "0.14.3"));
        assert!(!version_ge("0.14.2", "0.14.3"));
        assert!(version_ge("1.0.0", "0.14.3"));
        assert!(!version_ge("0.13.0", "0.14.0"));
        assert!(version_ge("0.14.10", "0.14.9"));
    }
}
