//! Optional, opt-in release-notification check.
//!
//! The relay is normally reached only as a Tor onion service and otherwise makes
//! no outbound clearnet connections. Checking GitHub for a newer release is a
//! direct HTTPS request to `api.github.com` that reveals the relay host's real
//! IP address and signals that it runs Axeno. For that reason this check is:
//!
//! - **off by default** — it runs only when `AXENO_UPDATE_CHECK` is truthy;
//! - **notify-only** — it never downloads, verifies, or installs anything. A
//!   key-holding relay should be updated through the operator's normal, audited
//!   deployment path, not by self-replacing its own binary.
//!
//! When enabled it logs a single warning per check if a newer tagged release
//! exists, then sleeps for [`CHECK_INTERVAL`].

use std::time::Duration;

use tracing::{debug, warn};

/// `owner/repo` that publishes Axeno releases.
const REPO: &str = "axenochat/axeno-relay";
/// Version this binary was built from.
const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// How often to re-check once enabled.
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Spawn the background check if `AXENO_UPDATE_CHECK` is enabled. No-op otherwise.
pub fn spawn_if_enabled() {
    if !enabled() {
        debug!("release-notification check disabled (set AXENO_UPDATE_CHECK=1 to enable)");
        return;
    }

    warn!(
        "release-notification check enabled: the relay will periodically contact \
         api.github.com over clearnet, revealing this host's IP to GitHub"
    );

    tokio::spawn(async move {
        loop {
            match check_once().await {
                Ok(Some(release)) => warn!(
                    current = CURRENT,
                    latest = %release.tag_name,
                    url = %release.html_url,
                    "a newer Axeno release is available; update the relay through your \
                     normal deployment path at your convenience"
                ),
                Ok(None) => debug!("relay is up to date (running {CURRENT})"),
                Err(e) => debug!("release-notification check failed: {e}"),
            }
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    });
}

fn enabled() -> bool {
    std::env::var("AXENO_UPDATE_CHECK")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Returns `Ok(Some(release))` when a strictly newer release exists, `Ok(None)`
/// when up to date or the tag cannot be compared, and `Err` on network/parse
/// failure.
async fn check_once() -> anyhow::Result<Option<Release>> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let client = reqwest::Client::builder()
        .user_agent(concat!("axeno-relay/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()?;

    let resp = client
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("github returned status {}", resp.status());
    }
    let release: Release = resp.json().await?;

    let current = semver::Version::parse(CURRENT)?;
    let latest_str = release.tag_name.trim_start_matches('v');
    match semver::Version::parse(latest_str) {
        Ok(latest) if latest > current => Ok(Some(release)),
        Ok(_) => Ok(None),
        Err(e) => {
            debug!("could not parse latest release tag '{}': {e}", release.tag_name);
            Ok(None)
        }
    }
}

#[derive(serde::Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    html_url: String,
}
