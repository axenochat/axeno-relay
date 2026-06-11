//! Release-notification check, routed through the relay's own Tor daemon.
//!
//! The relay is normally reached only as a Tor onion service and otherwise makes
//! no outbound clearnet connections. Checking GitHub for a newer release from
//! the host's real IP would reveal that IP and signal that it runs Axeno, so the
//! check rides the loopback SOCKS port of the tor daemon the relay already
//! spawns for its hidden service. Over Tor the check is on by default; without
//! Tor it never touches the clearnet unless explicitly opted in. It is
//! **notify-only** — it never downloads, verifies, or installs anything. A
//! key-holding relay should be updated through the operator's normal, audited
//! deployment path, not by self-replacing its own binary.
//!
//! `AXENO_UPDATE_CHECK` semantics:
//! - *unset* — check daily over Tor when the relay's tor is running; if there
//!   is no Tor SOCKS port (public bind, or tor not installed), do nothing.
//! - `0`/`false`/`no`/`off` — never check.
//! - `1`/`true`/`yes`/`on` — check daily; still prefers Tor, but falls back to
//!   a direct clearnet request when Tor is unavailable (reveals the host IP).
//!
//! When a newer tagged release exists it logs a single warning per check, then
//! sleeps for [`CHECK_INTERVAL`].

use std::time::Duration;

use tracing::{debug, warn};

/// `owner/repo` that publishes Axeno releases.
const REPO: &str = "axenochat/axeno-relay";
/// Version this binary was built from.
const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// How often to re-check.
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Grace period before the first check: tor needs time to bootstrap before its
/// SOCKS port accepts connections.
const INITIAL_DELAY: Duration = Duration::from_secs(2 * 60);
/// Retry sooner after a failed check (commonly tor still bootstrapping, or a
/// flaky exit) instead of going silent for a whole day.
const RETRY_INTERVAL: Duration = Duration::from_secs(30 * 60);

enum Mode {
    /// `AXENO_UPDATE_CHECK` unset: Tor-only, on by default.
    Default,
    /// Explicitly enabled: prefer Tor, allow clearnet fallback.
    Enabled,
    /// Explicitly disabled (or unrecognized value: fail private).
    Disabled,
}

fn mode() -> Mode {
    match std::env::var("AXENO_UPDATE_CHECK") {
        Err(_) => Mode::Default,
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Mode::Enabled,
            _ => Mode::Disabled,
        },
    }
}

/// Spawn the background check. `tor_socks_port` is the loopback SOCKS port of
/// the relay's own tor daemon, when one was started.
pub fn spawn(tor_socks_port: Option<u16>) {
    let proxy_port = match mode() {
        Mode::Disabled => {
            debug!("release-notification check disabled (AXENO_UPDATE_CHECK)");
            return;
        }
        Mode::Default => {
            let Some(port) = tor_socks_port else {
                debug!(
                    "release-notification check skipped: no relay Tor SOCKS port is available \
                     and AXENO_UPDATE_CHECK is not set (the default never uses clearnet; set \
                     AXENO_UPDATE_CHECK=1 to allow a direct check that reveals this host's IP)"
                );
                return;
            };
            Some(port)
        }
        Mode::Enabled => {
            if tor_socks_port.is_none() {
                warn!(
                    "release-notification check enabled without Tor: the relay will periodically \
                     contact api.github.com over clearnet, revealing this host's IP to GitHub"
                );
            }
            tor_socks_port
        }
    };
    if let Some(port) = proxy_port {
        debug!(socks_port = port, "release-notification check enabled, routed over Tor");
    }

    tokio::spawn(async move {
        tokio::time::sleep(INITIAL_DELAY).await;
        loop {
            let next = match check_once(proxy_port).await {
                Ok(Some(release)) => {
                    warn!(
                        current = CURRENT,
                        latest = %release.tag_name,
                        url = %release.html_url,
                        "a newer Axeno release is available; update the relay through your \
                         normal deployment path at your convenience"
                    );
                    CHECK_INTERVAL
                }
                Ok(None) => {
                    debug!("relay is up to date (running {CURRENT})");
                    CHECK_INTERVAL
                }
                Err(e) => {
                    debug!(
                        "release-notification check failed: {e}; retrying in {} minutes",
                        RETRY_INTERVAL.as_secs() / 60
                    );
                    RETRY_INTERVAL
                }
            };
            tokio::time::sleep(next).await;
        }
    });
}

/// Returns `Ok(Some(release))` when a strictly newer release exists, `Ok(None)`
/// when up to date or the tag cannot be compared, and `Err` on network/parse
/// failure.
async fn check_once(tor_socks_port: Option<u16>) -> anyhow::Result<Option<Release>> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!("axeno-relay/", env!("CARGO_PKG_VERSION")))
        // Generous timeout: a Tor circuit to a clearnet exit can be slow.
        .timeout(Duration::from_secs(60));
    if let Some(port) = tor_socks_port {
        // socks5h: the proxy (tor) resolves the hostname, so even the DNS
        // lookup for api.github.com never leaves Tor.
        builder = builder.proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))?);
    }
    let client = builder.build()?;

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
