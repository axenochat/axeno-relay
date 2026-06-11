//! Automatic Tor hidden-service bootstrap for loopback-bound relays.

use std::fs;
use std::path::Path;

use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{info, warn};

/// Pick a currently free loopback port for tor's SOCKS listener. There is a
/// small window between dropping the probe listener and tor binding the port,
/// but ephemeral-port reuse within milliseconds is vanishingly rare, and a
/// collision only costs the SOCKS proxy (tor logs the bind failure), never the
/// relay itself.
fn pick_free_loopback_port() -> anyhow::Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

/// Start the hidden-service tor daemon. Returns the loopback SOCKS port opened
/// on it (used by the release-notification check so it can reach GitHub without
/// revealing the relay's IP), or `None` when tor is not installed.
pub(crate) async fn start_tor_hidden_service(port: u16, data_dir: &Path) -> anyhow::Result<Option<u16>> {
    if tokio::process::Command::new("tor").arg("--version").output().await.is_err() {
        warn!("Tor is not installed or not in PATH. Skipping automatic Hidden Service creation.");
        warn!("To run over Tor, please install tor (e.g. `apt install tor`) and restart the server.");
        return Ok(None);
    }

    let tor_dir = data_dir.join("tor");
    let hs_dir = tor_dir.join("hs");
    let torrc_path = tor_dir.join("torrc");

    fs::create_dir_all(&hs_dir)?;

    // Set strict permissions on the hidden service directory (Tor requires 0700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hs_dir, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&tor_dir, fs::Permissions::from_mode(0o700))?;
    }

    // The SOCKS listener is loopback-only and exists so the relay's own
    // outbound traffic (the opt-out release-notification check) can ride this
    // tor instead of the clearnet. Like a stock system tor on 9050, other
    // local processes could proxy through it; that grants outbound Tor access,
    // never access to relay state.
    let socks_port = pick_free_loopback_port()?;
    let torrc_content = format!(
        "DataDirectory {data_dir}\n\
         HiddenServiceDir {hs_dir}\n\
         HiddenServiceVersion 3\n\
         HiddenServicePort 80 127.0.0.1:{port}\n\
         SocksPort 127.0.0.1:{socks_port}\n\
         Log notice stdout\n",
        data_dir = tor_dir.display(),
        hs_dir = hs_dir.display(),
        port = port,
        socks_port = socks_port
    );
    fs::write(&torrc_path, torrc_content)?;

    info!("Starting Tor daemon for automatic Hidden Service...");

    let pid = std::process::id();
    let mut child = tokio::process::Command::new("tor")
        .arg("-f")
        .arg(&torrc_path)
        .arg("__OwningControllerProcess")
        .arg(pid.to_string())
        // tor has no need for the relay's secrets; strip them from the child's
        // environment so the at-rest key cannot leak via the tor process
        // (e.g. its /proc/<pid>/environ) through inheritance.
        .env_remove("AXENO_KEY")
        .env_remove("AXENO_KEY_FILE")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let hs_dir_clone = hs_dir.clone();
    let onion_out_path = data_dir.join("onion_address.txt");
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    tokio::spawn(async move {
        let Some(stdout) = stdout else { return; };
        let mut lines = BufReader::new(stdout).lines();
        let mut announced = false;
        while let Ok(Some(line)) = lines.next_line().await {
            info!("tor: {}", line);
            if announced || !line.contains("Bootstrapped 100%") {
                continue;
            }

            let hostname_path = hs_dir_clone.join("hostname");
            for _ in 0..30 {
                if let Ok(hostname) = fs::read_to_string(&hostname_path) {
                    info!("==================================================");
                    info!("Tor Hidden Service bootstrapped.");
                    info!("Your relay onion address is: ws://{}/ws", hostname.trim());
                    info!("==================================================");
                    let _ = fs::write(&onion_out_path, format!("ws://{}/ws", hostname.trim()));
                    announced = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }
            if !announced {
                warn!("Tor bootstrapped, but the hidden service hostname file was not available in time.");
            }
        }
    });

    tokio::spawn(async move {
        let Some(stderr) = stderr else { return; };
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            warn!("tor: {}", line);
        }
    });

    tokio::spawn(async move {
        let _ = child.wait().await;
        warn!("Tor daemon process exited.");
    });

    Ok(Some(socks_port))
}
