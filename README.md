# Axeno Relay

The Axeno relay is the message broker for [Axeno](https://github.com/axeno-chat/axeno-desktop), a private desktop messenger that uses the Signal Protocol over Tor. This repository is the relay; the desktop client lives in [**axeno-desktop**](https://github.com/axeno-chat/axeno-desktop).

> **Status:** early development, not independently audited. Do not rely on it where your safety is at stake.

## What the relay does

The relay is an **untrusted** message broker. It stores sealed envelopes for offline recipients, routes live delivery, issues short-lived sealed-sender certificates, and hosts encrypted invite bundles. It never sees plaintext. The only things it can observe are transport metadata: which mailbox a connection authenticates as, the destination mailbox of a message, ciphertext size, and timing.

Each contact gets a dedicated mailbox with its own tokens and sealed-sender key, so the relay cannot link your contacts to one another.

## Run a relay

**Linux is strongly recommended for a production relay.** macOS and Windows are supported for testing.

### Quick setup (recommended)

The setup script downloads the prebuilt relay binary, generates the at-rest key, and offers to install the relay as a hardened, auto-starting service that runs under its own isolated account.

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/axeno-chat/axeno-relay/main/scripts/setup-relay.sh | sudo bash
```

Windows (in an **elevated** PowerShell):

```powershell
irm https://raw.githubusercontent.com/axeno-chat/axeno-relay/main/scripts/setup-relay.ps1 | iex
```

On Linux the relay runs under a sandboxed systemd unit with `DynamicUser`; on macOS under a dedicated `_axeno` LaunchDaemon user; on Windows as a scheduled task under the low-privilege `LOCAL SERVICE` account. Pass `--no-service` (bash) or `-NoService` (PowerShell) to set up the binary and config without a service.

On first start the relay generates its keys, and if `tor` is installed it publishes a Tor v3 hidden service and writes the `.onion` address to `onion_address.txt` in the data directory. Share that address with the people who will use your relay.

### Manual setup

Requirements: Rust stable ([rustup](https://rustup.rs)), `protoc` (`apt install protobuf-compiler` / `brew install protobuf`), and the `tor` binary on your `PATH` to publish a hidden service.

```bash
cargo build --release
echo "AXENO_KEY=$(openssl rand -hex 32)" > .env   # at-rest key
./target/release/axeno-server
```

## Configuration

The relay is configured through environment variables. It also reads a `.env` file from its working directory at startup; real environment variables take precedence.

| Variable | Default | Purpose |
|---|---|---|
| `AXENO_BIND` | `127.0.0.1:8787` | Listen address. A loopback bind enables the automatic Tor hidden service; a public bind disables it. |
| `AXENO_DATA_DIR` | `axeno-relay-data` | Directory for persisted state, the at-rest key fallback, and Tor data. |
| `AXENO_KEY` | *(unset)* | Secret that encrypts the relay's private keys at rest. Recommended for any real deployment. |
| `AXENO_KEY_FILE` | *(unset)* | Path to a file whose contents are the at-rest secret. Use this for Docker, Kubernetes, or Vault secret mounts so the secret never enters the process environment. |
| `AXENO_UPDATE_CHECK` | *(unset)* | Set to `1` to let the relay check GitHub daily and log when a newer release exists. Off by default; when on, the relay contacts `api.github.com` over clearnet, revealing its IP. Notify-only — it never downloads or installs anything. |
| `RUST_LOG` | *(unset)* | Standard `tracing` filter, for example `axeno_server=debug`. |

## Hardening

The relay never sees message contents, but it holds two things worth protecting: its signing keys, which can mint sender certificates for any mailbox on the relay, and offline message queues. Run it like any other service that holds secrets. The setup script's service install applies a hardened profile by default.

### Encrypt the relay's keys at rest

The relay's private keys are always encrypted at rest in `relay-state.json`; they are never written in plaintext. The encryption secret is resolved in this order:

1. `AXENO_KEY`, the literal secret from the environment or the `.env` file.
2. `AXENO_KEY_FILE`, a path whose file contents are the secret. The secret never enters the process environment, so it cannot leak through process inspection or child processes. Best for container and secrets-manager deployments.
3. A randomly generated `relay-key` file (mode `0600`) created inside the data directory on first run.

The `relay-key` fallback means a fresh install is never insecure by default, but it only helps if `relay-state.json` leaks on its own — it does not protect against theft of the whole data directory. For real protection, set `AXENO_KEY` or `AXENO_KEY_FILE` and keep the secret outside the data directory.

### Run behind Tor

Clients should reach the relay through its `.onion` address. When the relay binds to a loopback address and `tor` is installed, it starts a v3 hidden service automatically and writes the address to `onion_address.txt`. Distribute that address to your users.

### Protect the data directory

- Keep `AXENO_DATA_DIR` readable only by the relay user (`0700`). It holds the encrypted state, the `relay-key` fallback if used, and the Tor hidden-service key.
- The Tor hidden-service key is your `.onion` identity. Anyone who obtains it can impersonate your relay's address. Back it up only if you want to keep the same address.

### Rotate a compromised key

Stop the relay, delete `relay-state.json`, the `relay-key` file, and the `tor` directory inside the data directory, then restart. The relay generates fresh keys and a new `.onion` address. Existing mailboxes and queues are dropped, and clients must pair again.

## Security model

The relay does not protect against:

- A compromised relay host. The hardening above reduces but does not eliminate this risk.
- Global traffic analysis. The relay is not a mixnet and can correlate messages by timing and size.
- Loss of availability. The relay is a single point of trust for delivery, though never for confidentiality.

## License

Axeno is licensed under the **GNU General Public License v3.0**. See [LICENSE](./LICENSE).
