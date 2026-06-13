# Axeno Relay

The Axeno relay is the message broker for [Axeno](https://github.com/axenochat/axeno-desktop), a private desktop messenger that uses the Signal Protocol over Tor. This repository is the relay; the desktop client lives in [**axeno-desktop**](https://github.com/axenochat/axeno-desktop).

> **Status:** early development, not independently audited. Do not rely on it where your safety is at stake.

## What the relay does

The relay is an **untrusted** message broker. It stores sealed envelopes for offline recipients, routes live delivery, issues short-lived sealed-sender certificates, and hosts encrypted invite bundles. It never sees plaintext. The only things it can observe are transport metadata: which mailbox a connection authenticates as, the destination mailbox of a message, the ciphertext size, and timing.

Each contact gets a dedicated mailbox with its own tokens and sealed-sender key, so the relay cannot link your contacts to one another.

## Run a relay

**Linux is recommended for a production relay.** You **CAN** use macOS and Windows, but you probably shouldn't if you really value your privacy.

### Quick setup (recommended)

The setup script downloads the prebuilt relay binary, generates the at-rest key, installs Tor if it is missing (Linux and macOS), and installs the relay as a hardened, auto-starting service under its own isolated account. In a terminal it asks before installing the service. Piped from `curl` there is no terminal to prompt on, so it uses the defaults and installs the service. Pass `--no-service` (bash) or `-NoService` (PowerShell) for a local setup without a service.

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/axenochat/axeno-relay/main/scripts/setup-relay.sh | sudo bash
```

Windows (in an **elevated** PowerShell):

```powershell
irm https://raw.githubusercontent.com/axenochat/axeno-relay/main/scripts/setup-relay.ps1 | iex
```

Before running anything, both scripts verify the download against a `SHA256SUMS` manifest signed with the project's release key (the public key is pinned inside each script), and abort if the signature or checksum does not match. HTTPS alone is not trusted.

**macOS note:** If you do not use the install script, you may run into issues with Gatekeeper, as I am not an "Official" Apple developer. To fix this simply run:
```
xattr -cr <path to axeno relay binary>
```
I may change this in future, but for now it's not feasible, and trivially fixable anyway.

The service runs under an isolated account: a systemd `DynamicUser` on Linux, a dedicated `_axeno` LaunchDaemon user on macOS, and the low-privilege `LOCAL SERVICE` account on Windows.

On first start the relay generates its keys and publishes a Tor v3 hidden service, writing the `ws://<id>.onion/ws` address to `onion_address.txt` in the data directory. The setup script waits for it and prints it; the first Tor bootstrap takes about 30 to 90 seconds. You can read it again later with `sudo cat /var/lib/axeno/onion_address.txt` on Linux, or from the data directory the script prints on macOS and Windows. Give that address to the people who will use your relay; in the desktop app they add it under **Settings**.

The script is safe to re-run. If you have installed it several times and the relay no longer starts (the logs mention decrypting relay keys), the at-rest key and the encrypted state have fallen out of sync. Re-run with `--reset` (bash) or `-Reset` (PowerShell) to remove the old key and state and set up fresh. This discards the relay's identity and any queued messages, so contacts pair again.

### Update the relay

**To update, just run the same setup command again.** There is no separate update command. Re-running the script downloads the latest release binary, verifies it against the signed `SHA256SUMS`, and restarts the service onto the new binary. It will not delete any of your data. Run it exactly as you first did:

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/axenochat/axeno-relay/main/scripts/setup-relay.sh | sudo bash
```

Windows (in an **elevated** PowerShell):

```powershell
irm https://raw.githubusercontent.com/axenochat/axeno-relay/main/scripts/setup-relay.ps1 | iex
```

### Manual setup

Requirements: Rust stable ([rustup](https://rustup.rs)), `protoc` (`apt install protobuf-compiler`, `brew install protobuf`), and the `tor` binary on your `PATH` to publish a hidden service.

```bash
cargo build --release
echo "AXENO_KEY=$(openssl rand -hex 32)" > .env   # at-rest key
./target/release/axeno-relay
```

## Configuration

The relay is configured through environment variables. It also reads a `.env` file from its working directory at startup; real environment variables take precedence.

| Variable | Default | Purpose |
|---|---|---|
| `AXENO_BIND` | `127.0.0.1:8787` | Listen address. A loopback bind enables the automatic Tor hidden service; a public bind disables it. |
| `AXENO_DATA_DIR` | `axeno-relay-data` | Directory for persisted state, the at-rest key fallback, and Tor data. |
| `AXENO_KEY` | *(unset)* | Secret that encrypts the relay's private keys at rest. Recommended for any real deployment. |
| `AXENO_KEY_FILE` | *(unset)* | Path to a file whose contents are the at-rest secret. Use this for Docker, Kubernetes, or Vault secret mounts so the secret never enters the process environment. |
| `AXENO_UPDATE_CHECK` | *(unset)* | Daily check for a newer release, routed through the relay's own Tor so GitHub never sees the host's IP. On by default whenever the relay runs its Tor hidden service; without Tor it stays silent. Set to `0` to disable entirely, or `1` to also allow a direct clearnet check when Tor is unavailable (this reveals the host's IP). It only logs; it never downloads or installs anything. |
| `RUST_LOG` | *(unset)* | Standard `tracing` filter, for example `axeno_relay=debug`. |

## Hardening

The relay never sees message contents, but it holds two things worth protecting: its signing keys, which can mint sender certificates for any mailbox on the relay, and the offline message queues. Run it like any other service that holds secrets. The setup script's service install applies a hardened profile by default.

### Encrypt the relay's keys at rest

The relay's private keys are always encrypted at rest in `relay-state.json`; they are never written in plaintext. The encryption secret is resolved in this order:

1. `AXENO_KEY`, the literal secret from the environment or the `.env` file.
2. `AXENO_KEY_FILE`, a path whose file contents are the secret. The secret never enters the process environment, so it cannot leak through process inspection or child processes. Best for container and secrets-manager deployments.
3. A randomly generated `relay-key` file (mode `0600`) created inside the data directory on first run.

The `relay-key` fallback means a fresh install is never insecure by default, but it only helps if `relay-state.json` leaks on its own. It does not protect against theft of the whole data directory. For real protection, set `AXENO_KEY` or `AXENO_KEY_FILE` and keep the secret outside the data directory.

If you set `AXENO_KEY` yourself, **use a high-entropy value** such as `openssl rand -hex 32`. The at-rest wrapping derives its key from this secret with Argon2id at moderate cost parameters. That is appropriate for a random 256-bit secret but is not enough to protect a short or guessable passphrase against an attacker who has stolen `relay-state.json`. Treat `AXENO_KEY` as a key, not a password.

### Run behind Tor

Clients should reach the relay through its `.onion` address. When the relay binds to a loopback address and `tor` is installed, it starts a v3 hidden service automatically and writes the address to `onion_address.txt`. Distribute that address to your users.

### Protect the data directory

- Keep `AXENO_DATA_DIR` readable only by the relay user (`0700`). It holds the encrypted state, the `relay-key` fallback if used, and the Tor hidden-service key.
- The Tor hidden-service key is your `.onion` identity. Anyone who obtains it can impersonate your relay's address. Back it up only if you want to keep the same address.

### Rotate a compromised key

Stop the relay, delete `relay-state.json`, the `relay-key` file, and the `tor` directory inside the data directory, then restart. The relay generates fresh keys and a new `.onion` address. Existing mailboxes and queues are dropped, and clients must pair again.

## Capacity and scaling

A relay's practical limit is the Tor daemon, not the relay process. Each client keeps one long-lived rendezvous circuit per contact route it uses on your relay, so the number of inbound circuits grows with the number of users times the contacts they have on this relay. A standard `tor` handles a few thousand concurrent rendezvous circuits, which works out to roughly a few hundred active users per relay. Axeno is built to be self-hosted and spread across many small relays rather than centralized on one large one. If you expect more load than that, run several relays (and look at Onionbalance) instead of scaling a single instance.

The relay caps mailboxes, bundles, queues, and connections (see `config.rs`) and stores state durably. Durable writes cost disk fsyncs on the send path, so peak message throughput depends on your storage. Use an SSD.

## Security model

The relay does not protect against:

- A compromised relay host. The hardening above reduces but does not eliminate this risk.
- Global traffic analysis. The relay is not a mixnet and can correlate messages by timing and size.
- Loss of availability. The relay is a single point of trust for delivery, though never for confidentiality.

Two deliberate trade-offs are worth knowing about:

- **Trust on first use.** A client pins your relay's trust root on its first connection and refuses to continue if it later changes. This catches a later swap, but the first connection is trusted implicitly, so share the `.onion` address over a channel you trust.
- **Mailbox reclamation.** A mailbox that sits idle for 30 days with an empty queue and no live connection is garbage-collected (proof-of-work gates creating a mailbox, not keeping it). Once a mailbox is collected, its random id is free again, so someone who knows that id could re-register it with their own token. They would only ever receive sealed ciphertext they cannot read, and the original owner is locked out rather than impersonated, but it is a possible nuisance against a long-abandoned mailbox. An active mailbox renews its lease on every connection and inbound message and is never collected.

## License

Axeno is licensed under the **GNU General Public License v3.0**. See [LICENSE](./LICENSE).
