#!/usr/bin/env bash
#
# Axeno relay setup (Linux and macOS).
#
# Downloads the prebuilt relay binary from GitHub Releases, generates an
# at-rest encryption key, writes a config file, and optionally installs the
# relay as a hardened, auto-starting service running under its own isolated
# user.
#
#   curl -fsSL https://raw.githubusercontent.com/axenochat/axeno-relay/main/scripts/setup-relay.sh | sudo bash
#
# Flags:
#   --no-service     set up the binary + config but do not install a service
#   --reset          remove any existing relay state and at-rest key, then set up fresh
#   --yes, -y        assume "yes" to prompts (non-interactive)
#   --bind ADDR      listen address (default 127.0.0.1:8787; loopback enables Tor)
#   --help, -h       show this help
#
# Linux is the recommended platform for a production relay. macOS works but is
# intended for testing.
set -euo pipefail

# Repository that publishes releases. Update this if the project moves to an org.
REPO="axenochat/axeno-relay"
RAW_URL="https://raw.githubusercontent.com/${REPO}/main/scripts/setup-relay.sh"

ASSUME_YES=0
INSTALL_SERVICE=1
RESET=0
BIND_ADDR="127.0.0.1:8787"

c_red=$'\033[31m'; c_yellow=$'\033[33m'; c_green=$'\033[32m'; c_dim=$'\033[2m'; c_reset=$'\033[0m'
info()  { printf '%s==>%s %s\n' "$c_green" "$c_reset" "$*"; }
warn()  { printf '%sWARN:%s %s\n' "$c_yellow" "$c_reset" "$*" >&2; }
err()   { printf '%sERROR:%s %s\n' "$c_red" "$c_reset" "$*" >&2; }
die()   { err "$*"; exit 1; }

usage() { sed -n '2,/^set /p' "$0" | sed '/^set /d; s/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --no-service) INSTALL_SERVICE=0 ;;
    --reset)      RESET=1 ;;
    -y|--yes)     ASSUME_YES=1 ;;
    --bind)       BIND_ADDR="${2:?--bind needs an address}"; shift ;;
    -h|--help)    usage ;;
    *) die "unknown option: $1 (use --help)" ;;
  esac
  shift
done

confirm() {
  # confirm "question" default(y/n)
  local q="$1" def="${2:-y}" reply
  if [ "$ASSUME_YES" = 1 ]; then return 0; fi
  if [ ! -t 0 ]; then
    # No TTY (e.g. piped from curl) and not --yes: take the default.
    [ "$def" = y ]; return
  fi
  local prompt="[Y/n]"; [ "$def" = n ] && prompt="[y/N]"
  read -r -p "$q $prompt " reply || true
  reply="${reply:-$def}"
  case "$reply" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

# --------------------------------------------------------------------------
# Detect platform and pick the matching release asset.
# --------------------------------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux)  PLATFORM=linux ;;
  Darwin) PLATFORM=macos ;;
  *) die "unsupported OS: $OS (this script supports Linux and macOS; use setup-relay.ps1 on Windows)" ;;
esac
case "$ARCH" in
  x86_64|amd64)  ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "unsupported architecture: $ARCH" ;;
esac
SLUG="${PLATFORM}-${ARCH}"
ASSET="axeno-relay-${SLUG}.tar.gz"
URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
SUMS_URL="https://github.com/${REPO}/releases/latest/download/SHA256SUMS"
SIG_URL="https://github.com/${REPO}/releases/latest/download/SHA256SUMS.sig"

# Public key for verifying release signatures (RSA-3072 / SHA-256). The matching
# private key (RELAY_SIGNING_KEY) signs SHA256SUMS in CI; see
# .github/workflows/release.yml. If you rotate the key, update this block and the
# secret together.
RELEASE_PUBKEY_PEM='-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAumgXLrFiBelXGnDNSem8
DfotHj4SBAOFso+R/IVIsmFoO9NQkTN1Yn6m3CKF16i5cLO9AGM+mWe6u+jV/2Dd
VtaXUVfieIvkxstnu1KdFE9D5KFzxwFV0Jlc3Y5zZRNF9zJ9U+YTNq/A4ZTh2S+1
ujFNnhYwdT6XMpf7qK5RlVtphcxSut4wKciMwBivPquGC6eJAOVj8OZHq6Z0MdND
QuyegwZGHvulfbEYqv2t0xfaZrOJY24LHn2fxpyX9qfp/T4qgL7MweSHtUg5lFVU
Psz2/Kv8Zg7ucxH6YgTvLAzU+v7f6pjqTZ89QIn38ubfTYrWr+05Lzw0UY2DrPKU
kXAiN6wNenAsb7TtBgMa69PzdFdU7IDOqFTNJYIWKkQEDX0vkolJ2qEg29TBg2Ti
xTvQYjC3Ob/EtAQ2vV0D7NeOYXY/dwjAoQs/7vRPv9ob/JdOu2yktYojQPNSX0yy
JfY/tFEOiAK8gYrPeZHQADqowZqRCy4OEDe6fUC8wACBAgMBAAE=
-----END PUBLIC KEY-----'

if [ "$PLATFORM" != linux ]; then
  warn "Running a relay on ${OS} is not recommended for production. Linux is strongly advised."
  confirm "Continue anyway?" n || die "aborted"
fi

for tool in curl tar openssl; do command -v "$tool" >/dev/null || die "required tool not found: $tool"; done

gen_key() {
  if command -v openssl >/dev/null; then openssl rand -hex 32
  else head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

# Print the path to the tor binary, checking PATH plus the standard Homebrew
# locations (root's PATH does not include Homebrew). Returns 1 if not found.
tor_path() {
  if command -v tor >/dev/null 2>&1; then command -v tor; return 0; fi
  local t
  for t in /opt/homebrew/bin/tor /usr/local/bin/tor; do
    [ -x "$t" ] && { printf '%s\n' "$t"; return 0; }
  done
  return 1
}

# Ensure the tor binary is present. The relay publishes its .onion address by
# spawning tor at startup, so without tor a freshly installed service runs but is
# unreachable, which is the most confusing failure mode of this script.
#
# Linux: install it with the system package manager (the service path has root).
# macOS: Homebrew refuses to run as root, so install it as the user who invoked
# sudo. Returns 0 if tor is available afterward, 1 otherwise.
ensure_tor() {
  if tor_path >/dev/null; then return 0; fi

  if [ "$PLATFORM" = macos ]; then
    local brew="" b
    for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
      [ -x "$b" ] && { brew="$b"; break; }
    done
    [ -z "$brew" ] && brew="$(command -v brew 2>/dev/null || true)"
    if [ -z "$brew" ]; then
      warn "Homebrew was not found; cannot install Tor automatically."
      return 1
    fi
    if [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = root ]; then
      warn "Cannot install Tor: Homebrew will not run as root and no invoking user was found."
      warn "Run this script with sudo from your normal account, or 'brew install tor' yourself."
      return 1
    fi
    info "Installing Tor via Homebrew (as $SUDO_USER) ..."
    sudo -u "$SUDO_USER" "$brew" install tor || true
    tor_path >/dev/null
    return $?
  fi

  info "Installing Tor (required to publish the relay's .onion address) ..."
  if   command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y tor
  elif command -v dnf     >/dev/null; then dnf install -y tor
  elif command -v yum     >/dev/null; then yum install -y tor
  elif command -v pacman  >/dev/null; then pacman -Sy --noconfirm tor
  elif command -v zypper  >/dev/null; then zypper install -y tor
  elif command -v apk     >/dev/null; then apk add tor
  else return 1; fi
  command -v tor >/dev/null
}

# Poll for the published onion address for up to ~90s and print it, or fall back
# to an instruction. $1 = path to onion_address.txt.
wait_for_onion() {
  local file="$1" onion=""
  printf '%s==>%s Waiting for Tor to publish the hidden service (first run can take ~30-90s)' "$c_green" "$c_reset"
  local i
  for i in $(seq 1 30); do
    if [ -s "$file" ]; then onion="$(cat "$file")"; break; fi
    sleep 3; printf '.'
  done
  printf '\n'
  if [ -n "$onion" ]; then
    info "Relay address (share this with the people who will use it):"
    printf '\n    %s%s%s\n\n' "$c_green" "$onion" "$c_reset"
  else
    warn "Not published yet. Check again shortly with:  sudo cat $file"
  fi
}

# --------------------------------------------------------------------------
# Download and unpack the binary.
# --------------------------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
info "Downloading $ASSET ..."
curl -fSL --proto '=https' --tlsv1.2 "$URL" -o "$TMP/relay.tar.gz" \
  || die "download failed. Has a release been published yet? ($URL)"

# Verify authenticity (signed SHA256SUMS) and integrity (hash match) before we
# unpack or run anything. Fail closed on any problem.
info "Verifying signature ..."
curl -fSL --proto '=https' --tlsv1.2 "$SUMS_URL" -o "$TMP/SHA256SUMS" \
  || die "could not download SHA256SUMS ($SUMS_URL)"
curl -fSL --proto '=https' --tlsv1.2 "$SIG_URL" -o "$TMP/SHA256SUMS.sig" \
  || die "could not download SHA256SUMS.sig ($SIG_URL)"
printf '%s\n' "$RELEASE_PUBKEY_PEM" > "$TMP/relay.pub"
openssl dgst -sha256 -verify "$TMP/relay.pub" \
  -signature "$TMP/SHA256SUMS.sig" "$TMP/SHA256SUMS" >/dev/null 2>&1 \
  || die "SHA256SUMS signature is INVALID. Refusing to install a possibly tampered binary."
want="$(awk -v f="$ASSET" '$2 == f {print $1}' "$TMP/SHA256SUMS")"
[ -n "$want" ] || die "no checksum entry for $ASSET in the signed SHA256SUMS."
got="$(openssl dgst -sha256 "$TMP/relay.tar.gz" | awk '{print $NF}')"
[ "$want" = "$got" ] || die "checksum mismatch for $ASSET (signed $want, got $got); aborting."
info "Signature and checksum verified."

tar -xzf "$TMP/relay.tar.gz" -C "$TMP"
[ -f "$TMP/axeno-relay" ] || die "archive did not contain an axeno-relay binary"
chmod +x "$TMP/axeno-relay"

# macOS: clear Apple's quarantine flag so Gatekeeper never blocks the binary.
# In this script's own path this is a no-op — curl and command-line tar don't
# set the flag, so a fetched binary is never quarantined. It only matters as a
# safety net if a quarantined binary somehow reaches here (e.g. one downloaded
# through a web browser). Harmless when there's no flag to remove.
if [ "$PLATFORM" = macos ]; then
  xattr -d com.apple.quarantine "$TMP/axeno-relay" 2>/dev/null || true
fi

# --------------------------------------------------------------------------
# Install. Two modes: hardened system service, or a local unprivileged setup.
# --------------------------------------------------------------------------
if [ "$INSTALL_SERVICE" = 1 ] && [ ! -t 0 ] && [ "$ASSUME_YES" != 1 ]; then
  info "No terminal detected (piped from curl), so prompts use their defaults:"
  info "installing as an auto-starting hardened service. Re-run with --no-service"
  info "for a local, non-service install instead."
fi
if [ "$INSTALL_SERVICE" = 1 ] && ! confirm "Install Axeno as an auto-starting hardened service?" y; then
  INSTALL_SERVICE=0
fi

if [ "$INSTALL_SERVICE" = 0 ]; then
  # --- Local, no service: install next to the user, write a .env, print run cmd.
  DEST="${PWD}/axeno-relay"
  mkdir -p "$DEST"
  install -m 0755 "$TMP/axeno-relay" "$DEST/axeno-relay"
  ENV_FILE="$DEST/.env"
  if [ -f "$ENV_FILE" ]; then
    warn "$ENV_FILE already exists; leaving its AXENO_KEY untouched."
  else
    umask 077
    { echo "AXENO_KEY=$(gen_key)"; echo "AXENO_BIND=${BIND_ADDR}"; } > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
  fi
  info "Installed to $DEST"
  if ! command -v tor >/dev/null; then
    warn "Tor is not installed. The relay needs it to publish a .onion address."
    warn "Install it first:  $([ "$PLATFORM" = macos ] && echo 'brew install tor' || echo 'sudo apt install tor   (or your distro'\''s package)')"
  fi
  info "Next steps:"
  info "  1. Start it:  cd '$DEST' && ./axeno-relay"
  info "  2. Wait ~30-90s, then read your address:  cat '$DEST/axeno-relay-data/onion_address.txt'"
  info "  3. Share that ws://...onion/ws address; add it in the Axeno desktop app (Settings)."
  info "The .env holds your at-rest key. Back it up and keep it private."
  exit 0
fi

# --- Service install requires root.
if [ "$(id -u)" -ne 0 ]; then
  die "installing a service needs root. Re-run with sudo, e.g.:  sudo bash $0"
fi

BIN_DEST=/usr/local/bin/axeno-relay
install -m 0755 "$TMP/axeno-relay" "$BIN_DEST"
info "Installed binary to $BIN_DEST"

if [ "$PLATFORM" = linux ]; then
  # ---------------------------------------------------------------------
  # Linux: systemd unit with DynamicUser (an isolated, transient account
  # allocated per start) plus a strict sandbox. The at-rest key lives in a
  # root-only EnvironmentFile that the service user never sees.
  # ---------------------------------------------------------------------
  if [ "$RESET" = 1 ]; then
    warn "Reset requested: stopping the service and removing the existing key and state."
    systemctl stop axeno-relay.service 2>/dev/null || true
    rm -f /etc/axeno/relay.env
    rm -rf /var/lib/axeno /var/lib/private/axeno
  fi
  ENV_DIR=/etc/axeno
  ENV_FILE="$ENV_DIR/relay.env"
  install -d -m 0750 "$ENV_DIR"
  if [ -f "$ENV_FILE" ]; then
    warn "$ENV_FILE exists; keeping the existing AXENO_KEY."
  else
    umask 077
    {
      echo "# Axeno relay environment. Root-only; never commit this."
      echo "AXENO_KEY=$(gen_key)"
      echo "AXENO_BIND=${BIND_ADDR}"
      echo "AXENO_DATA_DIR=/var/lib/axeno"
    } > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    info "Generated at-rest key in $ENV_FILE (root-only). Back this file up."
  fi

  UNIT=/etc/systemd/system/axeno-relay.service
  cat > "$UNIT" <<'UNIT_EOF'
[Unit]
Description=Axeno relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/axeno/relay.env
ExecStart=/usr/local/bin/axeno-relay
Restart=on-failure
RestartSec=5

# Run as an isolated, auto-managed user with a persistent state directory.
DynamicUser=yes
StateDirectory=axeno
WorkingDirectory=/var/lib/axeno

# Sandbox. The relay binds a loopback port and needs no privileges.
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
UNIT_EOF

  # Install Tor before starting so the relay finds it on first launch and can
  # publish the hidden service immediately (it only checks for tor at startup).
  TOR_OK=0
  if ensure_tor; then TOR_OK=1; else
    warn "Could not install Tor automatically. The relay will run but cannot publish"
    warn "a .onion address until Tor is installed; then:  systemctl restart axeno-relay"
  fi

  systemctl daemon-reload
  systemctl enable axeno-relay.service
  # `restart` (not `enable --now`) so re-running the installer to update the
  # binary actually swaps the running process: enable --now is a no-op on an
  # already-active service, which would leave the old binary running. restart
  # also cleanly starts the service on a fresh install.
  systemctl restart axeno-relay.service

  # Confirm the relay actually stays up rather than reporting success and leaving
  # a crash loop. The usual cause of an immediate failure is leftover state from
  # an earlier install that was sealed under a different at-rest key.
  sleep 3
  if ! systemctl is-active --quiet axeno-relay.service; then
    err "The relay started but is not staying up. Recent logs:"
    journalctl -u axeno-relay -n 15 --no-pager >&2 || true
    err ""
    err "If the logs mention decrypting relay keys, leftover state from an earlier"
    err "install is sealed under a different key. Re-run with --reset to wipe it:"
    err "  curl -fsSL $RAW_URL | sudo bash -s -- --reset"
    exit 1
  fi
  info "Service installed and started (DynamicUser, sandboxed)."

  if [ "$TOR_OK" = 1 ]; then
    wait_for_onion /var/lib/axeno/onion_address.txt
  fi

  echo
  info "Next steps:"
  info "  1. Share your ws://...onion/ws address (above) with the people who will use this relay."
  info "  2. In the Axeno desktop app: Settings -> add that relay -> set it as your default."
  info "  3. Use Add Contact to generate and exchange a connection code, then start messaging."
  info "Manage the relay:"
  info "  systemctl status axeno-relay     # health"
  info "  journalctl -u axeno-relay -f     # live logs"
  info "  systemctl restart axeno-relay    # restart (e.g. after installing Tor)"

else
  # ---------------------------------------------------------------------
  # macOS: LaunchDaemon running as a dedicated _axeno role user. The key is
  # stored in the root-only plist's environment.
  # ---------------------------------------------------------------------
  SVC_USER=_axeno
  DATA=/usr/local/var/axeno
  PLIST=/Library/LaunchDaemons/com.axeno.relay.plist

  if [ "$RESET" = 1 ]; then
    warn "Reset requested: stopping the service and removing the existing key and state."
    launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    rm -rf "$DATA"
  fi

  if ! dscl . -read "/Users/$SVC_USER" >/dev/null 2>&1; then
    # Find a free UID in the system range (200-400).
    uid=200
    while dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$uid"; do uid=$((uid+1)); done
    info "Creating service user $SVC_USER (uid $uid)"
    dscl . -create "/Users/$SVC_USER"
    dscl . -create "/Users/$SVC_USER" UserShell /usr/bin/false
    dscl . -create "/Users/$SVC_USER" RealName "Axeno relay"
    dscl . -create "/Users/$SVC_USER" UniqueID "$uid"
    dscl . -create "/Users/$SVC_USER" PrimaryGroupID "$uid"
    dscl . -create "/Groups/$SVC_USER" 2>/dev/null || true
    dscl . -create "/Groups/$SVC_USER" PrimaryGroupID "$uid" 2>/dev/null || true
    dscl . -create "/Users/$SVC_USER" NFSHomeDirectory /var/empty
  fi

  install -d -m 0750 -o "$SVC_USER" "$DATA"
  # Reuse the existing at-rest key on re-run so data already encrypted under it
  # stays readable; only mint a fresh key on first install. (Linux/Windows do
  # the same via their existing-file checks.)
  if [ -f "$PLIST" ]; then
    KEY="$(sed -n 's/.*<key>AXENO_KEY<\/key><string>\(.*\)<\/string>.*/\1/p' "$PLIST" | head -1)"
    if [ -n "$KEY" ]; then info "Reusing existing at-rest key from $PLIST"; else KEY="$(gen_key)"; fi
  else
    KEY="$(gen_key)"
  fi

  # Install Tor (as the user who ran sudo, since Homebrew refuses to run as root)
  # and capture its directory. launchd gives daemons a minimal PATH that excludes
  # Homebrew, so the relay running as _axeno would not otherwise find tor.
  TOR_OK=0; TOR_DIR=""
  if ensure_tor; then
    TOR_OK=1; TOR_DIR="$(dirname "$(tor_path)")"
  else
    warn "Tor is not installed. Install it as your normal user (not root):  brew install tor"
    warn "then restart the relay:  sudo launchctl kickstart -k system/com.axeno.relay"
  fi
  SVC_PATH="${TOR_DIR:+$TOR_DIR:}/usr/bin:/bin:/usr/sbin:/sbin"

  cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.axeno.relay</string>
  <key>UserName</key><string>${SVC_USER}</string>
  <key>ProgramArguments</key><array><string>${BIN_DEST}</string></array>
  <key>WorkingDirectory</key><string>${DATA}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>AXENO_KEY</key><string>${KEY}</string>
    <key>AXENO_BIND</key><string>${BIND_ADDR}</string>
    <key>AXENO_DATA_DIR</key><string>${DATA}</string>
    <key>PATH</key><string>${SVC_PATH}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/axeno-relay.log</string>
  <key>StandardOutPath</key><string>/var/log/axeno-relay.log</string>
</dict>
</plist>
PLIST_EOF
  chmod 600 "$PLIST"   # root-only: protects AXENO_KEY in the plist
  chown root:wheel "$PLIST"

  launchctl unload "$PLIST" 2>/dev/null || true
  launchctl load "$PLIST"
  info "LaunchDaemon installed and started as user $SVC_USER."
  warn "The AXENO_KEY is stored in $PLIST (root-only). Back it up."

  # Confirm it stays up. A nonzero last-exit usually means leftover state from an
  # earlier install sealed under a different at-rest key.
  sleep 3
  svc_status="$(launchctl list com.axeno.relay 2>/dev/null | sed -n 's/.*"LastExitStatus" = \([0-9-]*\);.*/\1/p')"
  if [ -n "$svc_status" ] && [ "$svc_status" != 0 ]; then
    err "The relay exited with status $svc_status. Recent log:"
    tail -n 15 /var/log/axeno-relay.log >&2 2>/dev/null || true
    err ""
    err "If this mentions decrypting relay keys, leftover state is sealed under a"
    err "different key. Re-run with --reset to wipe it and start fresh."
    exit 1
  fi

  if [ "$TOR_OK" = 1 ]; then
    wait_for_onion "${DATA}/onion_address.txt"
  fi

  echo
  info "Next steps:"
  info "  1. Share your ws://...onion/ws address (above) with the people who will use this relay."
  info "  2. In the Axeno desktop app: Settings -> add that relay -> set it as your default."
  info "  3. Use Add Contact to generate and exchange a connection code, then start messaging."
  info "Manage the relay:"
  info "  sudo launchctl kickstart -k system/com.axeno.relay   # restart"
  info "  tail -f /var/log/axeno-relay.log                     # live logs"
fi

info "Done."
