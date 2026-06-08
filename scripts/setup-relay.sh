#!/usr/bin/env bash
#
# Axeno relay setup (Linux and macOS).
#
# Downloads the prebuilt relay binary from GitHub Releases, generates an
# at-rest encryption key, writes a config file, and optionally installs the
# relay as a hardened, auto-starting service running under its own isolated
# user.
#
#   curl -fsSL https://raw.githubusercontent.com/axeno-chat/axeno-relay/main/scripts/setup-relay.sh | sudo bash
#
# Flags:
#   --no-service     set up the binary + config but do not install a service
#   --yes, -y        assume "yes" to prompts (non-interactive)
#   --bind ADDR      listen address (default 127.0.0.1:8787; loopback enables Tor)
#   --help, -h       show this help
#
# Linux is the recommended platform for a production relay. macOS works but is
# intended for testing.
set -euo pipefail

# Repository that publishes releases. Update this if the project moves to an org.
REPO="axeno-chat/axeno-relay"

ASSUME_YES=0
INSTALL_SERVICE=1
BIND_ADDR="127.0.0.1:8787"

c_red=$'\033[31m'; c_yellow=$'\033[33m'; c_green=$'\033[32m'; c_dim=$'\033[2m'; c_reset=$'\033[0m'
info()  { printf '%s==>%s %s\n' "$c_green" "$c_reset" "$*"; }
warn()  { printf '%sWARN:%s %s\n' "$c_yellow" "$c_reset" "$*" >&2; }
err()   { printf '%sERROR:%s %s\n' "$c_red" "$c_reset" "$*" >&2; }
die()   { err "$*"; exit 1; }

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --no-service) INSTALL_SERVICE=0 ;;
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
ASSET="axeno-server-${SLUG}.tar.gz"
URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"

if [ "$PLATFORM" != linux ]; then
  warn "Running a relay on ${OS} is not recommended for production — Linux is strongly advised."
  confirm "Continue anyway?" n || die "aborted"
fi

for tool in curl tar; do command -v "$tool" >/dev/null || die "required tool not found: $tool"; done
command -v tor >/dev/null || warn "the 'tor' binary is not on PATH. The relay needs it to publish a .onion address. Install it ($([ "$PLATFORM" = macos ] && echo 'brew install tor' || echo 'apt install tor / dnf install tor')) before starting in production."

gen_key() {
  if command -v openssl >/dev/null; then openssl rand -hex 32
  else head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

# --------------------------------------------------------------------------
# Download and unpack the binary.
# --------------------------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
info "Downloading $ASSET ..."
curl -fSL --proto '=https' --tlsv1.2 "$URL" -o "$TMP/relay.tar.gz" \
  || die "download failed. Has a release been published yet? ($URL)"
tar -xzf "$TMP/relay.tar.gz" -C "$TMP"
[ -f "$TMP/axeno-server" ] || die "archive did not contain an axeno-server binary"
chmod +x "$TMP/axeno-server"

# --------------------------------------------------------------------------
# Install. Two modes: hardened system service, or a local unprivileged setup.
# --------------------------------------------------------------------------
if [ "$INSTALL_SERVICE" = 1 ] && ! confirm "Install Axeno as an auto-starting hardened service?" y; then
  INSTALL_SERVICE=0
fi

if [ "$INSTALL_SERVICE" = 0 ]; then
  # --- Local, no service: install next to the user, write a .env, print run cmd.
  DEST="${PWD}/axeno-relay"
  mkdir -p "$DEST"
  install -m 0755 "$TMP/axeno-server" "$DEST/axeno-server"
  ENV_FILE="$DEST/.env"
  if [ -f "$ENV_FILE" ]; then
    warn "$ENV_FILE already exists; leaving its AXENO_KEY untouched."
  else
    umask 077
    { echo "AXENO_KEY=$(gen_key)"; echo "AXENO_BIND=${BIND_ADDR}"; } > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
  fi
  info "Installed to $DEST"
  info "Start it with:  cd '$DEST' && ./axeno-server"
  info "The .env holds your at-rest key — back it up and keep it private."
  exit 0
fi

# --- Service install requires root.
if [ "$(id -u)" -ne 0 ]; then
  die "installing a service needs root. Re-run with sudo, e.g.:  sudo bash $0"
fi

BIN_DEST=/usr/local/bin/axeno-server
install -m 0755 "$TMP/axeno-server" "$BIN_DEST"
info "Installed binary to $BIN_DEST"

if [ "$PLATFORM" = linux ]; then
  # ---------------------------------------------------------------------
  # Linux: systemd unit with DynamicUser (an isolated, transient account
  # allocated per start) plus a strict sandbox. The at-rest key lives in a
  # root-only EnvironmentFile that the service user never sees.
  # ---------------------------------------------------------------------
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
ExecStart=/usr/local/bin/axeno-server
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

  systemctl daemon-reload
  systemctl enable --now axeno-relay.service
  info "Service installed and started (DynamicUser, sandboxed)."
  info "Status:        systemctl status axeno-relay"
  info "Logs:          journalctl -u axeno-relay -f"
  info "Onion address: cat /var/lib/axeno/onion_address.txt   (once Tor publishes it)"

else
  # ---------------------------------------------------------------------
  # macOS: LaunchDaemon running as a dedicated _axeno role user. The key is
  # stored in the root-only plist's environment.
  # ---------------------------------------------------------------------
  SVC_USER=_axeno
  DATA=/usr/local/var/axeno
  PLIST=/Library/LaunchDaemons/com.axeno.relay.plist

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
  KEY="$(gen_key)"

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
  info "Logs:          tail -f /var/log/axeno-relay.log"
  info "Onion address: sudo cat ${DATA}/onion_address.txt   (once Tor publishes it)"
fi

info "Done."
