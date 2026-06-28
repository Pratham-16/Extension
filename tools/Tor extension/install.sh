#!/usr/bin/env bash
# install.sh — registers tor_mode_host.py as a native messaging host for
# Firefox, so the Tor Mode extension is allowed to launch it.
#
# Run this once after loading the extension (or after its ID changes).
set -euo pipefail

HOST_NAME="com.b14ckwolf.tormode"
EXTENSION_ID="tor-mode@b14ckwolf.local"
INSTALL_DIR="$HOME/.mozilla/native-messaging-hosts"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_SCRIPT="$SCRIPT_DIR/tor_mode_host.py"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 was not found on PATH. Install it first." >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "Warning: curl was not found. The verification step (check.torproject.org) needs it." >&2
fi

mkdir -p "$INSTALL_DIR"
chmod +x "$HOST_SCRIPT"

cat > "$INSTALL_DIR/$HOST_NAME.json" <<EOF
{
  "name": "$HOST_NAME",
  "description": "Native host for the Tor Mode extension",
  "path": "$HOST_SCRIPT",
  "type": "stdio",
  "allowed_extensions": ["$EXTENSION_ID"]
}
EOF

echo "Installed native messaging host manifest:"
echo "  $INSTALL_DIR/$HOST_NAME.json"
echo "  -> points to $HOST_SCRIPT"
echo
echo "Next steps:"
echo "  1. Load (or reload) the Tor Mode extension in about:debugging."
echo "  2. Click the toolbar icon and switch on Tor mode."
echo "  3. The first start/stop will prompt for your admin password"
echo "     (via pkexec) unless you've configured passwordless sudo for"
echo "     'systemctl start tor' / 'systemctl stop tor' specifically."