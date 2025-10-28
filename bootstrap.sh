#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create venv under /var/lib/wg-installer
STATE_DIR="/var/lib/wg-installer"
VENV_DIR="${STATE_DIR}/venv"
mkdir -p "$STATE_DIR"
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/python" -m pip install --upgrade pip
fi

# Activate venv
if [ -f "$VENV_DIR/bin/activate" ]; then
  . "$VENV_DIR/bin/activate"
fi

# Install package with [tui] extras
"$VENV_DIR/bin/pip" install -e "$SCRIPT_DIR"[tui]

# Run the CLI
exec "$VENV_DIR/bin/wg-installer" "$@"
