#!/usr/bin/env bash
set -Eeuo pipefail

# Robust script directory resolution
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Re-exec as root for system tasks
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    # forward all args correctly
    exec sudo -E bash "$0" "$@"
  fi
  echo "Must run as root" >&2
  exit 1
fi

# Install minimal system prerequisites for Python venv and runtime
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends python3 python3-venv python3-pip

# Create venv under /var/lib/wg-installer
STATE_DIR="/var/lib/wg-installer"
VENV_DIR="${STATE_DIR}/venv"
mkdir -p "$STATE_DIR"
python3 -m venv "$VENV_DIR"
# Ensure pip is up to date inside venv
"$VENV_DIR/bin/python" -m pip install --upgrade pip

# Write requirements if not present (kept simple & pinned)
REQS="$SCRIPT_DIR/requirements.txt"
if [ ! -f "$REQS" ]; then
  cat > "$REQS" <<'EOF'
qrcode==7.4.2
Pillow==10.3.0
EOF
fi

# Install Python deps in venv (quiet-ish)
"$VENV_DIR/bin/pip" install -r "$REQS"

# Hand off to Python orchestrator; pass through args
# Ensure the package exists (package directory or main module)
PKG_INIT="$SCRIPT_DIR/wg_installer/__init__.py"
PKG_MAIN="$SCRIPT_DIR/wg_installer/main.py"
if [ ! -f "$PKG_INIT" ] && [ ! -f "$PKG_MAIN" ]; then
  echo "wg_installer package not found next to bootstrap.sh" >&2
  exit 1
fi

exec "$VENV_DIR/bin/python" -m wg_installer.main "$@"
