#!/usr/bin/env bash
set -Eeuo pipefail

# Re-exec as root for system tasks
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$0" "$ @"
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
REQS="$(dirname "$0")/requirements.txt"
if [ ! -f "$REQS" ]; then
  cat > "$REQS" <<'EOF'
qrcode==7.4.2
Pillow==10.3.0
EOF
fi

# Install Python deps in venv (quiet-ish)
"$VENV_DIR/bin/pip" install -r "$REQS"

# Hand off to Python orchestrator; pass through args
SCRIPT="$(dirname "$0")/wg_installer.py"
if [ ! -f "$SCRIPT" ]; then
  echo "wg_installer.py not found next to bootstrap.sh" >&2
  exit 1
fi

exec "$VENV_DIR/bin/python" -m wg_installer.main "$@"
