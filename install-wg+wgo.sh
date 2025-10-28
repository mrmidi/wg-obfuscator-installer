#!/usr/bin/env bash
set -Eeuo pipefail

# Save original invocation args so we can re-exec under sudo if needed.
ORIG_ARGS=("$@")

# ========= Output colors (optional) =========
# Use colors only when stderr is a TTY to avoid control codes in logs/files.
if [ -t 2 ]; then
  RED='\033[0;31m'
  YEL='\033[0;33m'
  BLU='\033[0;34m'
  BOLD='\033[1m'
  RESET='\033[0m'
else
  RED='' YEL='' BLU='' BOLD='' RESET=''
fi

# ========= Globals / Defaults =========
STATE_DIR="/var/lib/wg-installer"
STATE_FILE="${STATE_DIR}/state.json"
SRC_DIR="/usr/local/src/wg-obfuscator"
WG_CONF_DIR="/etc/wireguard"
WG_PRIV="${WG_CONF_DIR}/privatekey"
WG_PUB="${WG_CONF_DIR}/publickey"
WG_CONF="${WG_CONF_DIR}/wg0.conf"
WG_INT_NAME="wg0"

OBF_BIN="/usr/local/bin/wg-obfuscator"
OBF_CONF="/etc/wg-obfuscator.conf"
OBF_SERVICE="/etc/systemd/system/wg-obfuscator.service"

NFT_DIR="/etc/nftables.d"
NFT_MAIN="/etc/nftables.conf"
NFT_SNIPPET="${NFT_DIR}/50-wg-installer.nft"
NFT_TABLE_FILT="wginst"
NFT_TABLE_NAT="wginst_nat"

DEFAULT_PUB_PORT="${PUB_PORT:-3478}"       # public UDP (obfuscator)
DEFAULT_WG_PORT="${WG_PORT:-51820}"        # internal WG port (loopback-only via firewall)
DEFAULT_SUBNET="${WG_SUBNET:-10.7.0.0/24}" # tunnel subnet (IPv4 edge)
DEFAULT_MASKING="${MASKING:-STUN}"         # STUN|AUTO|NONE (server)
ASSUME_YES="${ASSUME_YES:-0}"
NONINTERACTIVE="${NONINTERACTIVE:-0}"
DRY_RUN=0

# ========= Utilities =========
log()  { printf -- "%b[wg-installer]%b %s\n" "${BLU}" "${RESET}" "$*"; }
die()  { printf -- "%b[wg-installer][%sERROR%s]%b %s\n" "${RED}" "${BOLD}" "${RESET}" "${RESET}" "$*" >&2; exit 1; }
as_root() {
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      log "Not running as root: requesting elevated privileges with sudo..."
      exec sudo bash "$0" "${ORIG_ARGS[@]}"
    fi
    die "Must run as root."
  fi
}

need_cmd() {
  # In dry-run, we only require a minimal set to let discovery run.
  if [ "$DRY_RUN" = "1" ]; then
    command -v "$1" >/dev/null 2>&1 || log "DRY-RUN: would require command '$1' (not found, continuing)"
    return 0
  fi
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

prompt() {
  local msg="$1" def="$2" var
  if [ "$ASSUME_YES" = "1" ] || [ "$NONINTERACTIVE" = "1" ]; then
    printf "%s [%s]: %s (auto)\n" "$msg" "$def" "$def"
    printf "%s" "$def"
    return 0
  fi
  read -r -p "$msg [$def]: " var || true
  [ -z "${var:-}" ] && var="$def"
  printf "%s" "$var"
}

# Lightweight TUI wrapper: prefer whiptail, fallback to dialog, else plain prompts.
# Respects ASSUME_YES/NONINTERACTIVE and DRY_RUN.
UI=none
ui_detect() {
  if [ -t 1 ] && command -v whiptail >/dev/null 2>&1; then UI=whiptail
  elif [ -t 1 ] && command -v dialog   >/dev/null 2>&1; then UI=dialog
  else UI=none; fi
}

ui_input() { # ui_input "Title" "Prompt" "default" -> echo value
  local title="$1" prompt="$2" def="$3" out
  if [ "$ASSUME_YES" = "1" ] || [ "$NONINTERACTIVE" = "1" ]; then
    printf "%s [%s]: %s (auto)\n" "$prompt" "$def" "$def"
    printf "%s" "$def"
    return 0
  fi
  if [ "$DRY_RUN" = "1" ]; then
    printf "[DRY-RUN] %s [%s]: %s\n" "$prompt" "$def" "$def"
    printf "%s" "$def"
    return 0
  fi
  case "$UI" in
    whiptail) out=$(whiptail --title "$title" --inputbox "$prompt" 10 60 "$def" 3>&1 1>&2 2>&3);;
    dialog)   out=$(dialog   --title "$title" --inputbox "$prompt" 10 60 "$def" 3>&1 1>&2 2>&3);;
    *)        printf "%s [%s]: " "$prompt" "$def"; read -r out; out="${out:-$def}";;
  esac
  printf "%s" "$out"
}

ui_confirm() { # ui_confirm "Title" "Question" "Y|N" -> return 0/1
  local title="$1" prompt="$2" d="${3:-Y}" yn
  if [ "$ASSUME_YES" = "1" ] || [ "$NONINTERACTIVE" = "1" ]; then
    [ "$d" = "Y" ] && return 0 || return 1
  fi
  if [ "$DRY_RUN" = "1" ]; then
    printf "[DRY-RUN] %s (default %s)\n" "$prompt" "$d"
    [ "$d" = "Y" ] && return 0 || return 1
  fi
  case "$UI" in
    whiptail) whiptail --title "$title" --yesno "$prompt" 9 60; return $?;;
    dialog)   dialog   --title "$title" --yesno "$prompt" 9 60; return $?;;
    *)        while :; do
                read -r -p "$prompt [y/n] (default $d): " yn; yn="${yn:-$d}"
                case "$yn" in [Yy]*) return 0;; [Nn]*) return 1;; esac
              done;;
  esac
}

ui_menu() { # ui_menu "Title" "Prompt" tag1 "Label 1" tag2 "Label 2" ... -> echo chosen tag
  local title="$1" prompt="$2"; shift 2
  if [ "$ASSUME_YES" = "1" ] || [ "$NONINTERACTIVE" = "1" ]; then
    # choose first tag as default
    printf "%s" "$1"
    return 0
  fi
  if [ "$DRY_RUN" = "1" ]; then
    printf "[DRY-RUN] %s\n" "$prompt"
    printf "%s" "$1"
    return 0
  fi
  case "$UI" in
    whiptail) whiptail --title "$title" --menu "$prompt" 15 60 7 "$@" 3>&1 1>&2 2>&3;;
    dialog)   dialog   --title "$title" --menu "$prompt" 15 60 7 "$@" 3>&1 1>&2 2>&3;;
    *)        echo "$prompt"
              local args=("$@"); local i=0
              while [ $i -lt ${#args[@]} ]; do
                printf "  %s  %s\n" "${args[$i]}" "${args[$((i+1))]}"; i=$((i+2))
              done
              local sel; read -r -p "Enter choice (tag): " sel; printf "%s" "$sel";;
  esac
}

# Command runner: executes or prints
run() {
  if [ "$DRY_RUN" = "1" ]; then
    # Highlight dry-run messages in yellow for visibility
    printf "%b[DRY-RUN]%b %s\n" "${YEL}" "${RESET}" "$*" >&2
    return 0
  fi
  # We intentionally use eval to support pipelines, redirections and "|| true"
  # in single-call sites (systemctl/nft invocations). Safer than re-spreading
  # across multiple lines and preserves the original command semantics.
  # shellcheck disable=SC2294
  eval "$@"
}

# File writer: shows diff-ish content in dry-run
write_file() {
  # usage: write_file <path> <mode> <<'EOF' ... EOF
  local path="$1" mode="$2"
  shift 2
  if [ "$DRY_RUN" = "1" ]; then
    printf "[DRY-RUN] Would write file: %s (mode %s)\n" "$path" "$mode"
    cat | sed 's/^/[DRY-RUN]   /'
  else
    umask 077
    # shellcheck disable=SC2094
    cat > "$path"
    chmod "$mode" "$path"
  fi
}

append_file() {
  local path="$1" mode="$2"
  if [ "$DRY_RUN" = "1" ]; then
    printf "[DRY-RUN] Would append to file: %s (mode %s)\n" "$path" "$mode"
    cat | sed 's/^/[DRY-RUN]   /'
  else
    umask 077
    cat >> "$path"
    chmod "$mode" "$path"
  fi
}

ensure_dir() {
  local d="$1" perm="${2:-700}"
  if [ "$DRY_RUN" = "1" ]; then
    printf "[DRY-RUN] Would create dir: %s (perm %s)\n" "$d" "$perm"
  else
    mkdir -p "$d"
    chmod "$perm" "$d"
  fi
}

json_put() {
  local key="$1" val="$2"
  ensure_dir "$STATE_DIR"
  if [ "$DRY_RUN" = "1" ]; then
    printf "[DRY-RUN] Would set state: %s=%s in %s\n" "$key" "$val" "$STATE_FILE"
    return 0
  fi
  if [ ! -f "$STATE_FILE" ]; then
    printf "{}" > "$STATE_FILE"
  fi
  if ! command -v jq >/dev/null 2>&1; then
    tmp="$(mktemp)"
    if grep -q "\"$key\"" "$STATE_FILE"; then
      # Use '|' as sed delimiter so '/' in values (eg. CIDRs) don't break the expression.
      sed "s|\"$key\": *\"[^\"]*\"|\"$key\":\"$val\"|" "$STATE_FILE" > "$tmp"
    else
      sed 's/}$/,"__PLACEHOLDER__":""}/' "$STATE_FILE" > "$tmp"
      # Use '|' delimiter here too for the same reason.
      sed -i "s|\"__PLACEHOLDER__\":\"\"|\"$key\":\"$val\"|" "$tmp"
    fi
    mv "$tmp" "$STATE_FILE"
  else
    tmp="$(mktemp)"
    jq --arg k "$key" --arg v "$val" '.[$k]=$v' "$STATE_FILE" > "$tmp"
    mv "$tmp" "$STATE_FILE"
  fi
}

# ========= Argument parsing =========
DO_UNINSTALL=0
DO_PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) ASSUME_YES=1 ;;
    --noninteractive) NONINTERACTIVE=1 ASSUME_YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --uninstall) DO_UNINSTALL=1 ;;
    --purge) DO_UNINSTALL=1; DO_PURGE=1 ;;
    --help|-h)
      cat <<EOF
Usage: sudo bash $0 [--yes] [--noninteractive] [--dry-run] [--uninstall|--purge]

Environment overrides:
  PUB_PORT, WG_PORT, WG_SUBNET, MASKING

Examples:
  sudo bash $0 --dry-run
  sudo PUB_PORT=5349 WG_SUBNET=10.40.0.0/24 bash $0 -y
  sudo bash $0 --uninstall
  sudo bash $0 --purge
EOF
      exit 0
      ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

# ========= Uninstall =========
uninstall() {
  as_root
  log "Stopping services..."
  run "systemctl stop wg-obfuscator.service 2>/dev/null || true"
  run "systemctl disable wg-obfuscator.service 2>/dev/null || true"
  run "systemctl stop 'wg-quick@${WG_INT_NAME}.service' 2>/dev/null || true"
  run "systemctl disable 'wg-quick@${WG_INT_NAME}.service' 2>/dev/null || true"

  if [ -f "$NFT_SNIPPET" ] || [ "$DRY_RUN" = "1" ]; then
    log "Removing nftables ruleset..."
    run "nft list tables >/dev/null 2>&1 && { nft list tables | grep -qw '$NFT_TABLE_FILT' && nft delete table inet '$NFT_TABLE_FILT' || true; nft list tables | grep -qw '$NFT_TABLE_NAT' && nft delete table ip '$NFT_TABLE_NAT' || true; }"
    [ "$DRY_RUN" = "1" ] || rm -f "$NFT_SNIPPET"
    if run "systemctl is-enabled nftables >/dev/null 2>&1"; then
      run "systemctl reload nftables || true"
    fi
  fi

  if [ -f /etc/sysctl.d/99-wg-installer.conf ] || [ "$DRY_RUN" = "1" ]; then
    log "Reverting sysctl IPv4 forwarding..."
    [ "$DRY_RUN" = "1" ] || rm -f /etc/sysctl.d/99-wg-installer.conf
    run "sysctl -p >/dev/null 2>&1 || true"
  fi

  if [ -x "$OBF_BIN" ] || [ "$DRY_RUN" = "1" ]; then
    log "Removing wg-obfuscator binary..."
    [ "$DRY_RUN" = "1" ] || rm -f "$OBF_BIN"
  fi
  if [ -f "$OBF_SERVICE" ] || [ "$DRY_RUN" = "1" ]; then
    log "Removing wg-obfuscator service..."
    run "systemctl daemon-reload || true"
    [ "$DRY_RUN" = "1" ] || rm -f "$OBF_SERVICE"
  fi

  if [ "$DO_PURGE" = "1" ]; then
    log "Purging configuration and state..."
    [ "$DRY_RUN" = "1" ] || rm -f "$OBF_CONF"
    [ "$DRY_RUN" = "1" ] || rm -rf "$SRC_DIR"
    [ "$DRY_RUN" = "1" ] || rm -rf "$STATE_DIR"
    if command -v dpkg >/dev/null 2>&1; then
      run "apt-get -y purge wireguard wireguard-tools >/dev/null 2>&1 || true"
    fi
    [ "$DRY_RUN" = "1" ] || rm -f "$WG_CONF" "$WG_PRIV" "$WG_PUB"
    [ "$DRY_RUN" = "1" ] || rmdir "$WG_CONF_DIR" 2>/dev/null || true
  else
    log "Safe remove: configs/keys kept in /etc"
  fi

  log "Uninstall complete."
  exit 0
}
[ "$DO_UNINSTALL" = "1" ] && uninstall

# ========= Preflight =========
as_root
need_cmd ip
need_cmd systemctl
need_cmd awk
need_cmd sed
need_cmd ss
need_cmd modprobe || true

log "Detecting virtualization..."
VIRT_TYPE="$(systemd-detect-virt || true)"
[ -z "$VIRT_TYPE" ] && VIRT_TYPE="unknown"
json_put virt_type "$VIRT_TYPE"
log "Virtualization: $VIRT_TYPE"

log "Checking /dev/net/tun..."
if [ ! -e /dev/net/tun ]; then
  die "/dev/net/tun is missing. Enable TUN on host/container and rerun."
fi

log "Detecting WAN interface..."
WAN_IFACE="$(ip -4 route show default | awk '/default/ {print $5; exit}')"
[ -z "$WAN_IFACE" ] && die "No default IPv4 route found. IPv4 is required for wg-obfuscator."
json_put wan_iface "$WAN_IFACE"
log "WAN interface: $WAN_IFACE"

WAN_ADDR="$(ip -4 addr show dev "$WAN_IFACE" | awk '/inet / {print $2; exit}')"
[ -z "$WAN_ADDR" ] && die "No IPv4 address on $WAN_IFACE. wg-obfuscator is IPv4-only on the public side."
json_put wan_addr "$WAN_ADDR"
log "WAN IPv4: $WAN_ADDR"

# ========= Prompts =========
ui_detect
PUB_PORT="$(ui_input "wg-obfuscator" "Public UDP port for wg-obfuscator" "$DEFAULT_PUB_PORT")"
WG_PORT="$(ui_input "WireGuard" "Internal WireGuard port (loopback-only via firewall)" "$DEFAULT_WG_PORT")"
WG_SUBNET="$(ui_input "WireGuard" "WireGuard server subnet (IPv4 CIDR)" "$DEFAULT_SUBNET")"
# Prompt label corrected: STUTN -> STUN
MASKING="$(ui_menu  "Obfuscation" "Choose masking mode" \
          STUN "STUN emulation" AUTO "Auto-detect" NONE "No masking")"
# ensure default
[ -z "$MASKING" ] && MASKING="$DEFAULT_MASKING"
# correct a potential typo input (STUTN->STUN)
[ "$MASKING" = "STUTN" ] && MASKING="STUN"

[[ "$PUB_PORT" =~ ^[0-9]+$ ]] || die "Public port must be numeric."
[[ "$WG_PORT"  =~ ^[0-9]+$ ]] || die "WG port must be numeric."
echo "$WG_SUBNET" | awk -F'[./]' 'NF>=5 && $5>=0 && $5<=32' >/dev/null || die "Invalid IPv4 CIDR for WG subnet."

json_put public_port "$PUB_PORT"
json_put wg_port "$WG_PORT"
json_put wg_subnet "$WG_SUBNET"
json_put masking "$MASKING"

if ss -H -u -n | awk -v p=":$PUB_PORT" '$5 ~ p { found=1 } END{ exit !found }'; then
  die "Public UDP port $PUB_PORT already in use."
fi
if ss -H -u -n | awk -v p=":$WG_PORT" '$5 ~ p { found=1 } END{ exit !found }'; then
  log "Note: Internal WG port $WG_PORT appears in use; proceeding (may be existing wg0)."
fi

# ========= System update & packages =========
log "Updating APT and installing packages..."
export DEBIAN_FRONTEND=noninteractive
run "apt-get update -y"
run "apt-get upgrade -y"
  run "apt-get install -y --no-install-recommends wireguard wireguard-tools nftables iproute2 jq curl git build-essential ipcalc whiptail || apt-get install -y --no-install-recommends dialog"

# ========= Kernel WG availability / userspace fallback =========
WG_KERNEL_OK=1
if ! run "modprobe wireguard 2>/dev/null"; then
  log "Kernel WireGuard module not loadable; trying userspace wireguard-go..."
  WG_KERNEL_OK=0
  run "apt-get install -y wireguard-go"
fi
json_put wg_mode "$([ "$WG_KERNEL_OK" = "1" ] && echo kernel || echo userspace)"

# ========= WireGuard configuration =========
log "Ensuring /etc/wireguard and keys..."
ensure_dir "$WG_CONF_DIR" 700

if [ ! -f "$WG_PRIV" ]; then
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: Would generate WireGuard keys at $WG_PRIV / $WG_PUB"
  else
    need_cmd wg
    umask 077
    wg genkey | tee "$WG_PRIV" | wg pubkey > "$WG_PUB"
    chmod 600 "$WG_PRIV"
    chmod 644 "$WG_PUB"
    log "Generated WireGuard server keys."
  fi
else
  log "Existing WireGuard keys found; keeping."
fi

# Derive first usable host and prefix from the provided CIDR (e.g., 10.7.0.0/24)
PREFIX="${WG_SUBNET#*/}"
if FIRST_HOST="$(ipcalc "$WG_SUBNET" | awk '/HostMin/ {print $2; exit}')"; then
  WG_ADDR="$FIRST_HOST"
else
  # Fallback: keep the old simple heuristic (best-effort)
  WG_ADDR="$(echo "$WG_SUBNET" | awk -F/ '{print $1}')"
  WG_ADDR="${WG_ADDR%.*}.1"
fi

# We always render a fresh candidate; keep existing live file if present
TMP_WG="$(mktemp)"
if [ "$DRY_RUN" = "1" ]; then
  _wg_priv_val="<kept-existing-or-generated>"
else
  _wg_priv_val="$(cat "$WG_PRIV")"
fi
cat > "$TMP_WG" <<EOF
[Interface]
Address = ${WG_ADDR}/${PREFIX}
ListenPort = $WG_PORT
PrivateKey = ${_wg_priv_val}
SaveConfig = false
MTU = 1420
EOF

log "Enabling IPv4 forwarding via sysctl drop-in..."
if [ "$DRY_RUN" = "1" ]; then
  printf "[DRY-RUN] Would write /etc/sysctl.d/99-wg-installer.conf with: net.ipv4.ip_forward = 1\n"
  printf "[DRY-RUN] Would run: sysctl -p\n"
else
  write_file /etc/sysctl.d/99-wg-installer.conf 644 <<'EOF'
net.ipv4.ip_forward = 1
EOF
  run "sysctl -p >/dev/null 2>&1 || true"
fi

if [ ! -f "$WG_CONF" ]; then
  if [ "$DRY_RUN" = "1" ]; then
    printf "[DRY-RUN] Would create %s with contents:\n" "$WG_CONF"
    sed 's/^/[DRY-RUN]   /' "$TMP_WG"
  else
    mv "$TMP_WG" "$WG_CONF"
    chmod 600 "$WG_CONF"
    log "Created $WG_CONF"
  fi
else
  rm -f "$TMP_WG"
  log "Keeping existing $WG_CONF"
fi

# ========= Build/install wg-obfuscator =========
if [ ! -x "$OBF_BIN" ]; then
  log "Installing wg-obfuscator..."
  run "rm -rf '$SRC_DIR'"
  run "git clone --depth=1 https://github.com/ClusterM/wg-obfuscator '$SRC_DIR'"
  run "make -C '$SRC_DIR'"
  run "make -C '$SRC_DIR' install"
  if [ ! -f "$OBF_SERVICE" ]; then
    write_file "$OBF_SERVICE" 644 <<EOF
[Unit]
Description=WireGuard Obfuscator
After=network.target wg-quick@${WG_INT_NAME}.service
Wants=wg-quick@${WG_INT_NAME}.service

[Service]
Type=simple
ExecStart=${OBF_BIN} --config=${OBF_CONF}
Restart=always
RestartSec=2s
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  fi
else
  log "wg-obfuscator binary already present; skipping build."
fi

# ========= Create obfuscator config =========
if [ ! -f "$OBF_CONF" ]; then
  if [ "$DRY_RUN" = "1" ]; then
    OBF_KEY="<random-generated-on-apply>"
  else
    OBF_KEY="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    json_put obf_key "$OBF_KEY"
  fi
  write_file "$OBF_CONF" 600 <<EOF
# wg-obfuscator server config (IPv4-only public edge)
source-if = 0.0.0.0
source-lport = $PUB_PORT
target = 127.0.0.1:$WG_PORT
key = $OBF_KEY
masking = $MASKING
verbose = INFO
idle-timeout = 300
EOF
  log "Created $OBF_CONF"
else
  log "Keeping existing $OBF_CONF"
fi

# ========= nftables rules (minimal & persistent) =========
log "Configuring nftables rules..."
ensure_dir "$NFT_DIR" 755
write_file "$NFT_SNIPPET" 644 <<EOF
# Managed by wg-installer. Do not edit manually.
# Filter table (inet)
table inet $NFT_TABLE_FILT {
  chain input {
    type filter hook input priority 0;
    ct state established,related accept
    ip protocol icmp icmp type echo-request accept
    iif "lo" accept
    tcp dport 22 accept
    udp dport $PUB_PORT accept
    udp dport $WG_PORT iifname != "lo" drop
  }
  chain forward {
    type filter hook forward priority 0;
    ct state established,related accept
    iifname "$WG_INT_NAME" oifname "$WAN_IFACE" accept
    iifname "$WAN_IFACE" oifname "$WG_INT_NAME" accept
  }
}
# NAT table (IPv4 only)
table ip $NFT_TABLE_NAT {
  chain postrouting {
    type nat hook postrouting priority 100;
    oifname "$WAN_IFACE" ip saddr $WG_SUBNET masquerade
  }
}
EOF

if [ "$DRY_RUN" = "1" ]; then
  if [ -f "$NFT_MAIN" ]; then
    if ! grep -qF "${NFT_DIR}/*.nft" "$NFT_MAIN" 2>/dev/null; then
      printf "[DRY-RUN] Would append include \"%s/*.nft\" to %s\n" "$NFT_DIR" "$NFT_MAIN"
    else
      printf "[DRY-RUN] %s already includes %s/*.nft\n" "$NFT_MAIN" "$NFT_DIR"
    fi
  else
    printf "[DRY-RUN] Would create %s with: include \"%s/*.nft\"\n" "$NFT_MAIN" "$NFT_DIR"
  fi
  printf "[DRY-RUN] Would: systemctl enable nftables && systemctl restart nftables\n"
else
  # 1) Validate and apply the snippet transactionally at runtime
  run "nft -c -f '$NFT_SNIPPET'"
  run "nft -f '$NFT_SNIPPET'"
  if [ ! -f "$NFT_MAIN" ]; then
    write_file "$NFT_MAIN" 644 <<EOF
include "${NFT_DIR}/*.nft"
EOF
  elif ! grep -qF "${NFT_DIR}/*.nft" "$NFT_MAIN" 2>/dev/null; then
    append_file "$NFT_MAIN" 644 <<EOF
include "${NFT_DIR}/*.nft"
EOF
  fi
  run "systemctl enable nftables >/dev/null 2>&1 || true"
  # No forced restart needed; rules already applied transactionally above.
fi

# ========= Enable/start services =========
log "Enabling services..."
run "systemctl enable 'wg-quick@${WG_INT_NAME}.service' >/dev/null 2>&1 || true"
run "systemctl start  'wg-quick@${WG_INT_NAME}.service'"
run "systemctl daemon-reload"
run "systemctl enable wg-obfuscator.service >/dev/null 2>&1 || true"
run "systemctl restart wg-obfuscator.service"

# ========= Verify =========
if [ "$DRY_RUN" = "1" ]; then
  log "DRY-RUN verification steps (skipped execution):"
  printf "[DRY-RUN] Would check listeners: ss -lun | grep -E ':(%s|%s)\\\\b'\n" "$PUB_PORT" "$WG_PORT"
  printf "[DRY-RUN] Would run: wg show %s\n" "$WG_INT_NAME"
  printf "[DRY-RUN] Would run: nft list tables | grep -q '%s' and '%s'\n" "$NFT_TABLE_FILT" "$NFT_TABLE_NAT"
else
  sleep 1
  ss -lun | grep -E ":(?:$PUB_PORT|$WG_PORT)\b" >/dev/null || die "Expected UDP listeners not found."
  wg show "$WG_INT_NAME" >/dev/null 2>&1 || die "wg interface $WG_INT_NAME is not up."
  nft list tables | grep -q "$NFT_TABLE_FILT" || die "nftables filter table missing."
  nft list tables | grep -q "$NFT_TABLE_NAT"  || die "nftables NAT table missing."
fi

# ========= Persist state =========
json_put obf_public_port "$PUB_PORT"
json_put wg_internal_port "$WG_PORT"
json_put nft_rules "$NFT_SNIPPET"
json_put wg_conf "$WG_CONF"
json_put obf_conf "$OBF_CONF"

log "Installation complete."

cat <<EOF

=== SUMMARY ===
WireGuard:
  Interface: ${WG_INT_NAME}
  Config:    ${WG_CONF}
  Mode:      $([ "$WG_KERNEL_OK" = "1" ] && echo "kernel module" || echo "userspace (wireguard-go)")
  Subnet:    ${WG_SUBNET}
  Listen:    127.0.0.1:${WG_PORT} (enforced by nftables: external traffic to ${WG_PORT} dropped)

Obfuscator (IPv4 public edge):
  Binary:    ${OBF_BIN}
  Config:    ${OBF_CONF}
  Public:    0.0.0.0:${PUB_PORT}
  Masking:   ${MASKING}

Firewall (nftables):
  Snippet:   ${NFT_SNIPPET}
  NAT:       Masquerade ${WG_SUBNET} -> ${WAN_IFACE}
  Input:     SSH allowed, UDP ${PUB_PORT} allowed, direct UDP ${WG_PORT} blocked (except loopback)

State:
  ${STATE_FILE}

Uninstall:
  Safe remove (keep configs/keys): sudo bash $0 --uninstall
  Full purge  (remove all):         sudo bash $0 --purge
EOF