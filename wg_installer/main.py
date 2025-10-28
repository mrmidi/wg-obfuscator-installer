#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import signal
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Optional

import re
import qrcode
from pydantic import BaseModel, Field, validator
from wg_installer.i18n.i18n import Translator, detect_lang
from wg_installer.cli import build_parser, init_i18n

# ---------- Paths / constants ----------
STATE_DIR = Path("/var/lib/wg-installer")
EXPORT_ROOT = STATE_DIR / "export"
WG_CONF_DIR = Path("/etc/wireguard")
WG_PRIV = WG_CONF_DIR / "privatekey"
WG_PUB = WG_CONF_DIR / "publickey"
WG_CONF = WG_CONF_DIR / "wg0.conf"
WG_INT_NAME = "wg0"

OBF_BIN = "/usr/local/bin/wg-obfuscator"
OBF_CONF = Path("/etc/wg-obfuscator.conf")
OBF_SERVICE = Path("/etc/systemd/system/wg-obfuscator.service")

NFT_DIR = Path("/etc/nftables.d")
NFT_MAIN = Path("/etc/nftables.conf")
NFT_SNIPPET = NFT_DIR / "50-wg-installer.nft"
NFT_TABLE_FILT = "wginst"
NFT_TABLE_NAT = "wginst_nat"

STATE_FILE = STATE_DIR / "state.json"

DEFAULT_PUB_PORT = int(os.environ.get("PUB_PORT", "3478"))
DEFAULT_WG_PORT = int(os.environ.get("WG_PORT", "51820"))
DEFAULT_SUBNET = os.environ.get("WG_SUBNET", "10.7.0.0/24")
DEFAULT_MASKING = os.environ.get("MASKING", "STUN")  # STUN|AUTO|NONE

HTTP_SHARE_DEFAULT_PORT = int(os.environ.get("HTTP_SHARE_PORT", "8080"))

# ---------- Config Model ----------
class ServerConfig(BaseModel):
    public_host: str
    pub_port: int = Field(ge=1, le=65535)
    wg_port: int = Field(ge=1, le=65535)
    wg_subnet: str
    masking: str
    mtu: int = Field(ge=1200, le=1420)
    http_share: bool = False
    build_apk: bool = False

    @validator('wg_subnet')
    def validate_subnet(cls, v):
        try:
            net = ipaddress.ip_network(v, strict=False)
            if net.version != 4 or net.num_addresses < 4:
                raise ValueError
        except ValueError:
            raise ValueError(f'Invalid IPv4 subnet with at least 4 addresses: {v}')
        return v

    @validator('masking')
    def validate_masking(cls, v):
        v = v.strip().upper()
        if v == "STUTN":  # typo guard
            v = "STUN"
        if v not in ("STUN", "AUTO", "NONE"):
            raise ValueError(f'Invalid masking: {v}. Must be STUN, AUTO, or NONE')
        return v

# ---------- Utilities ----------
def run(cmd: list[str], dry: bool, check: bool = True, capture: bool = False):
    text = " ".join(cmd)
    if dry:
        print(f"[DRY-RUN] {text}")
        class Dummy:
            returncode = 0
            stdout = b""
            stderr = b""
        return Dummy()
    if capture:
        return subprocess.run(cmd, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return subprocess.run(cmd, check=check)


def _ensure_text(data: str | bytes) -> str:
    """Return *data* as a str regardless of whether bytes were provided."""
    if isinstance(data, bytes):
        return data.decode()
    return data

def write_file(path: Path, content: str, mode: int, dry: bool):
    if dry:
        print(f"[DRY-RUN] Would write file: {path} (mode {oct(mode)})")
        for line in content.splitlines():
            print(f"[DRY-RUN]   {line}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, mode)

def append_file(path: Path, content: str, mode: int, dry: bool):
    if dry:
        print(f"[DRY-RUN] Would append to file: {path} (mode {oct(mode)})")
        for line in content.splitlines():
            print(f"[DRY-RUN]   {line}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, mode)

def json_put(key: str, val: str, dry: bool):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if dry:
        print(f"[DRY-RUN] Would set state: {key}={val} in {STATE_FILE}")
        return
    data = {}
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text())
        except Exception:
            data = {}
    data[key] = val
    STATE_FILE.write_text(json.dumps(data, indent=2))

def detect_wan_iface_and_ip() -> tuple[str, str]:
    # Note: IPv4-only is intentional as wg-obfuscator works only with IPv4.
    try:
        out = subprocess.check_output(["ip", "-4", "route", "show", "default"], text=True)
    except Exception as e:
        raise SystemExit("No default IPv4 route found. IPv4 is required for wg-obfuscator.") from e

    tokens = out.strip().split()
    wan_iface = None
    for i, tok in enumerate(tokens):
        if tok == "dev" and i + 1 < len(tokens):
            wan_iface = tokens[i + 1]
            break
    if not wan_iface:
        raise SystemExit(f"Failed to parse default route line: {out.strip()}")

    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show", "dev", wan_iface], text=True)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                cidr = line.split()[1]  # e.g., "203.0.113.5/24"
                return wan_iface, cidr
    except Exception as e:
        raise SystemExit(f"No IPv4 address on {wan_iface}. wg-obfuscator is IPv4-only on the public side.") from e

    raise SystemExit("Failed to parse WAN IPv4.")

def first_host_and_client(nets: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, int]:
    net = ipaddress.ip_network(nets, strict=False)
    hosts = list(net.hosts())
    if len(hosts) < 2:
        raise SystemExit("Subnet too small for server+client.")
    server_ip, client_ip = hosts[0], hosts[1]
    return server_ip, client_ip, net.prefixlen

# ---------- Validation functions ----------
def validate_port(value: str) -> int:
    try:
        p = int(value)
    except ValueError:
        raise SystemExit(f"Port must be numeric: {value}")
    if not (1 <= p <= 65535):
        raise SystemExit(f"Port out of range: {p}")
    return p

def validate_cidr(value: str) -> str:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise SystemExit(f"Invalid CIDR: {value}")
    if net.version != 4:
        raise SystemExit(f"IPv4 only: {value}")
    if net.num_addresses < 4:
        raise SystemExit(f"Subnet too small: {value}")
    return value

def validate_masking(value: str) -> str:
    value = value.strip().upper()
    if value == "STUTN":  # typo guard
        value = "STUN"
    if value not in ("STUN", "AUTO", "NONE"):
        raise SystemExit(f"Invalid masking: {value}. Must be STUN, AUTO, or NONE")
    return value

def validate_mtu(value: str) -> int:
    try:
        m = int(value)
    except ValueError:
        raise SystemExit(f"MTU must be numeric: {value}")
    if not (1200 <= m <= 1420):
        raise SystemExit(f"MTU out of range: {m}. Must be 1200-1420")
    return m

# ---------- Installer Class ----------
class Installer:
    def __init__(self, args: argparse.Namespace, tr: Translator):
        self.args = args
        self.tr = tr
        self.dry = args.dry_run
        self.wan_iface: Optional[str] = None
        self.wan_cidr: Optional[str] = None
        self.config: Optional[ServerConfig] = None

    def detect_wan(self):
        # Note: IPv4-only is intentional as wg-obfuscator works only with IPv4.
        try:
            out = subprocess.check_output(["ip", "-4", "route", "show", "default"], text=True)
        except Exception as e:
            raise SystemExit("No default IPv4 route found. IPv4 is required for wg-obfuscator.") from e

        tokens = out.strip().split()
        wan_iface = None
        for i, tok in enumerate(tokens):
            if tok == "dev" and i + 1 < len(tokens):
                wan_iface = tokens[i + 1]
                break
        if not wan_iface:
            raise SystemExit(f"Failed to parse default route line: {out.strip()}")

        try:
            out = subprocess.check_output(["ip", "-4", "addr", "show", "dev", wan_iface], text=True)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    cidr = line.split()[1]  # e.g., "203.0.113.5/24"
                    self.wan_iface = wan_iface
                    self.wan_cidr = cidr
                    return
        except Exception as e:
            raise SystemExit(f"No IPv4 address on {wan_iface}. wg-obfuscator is IPv4-only on the public side.") from e

        raise SystemExit("Failed to parse WAN IPv4.")

    def ensure_packages(self):
        if shutil.which("apt-get") is None or shutil.which("dpkg-query") is None:
            print("[wg-installer] Skipping Debian package checks (apt/dpkg not found).")
            return

        needed = [
            "wireguard", "wireguard-tools", "nftables", "iproute2",
            "curl", "git", "build-essential"
        ]
        missing: list[str] = []
        for pkg in needed:
            r = subprocess.run(
                ["dpkg-query", "-W", "-f=${Status}", pkg],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            if "install ok installed" not in (r.stdout or ""):
                missing.append(pkg)

        if not missing:
            print("[wg-installer] All required packages present.")
            # Best-effort kernel module load
            run(["modprobe", "wireguard"], self.dry, check=False)
            return

        print(f"[wg-installer] Installing missing packages: {' '.join(missing)}")
        if self.dry:
            print(f"[DRY-RUN] apt-get install -y --no-install-recommends {' '.join(missing)}")
            return

        # Try to install without a global system upgrade
        rc = subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends", *missing]
        ).returncode
        if rc != 0:
            print("[wg-installer] apt-get install failed. You may need to run:", file=sys.stderr)
            print("  sudo apt-get update && sudo apt-get install -y --no-install-recommends " + " ".join(missing), file=sys.stderr)
            sys.exit(rc)

        run(["modprobe", "wireguard"], self.dry=False, check=False)

    def ensure_keys(self):
        WG_CONF_DIR.mkdir(parents=True, exist_ok=True)
        if WG_PRIV.exists() and WG_PUB.exists():
            print("[wg-installer] Existing WireGuard keys found; keeping.")
            return
        if self.dry:
            print(f"[DRY-RUN] Would generate WireGuard keys at {WG_PRIV} / {WG_PUB}")
            return
        subprocess.check_call(["wg", "genkey"], stdout=open(WG_PRIV, "wb"))
        with open(WG_PRIV, "rb") as f:
            priv = f.read()
        p = subprocess.Popen(["wg", "pubkey"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        pub, _ = p.communicate(priv)
        with open(WG_PUB, "wb") as f:
            f.write(pub)
        os.chmod(WG_PRIV, 0o600)
        os.chmod(WG_PUB, 0o644)
        print("[wg-installer] Generated WireGuard server keys.")

    def first_host_and_client(self, nets: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, int]:
        net = ipaddress.ip_network(nets, strict=False)
        hosts = list(net.hosts())
        if len(hosts) < 2:
            raise SystemExit("Subnet too small for server+client.")
        server_ip, client_ip = hosts[0], hosts[1]
        return server_ip, client_ip, net.prefixlen

    def create_wg_conf(self, server_ip: ipaddress.IPv4Address, prefix: int, wg_port: int, mtu: int):
        content = f'''[Interface]
Address = {server_ip}/{prefix}
ListenPort = {wg_port}
PrivateKey = {wg_private_key_text(self.dry)}
SaveConfig = false
MTU = {mtu}
'''
        if WG_CONF.exists():
            print("[wg-installer] Keeping existing", WG_CONF)
            return
        write_file(WG_CONF, content, 0o600, self.dry)

    def ensure_obfuscator_built(self):
        if Path(OBF_BIN).exists():
            print("[wg-installer] wg-obfuscator binary already present; skipping build.")
            return
        # Build from upstream
        src_dir = Path("/usr/local/src/wg-obfuscator")
        run(["rm", "-rf", str(src_dir)], self.dry)
        run(["git", "clone", "--depth=1", "https://github.com/ClusterM/wg-obfuscator", str(src_dir)], self.dry)
        run(["make", "-C", str(src_dir)], self.dry)
        run(["make", "-C", str(src_dir), "install"], self.dry)

    def ensure_obfuscator_conf(self, pub_port: int, wg_port: int, masking: str):
        if OBF_CONF.exists():
            print("[wg-installer] Keeping existing", OBF_CONF)
            return
        if masking == "STUTN":  # typo guard
            masking = "STUN"
        if self.dry:
            obf_key = "<random-generated-on-apply>"
        else:
            obf_key = subprocess.check_output(["bash", "-lc", "head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'"], text=True).strip()
            json_put("obf_key", obf_key, dry=False)
        content = f'''# wg-obfuscator server config (IPv4-only public edge)
source-if = 0.0.0.0
source-lport = {pub_port}
target = 127.0.0.1:{wg_port}
key = {obf_key}
masking = {masking}
verbose = INFO
idle-timeout = 300
'''
        write_file(OBF_CONF, content, 0o600, self.dry)

        service = f'''[Unit]
Description=WireGuard Obfuscator
After=network.target wg-quick@{WG_INT_NAME}.service
Wants=wg-quick@{WG_INT_NAME}.service

[Service]
Type=simple
ExecStart={OBF_BIN} --config={OBF_CONF}
Restart=always
RestartSec=2s
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
'''
        if not OBF_SERVICE.exists():
            write_file(OBF_SERVICE, service, 0o644, self.dry)

    def enable_services(self):
        systemctl(self.dry, "enable", f"wg-quick@{WG_INT_NAME}.service")
        systemctl(self.dry, "start",  f"wg-quick@{WG_INT_NAME}.service")
        systemctl(self.dry, "daemon-reload")
        systemctl(self.dry, "enable", "wg-obfuscator.service")
        systemctl(self.dry, "restart", "wg-obfuscator.service")

    def nft_apply_snippet(self):
        assert self.wan_iface
        snippet = f'''# Managed by wg-installer. Do not edit manually.
# Filter table (inet)
table inet {NFT_TABLE_FILT} {{
  chain input {{
    type filter hook input priority 0;
    ct state established,related accept
    ip protocol icmp icmp type echo-request accept
    iif "lo" accept
    tcp dport 22 accept
    udp dport {self.config.pub_port} accept
    udp dport {self.config.wg_port} iifname != "lo" drop
  }}
  chain forward {{
    type filter hook forward priority 0;
    ct state established,related accept
    iifname "{WG_INT_NAME}" oifname "{self.wan_iface}" accept
    iifname "{self.wan_iface}" oifname "{WG_INT_NAME}" accept
  }}
}}
# NAT table (IPv4 only)
table ip {NFT_TABLE_NAT} {{
  chain postrouting {{
    type nat hook postrouting priority 100;
    oifname "{self.wan_iface}" ip saddr {self.config.wg_subnet} masquerade
  }}
}}
'''
        write_file(NFT_SNIPPET, snippet, 0o644, self.dry)
        # Apply runtime safely
        if self.dry:
            print(f"[DRY-RUN] nft -c -f '{NFT_SNIPPET}' && nft -f '{NFT_SNIPPET}'")
        else:
            run(["nft", "-c", "-f", str(NFT_SNIPPET)], dry=False)
            run(["nft", "-f", str(NFT_SNIPPET)], dry=False)
        # Ensure main includes our directory
        if not NFT_MAIN.exists():
            append_file(NFT_MAIN, f'include "{NFT_DIR}/*.nft"\n', 0o644, self.dry)
        else:
            if f'{NFT_DIR}/*.nft' not in read_text(NFT_MAIN):
                append_file(NFT_MAIN, f'include "{NFT_DIR}/*.nft"\n', 0o644, self.dry)
        systemctl("enable nftables", self.dry)
        # No forced restart, rules already applied.

    def build_client_bundle(self) -> tuple[Path, str, ipaddress.IPv4Address, int]:
        EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
        pkg = EXPORT_ROOT / "pkg"
        pkg.mkdir(parents=True, exist_ok=True)

        srv_pub = "<server-pub>"
        if not self.dry:
            srv_pub = read_text(WG_PUB).strip()

        # Compute client ip: second host
        _, client_ip, prefix = self.first_host_and_client(self.config.wg_subnet)

        # Grab obfuscator server key from server conf
        obf_key = "<obf-key>"
        if not self.dry and OBF_CONF.exists():
            for line in read_text(OBF_CONF).splitlines():
                if line.strip().startswith("key"):
                    obf_key = line.split("=", 1)[1].strip()
                    break

        client_obf = pkg / "client-obf.conf"
        write_file(client_obf, f'''# wg-obfuscator client config
source-if = 127.0.0.1
source-lport = {self.config.wg_port}
target = {self.config.public_host}:{self.config.pub_port}
key = {obf_key}
masking = {self.config.masking}
verbose = INFO
idle-timeout = 300
''', 0o600, self.dry)

        # Generate client keys
        if self.dry:
            cli_priv, cli_pub = "DRYRUN_CLIENT_PRIVATE_KEY", "DRYRUN_CLIENT_PUBLIC_KEY"
        else:
            cli_priv = subprocess.check_output(["wg", "genkey"], text=True).strip()
            p = subprocess.Popen(["wg", "pubkey"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            cli_pub, _ = p.communicate(cli_priv)

        client_wg = pkg / "client-wg.conf"
        write_file(client_wg, f'''[Interface]
PrivateKey = {cli_priv}
Address = {client_ip}/{prefix}
DNS = 1.1.1.1

[Peer]
PublicKey = {srv_pub}
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:{self.config.wg_port}
PersistentKeepalive = 25
''', 0o600, self.dry)

        readme = pkg / "README.txt"
        write_file(readme, f'''WireGuard + Obfuscator Client Bundle
====================================

Server: {self.config.public_host}
Obfuscator public UDP: {self.config.pub_port}
WG internal (loopback-only on server): {self.config.wg_port}

Files:
  - client-obf.conf    (wg-obfuscator CLIENT -> talks to {self.config.public_host}:{self.config.pub_port})
  - client-wg.conf     (WireGuard -> connects to 127.0.0.1:{self.config.wg_port})

Linux/macOS quickstart:
  1) Start obfuscator client:
       sudo wg-obfuscator --config ./client-obf.conf
  2) Start WireGuard:
       sudo wg-quick up ./client-wg.conf
  3) Stop:
       sudo wg-quick down ./client-wg.conf
''', 0o644, self.dry)

        zip_name = f"wg-client-{self.config.public_host.replace(':','_')}-{self.config.pub_port}.zip"
        zip_path = EXPORT_ROOT / zip_name
        if self.dry:
            print(f"[DRY-RUN] Would create ZIP {zip_path}")
        else:
            if zip_path.exists():
                zip_path.unlink()
            shutil.make_archive(zip_path.with_suffix(""), "zip", root_dir=pkg)
            with open(EXPORT_ROOT / "SHA256SUMS.txt", "w") as sums:
                h = subprocess.check_output(["sha256sum", str(zip_path)], text=True).strip()
                sums.write(h + "\n")

        json_put("client_zip", str(zip_path), self.dry)
        return zip_path, cli_pub, client_ip, prefix

    def ensure_server_has_peer(self, client_pub: str, client_ip: ipaddress.IPv4Address, prefix: int):
        block = (
            "[Peer]\n"
            f"PublicKey = {client_pub.strip()}\n"
            f"AllowedIPs = {client_ip}/{prefix}\n"
            "PersistentKeepalive = 25\n"
        )
        if self.dry:
            print(f"[DRY-RUN] Would append peer to {WG_CONF}")
            for ln in block.splitlines():
                print(f"[DRY-RUN]   {ln}")
            return
        if not WG_CONF.exists():
            print(f"[ERROR] {WG_CONF} missing; cannot add peer.", file=sys.stderr)
            return
        text = read_text(WG_CONF)
        if f"PublicKey = {client_pub.strip()}" in text:
            print("[wg-installer] Peer already present in server config; skipping.")
            return
        with open(WG_CONF, "a", encoding="utf-8") as f:
            f.write("\n" + block)
        # Apply live if interface is up (best-effort)
        subprocess.run(["wg", "setconf", WG_INT_NAME, str(WG_CONF)], check=False)

    def share_over_http(self):
        # Use EXPORT_ROOT as docroot
        if self.dry:
            print(f"[DRY-RUN] Would start HTTP server on 0.0.0.0:{HTTP_SHARE_DEFAULT_PORT} serving {EXPORT_ROOT}")
            return

        os.chdir(EXPORT_ROOT)
        httpd = ThreadingHTTPServer(("0.0.0.0", HTTP_SHARE_DEFAULT_PORT), QuietHTTP)
        print(f"[wg-installer] HTTP share on http://{self.config.public_host}:{HTTP_SHARE_DEFAULT_PORT} (Ctrl+C to stop)")

        stop_event = threading.Event()

        def signal_handler(signum, frame):
            stop_event.set()

        signal.signal(signal.SIGINT, signal_handler)

        def _serve():
            try:
                while not stop_event.is_set():
                    httpd.handle_request()
            except Exception:
                pass

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        try:
            while t.is_alive() and not stop_event.is_set():
                time.sleep(0.2)
        finally:
            httpd.shutdown()
            t.join()

    def add_temp_nft_input_rule(self) -> str | None:
        if self.dry:
            print(f"[DRY-RUN] nft add rule inet {NFT_TABLE_FILT} input tcp dport {HTTP_SHARE_DEFAULT_PORT} accept comment wg-share")
            return None
        try:
            run(["nft", "add", "rule", "inet", NFT_TABLE_FILT, "input", "tcp", "dport", str(HTTP_SHARE_DEFAULT_PORT), "accept", "comment", "wg-share"], dry=False)
            out = subprocess.check_output(["nft", "--handle", "list", "chain", "inet", NFT_TABLE_FILT, "input"], text=True)
            for line in out.splitlines():
                if "wg-share" in line:
                    m = re.search(r'handle\s+(\d+)', line)
                    if m:
                        return m.group(1)
        except Exception:
            print("[WARN] Could not add/parse temporary nft rule (port may already be open?).")
        return None

    def del_temp_nft_rule(self, handle: str | None):
        if self.dry or handle is None:
            return
        try:
            run(["nft", "delete", "rule", "inet", NFT_TABLE_FILT, "input", "handle", handle], dry=False, check=False)
        except Exception:
            pass

    def run_installation(self):
        # Preflight
        if os.geteuid() != 0 and not self.dry:
            print("[ERROR] Must run as root.", file=sys.stderr)
            sys.exit(1)

        if not Path("/dev/net/tun").exists():
            print(self.tr.t("error.no_tun"), file=sys.stderr)
            sys.exit(1)

        self.detect_wan()
        json_put("wan_iface", self.wan_iface, self.dry)
        json_put("wan_addr", self.wan_cidr, self.dry)
        print(f"[wg-installer] {self.tr.t('log.detect_wan')}: {self.wan_iface}")
        print(f"[wg-installer] {self.tr.t('log.wan_ip')}: {self.wan_cidr}")

        defaults = {
            "default_host": self.wan_cidr.split("/")[0] if "/" in self.wan_cidr else "127.0.0.1",
            "pub_port": DEFAULT_PUB_PORT,
            "wg_port": DEFAULT_WG_PORT,
            "wg_subnet": DEFAULT_SUBNET,
            "masking": DEFAULT_MASKING,
            "mtu": 1420,
        }

        use_tui = not self.args.no_tui
        tui_cfg = None
        if use_tui:
            from wg_installer.tui import run_tui, Config as TUIConfig
            tui_cfg = run_tui(
                self.tr,
                default_public_host=defaults["default_host"],
                default_pub_port=defaults["pub_port"],
                default_wg_port=defaults["wg_port"],
                default_wg_subnet=defaults["wg_subnet"],
                default_masking=defaults["masking"],
                default_mtu=defaults["mtu"],
                default_http_share=bool(self.args.http_share),
                default_build_apk=False
            )

        if tui_cfg:
            config_data = {
                "public_host": tui_cfg.public_host,
                "pub_port": tui_cfg.pub_port,
                "wg_port": tui_cfg.wg_port,
                "wg_subnet": tui_cfg.wg_subnet,
                "masking": tui_cfg.masking,
                "mtu": tui_cfg.mtu,
                "http_share": tui_cfg.http_share,
                "build_apk": tui_cfg.build_apk,
            }
        else:
            # existing ask() fallbacks
            config_data = {
                "public_host": ask("prompt.public_host", defaults["default_host"], self.tr),
                "pub_port": validate_port(ask("prompt.public_port", str(defaults["pub_port"]), self.tr)),
                "wg_port": validate_port(ask("prompt.wg_port", str(defaults["wg_port"]), self.tr)),
                "wg_subnet": validate_cidr(ask("prompt.subnet", defaults["wg_subnet"], self.tr)),
                "masking": validate_masking(ask("prompt.masking", defaults["masking"], self.tr)),
                "mtu": validate_mtu(ask("prompt.mtu", str(defaults["mtu"]), self.tr)),
                "http_share": self.args.http_share,
                "build_apk": False,
            }

        self.config = ServerConfig(**config_data)

        # store chosen values
        json_put("public_port", str(self.config.pub_port), self.dry)
        json_put("wg_port", str(self.config.wg_port), self.dry)
        json_put("wg_subnet", self.config.wg_subnet, self.dry)
        json_put("masking", self.config.masking, self.dry)

        # Check for port conflicts
        if udp_port_in_use(self.config.pub_port):
            print(f"[WARN] Public port {self.config.pub_port} appears to be in use. Proceeding anyway.")
        if udp_port_in_use(self.config.wg_port):
            print(f"[WARN] WireGuard port {self.config.wg_port} appears to be in use. Proceeding anyway.")

        # Install system packages and enable forwarding
        self.ensure_packages()
        # Enable IPv4 forwarding
        sysctl_drop = Path("/etc/sysctl.d/99-wg-installer.conf")
        write_file(sysctl_drop, "net.ipv4.ip_forward = 1\n", 0o644, self.dry)
        if not self.dry:
            run(["sysctl", "-p", str(sysctl_drop)], dry=False, check=False)

        # Keys + confs
        self.ensure_keys()
        server_ip, _client_ip, prefix = self.first_host_and_client(self.config.wg_subnet)
        self.create_wg_conf(server_ip, prefix, self.config.wg_port, self.config.mtu)

        # Obfuscator
        self.ensure_obfuscator_built()
        self.ensure_obfuscator_conf(self.config.pub_port, self.config.wg_port, self.config.masking)

        # nftables
        self.nft_apply_snippet()

        # Services
        self.enable_services()

        # Build client bundle
        zip_path, cli_pub, client_ip, prefix = self.build_client_bundle()
        self.ensure_server_has_peer(cli_pub, client_ip, prefix)

        # HTTP share (optional)
        if self.config.http_share:
            # Make index + QR and open port
            # URLs
            zip_file = Path(str(zip_path)).name
            url_zip = f"http://{self.config.public_host}:{HTTP_SHARE_DEFAULT_PORT}/{zip_file}"

            # index.html
            html = f'''<!doctype html>
<meta charset="utf-8">
<title>WG Client Share</title>
<h1>WireGuard Client Download</h1>
<ul>
  <li><a href="{zip_file}">{zip_file}</a></li>
</ul>
<h2>QR Code</h2>
<p><img src="qr/client-zip.png" alt="ZIP QR" style="width:240px"></p>
'''
            write_file(EXPORT_ROOT / "index.html", html, 0o644, self.dry)
            qr_dir = EXPORT_ROOT / "qr"
            qr_print_and_png(url_zip, qr_dir / "client-zip.png", self.dry)

            # Temp nft rule
            handle = self.add_temp_nft_input_rule()
            try:
                print(f"[wg-installer] ZIP URL: {url_zip}")
                self.share_over_http()
            finally:
                self.del_temp_nft_rule(handle)

        # Summary
        print(f"=== {self.tr.t('summary.title')} ===")
        print(self.tr.t("summary.wireguard.title"))
        print(f"  {self.tr.t('summary.wireguard.interface')}: {WG_INT_NAME}")
        print(f"  {self.tr.t('summary.wireguard.config')}: {WG_CONF}")
        print(f"  {self.tr.t('summary.wireguard.subnet')}: {self.config.wg_subnet}")
        print(f"  {self.tr.t('summary.wireguard.listen')}: 127.0.0.1:{self.config.wg_port} ({self.tr.t('summary.wireguard.listen_enforced')})")
        print("")
        print(self.tr.t("summary.obfuscator.title"))
        print(f"  {self.tr.t('summary.obfuscator.binary')}: {OBF_BIN}")
        print(f"  {self.tr.t('summary.obfuscator.config')}: {OBF_CONF}")
        print(f"  {self.tr.t('summary.obfuscator.public')}: 0.0.0.0:{self.config.pub_port}")
        print(f"  {self.tr.t('summary.obfuscator.masking')}: {self.config.masking}")
        print("")
        print(self.tr.t("summary.firewall.title"))
        print(f"  {self.tr.t('summary.firewall.snippet')}: {NFT_SNIPPET}")
        print(f"  {self.tr.t('summary.firewall.nat')}: {self.tr.t('summary.firewall.nat_masquerade', subnet=self.config.wg_subnet, wan=self.wan_iface)}")
        print("")
        print(self.tr.t("summary.client_bundle.title"))
        print(f"  {self.tr.t('summary.client_bundle.zip')}: {zip_path}")

def ensure_packages(dry: bool):
    if shutil.which("apt-get") is None or shutil.which("dpkg-query") is None:
        print("[wg-installer] Skipping Debian package checks (apt/dpkg not found).")
        return

    needed = [
        "wireguard", "wireguard-tools", "nftables", "iproute2",
        "curl", "git", "build-essential"
    ]
    missing: list[str] = []
    for pkg in needed:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", pkg],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        if "install ok installed" not in (r.stdout or ""):
            missing.append(pkg)

    if not missing:
        print("[wg-installer] All required packages present.")
        # Best-effort kernel module load
        run(["modprobe", "wireguard"], dry, check=False)
        return

    print(f"[wg-installer] Installing missing packages: {' '.join(missing)}")
    if dry:
        print(f"[DRY-RUN] apt-get install -y --no-install-recommends {' '.join(missing)}")
        return

    # Try to install without a global system upgrade
    rc = subprocess.run(
        ["apt-get", "install", "-y", "--no-install-recommends", *missing]
    ).returncode
    if rc != 0:
        print("[wg-installer] apt-get install failed. You may need to run:", file=sys.stderr)
        print("  sudo apt-get update && sudo apt-get install -y --no-install-recommends " + " ".join(missing), file=sys.stderr)
        sys.exit(rc)

    run(["modprobe", "wireguard"], dry=False, check=False)

def ensure_keys(dry: bool):
    WG_CONF_DIR.mkdir(parents=True, exist_ok=True)
    if WG_PRIV.exists() and WG_PUB.exists():
        print("[wg-installer] Existing WireGuard keys found; keeping.")
        return
    if dry:
        print(f"[DRY-RUN] Would generate WireGuard keys at {WG_PRIV} / {WG_PUB}")
        return
    subprocess.check_call(["wg", "genkey"], stdout=open(WG_PRIV, "wb"))
    with open(WG_PRIV, "rb") as f:
        priv = f.read()
    p = subprocess.Popen(["wg", "pubkey"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    pub, _ = p.communicate(priv)
    with open(WG_PUB, "wb") as f:
        f.write(pub)
    os.chmod(WG_PRIV, 0o600)
    os.chmod(WG_PUB, 0o644)
    print("[wg-installer] Generated WireGuard server keys.")

def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def read_binary(path: Path) -> bytes:
    return path.read_bytes()

def wg_private_key_text(dry: bool) -> str:
    if dry:
        return "<kept-existing-or-generated>"
    return read_text(WG_PRIV).strip()

def systemctl(dry: bool, *args: str):
    if dry:
        print(f"[DRY-RUN] systemctl {' '.join(args)}")
        return
    subprocess.run(["systemctl", *args], check=False)

def enable_services(dry: bool):
    systemctl(dry, "enable", f"wg-quick@{WG_INT_NAME}.service")
    systemctl(dry, "start",  f"wg-quick@{WG_INT_NAME}.service")
    systemctl(dry, "daemon-reload")
    systemctl(dry, "enable", "wg-obfuscator.service")
    systemctl(dry, "restart", "wg-obfuscator.service")

def nft_apply_snippet(wan_iface: str, pub_port: int, wg_port: int, wg_subnet: str, dry: bool):
    snippet = f'''# Managed by wg-installer. Do not edit manually.
# Filter table (inet)
table inet {NFT_TABLE_FILT} {{
  chain input {{
    type filter hook input priority 0;
    ct state established,related accept
    ip protocol icmp icmp type echo-request accept
    iif "lo" accept
    tcp dport 22 accept
    udp dport {pub_port} accept
    udp dport {wg_port} iifname != "lo" drop
  }}
  chain forward {{
    type filter hook forward priority 0;
    ct state established,related accept
    iifname "{WG_INT_NAME}" oifname "{wan_iface}" accept
    iifname "{wan_iface}" oifname "{WG_INT_NAME}" accept
  }}
}}
# NAT table (IPv4 only)
table ip {NFT_TABLE_NAT} {{
  chain postrouting {{
    type nat hook postrouting priority 100;
    oifname "{wan_iface}" ip saddr {wg_subnet} masquerade
  }}
}}
'''
    write_file(NFT_SNIPPET, snippet, 0o644, dry)
    # Apply runtime safely
    if dry:
        print(f"[DRY-RUN] nft -c -f '{NFT_SNIPPET}' && nft -f '{NFT_SNIPPET}'")
    else:
        run(["nft", "-c", "-f", str(NFT_SNIPPET)], dry=False)
        run(["nft", "-f", str(NFT_SNIPPET)], dry=False)
    # Ensure main includes our directory
    if not NFT_MAIN.exists():
        append_file(NFT_MAIN, f'include "{NFT_DIR}/*.nft"\n', 0o644, dry)
    else:
        if f'{NFT_DIR}/*.nft' not in read_text(NFT_MAIN):
            append_file(NFT_MAIN, f'include "{NFT_DIR}/*.nft"\n', 0o644, dry)
    systemctl("enable nftables", dry)
    # No forced restart, rules already applied.

def create_wg_conf(server_ip: ipaddress.IPv4Address, prefix: int, wg_port: int, mtu: int, dry: bool):
    content = f'''[Interface]
Address = {server_ip}/{prefix}
ListenPort = {wg_port}
PrivateKey = {wg_private_key_text(dry)}
SaveConfig = false
MTU = {mtu}
'''
    if WG_CONF.exists():
        print("[wg-installer] Keeping existing", WG_CONF)
        return
    write_file(WG_CONF, content, 0o600, dry)

def ensure_obfuscator_built(dry: bool):
    if Path(OBF_BIN).exists():
        print("[wg-installer] wg-obfuscator binary already present; skipping build.")
        return
    # Build from upstream
    src_dir = Path("/usr/local/src/wg-obfuscator")
    run(["rm", "-rf", str(src_dir)], dry)
    run(["git", "clone", "--depth=1", "https://github.com/ClusterM/wg-obfuscator", str(src_dir)], dry)
    run(["make", "-C", str(src_dir)], dry)
    run(["make", "-C", str(src_dir), "install"], dry)

def ensure_obfuscator_conf(pub_port: int, wg_port: int, masking: str, dry: bool):
    if OBF_CONF.exists():
        print("[wg-installer] Keeping existing", OBF_CONF)
        return
    if masking == "STUTN":  # typo guard
        masking = "STUN"
    if dry:
        obf_key = "<random-generated-on-apply>"
    else:
        obf_key = subprocess.check_output(["bash", "-lc", "head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'"], text=True).strip()
        json_put("obf_key", obf_key, dry=False)
    content = f'''# wg-obfuscator server config (IPv4-only public edge)
source-if = 0.0.0.0
source-lport = {pub_port}
target = 127.0.0.1:{wg_port}
key = {obf_key}
masking = {masking}
verbose = INFO
idle-timeout = 300
'''
    write_file(OBF_CONF, content, 0o600, dry)

    service = f'''[Unit]
Description=WireGuard Obfuscator
After=network.target wg-quick@{WG_INT_NAME}.service
Wants=wg-quick@{WG_INT_NAME}.service

[Service]
Type=simple
ExecStart={OBF_BIN} --config={OBF_CONF}
Restart=always
RestartSec=2s
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
'''
    if not OBF_SERVICE.exists():
        write_file(OBF_SERVICE, service, 0o644, dry)

def ensure_server_has_peer(client_pub: str, client_ip: ipaddress.IPv4Address, prefix: int, dry: bool):
    block = (
        "[Peer]\n"
        f"PublicKey = {client_pub.strip()}\n"
        f"AllowedIPs = {client_ip}/{prefix}\n"
        "PersistentKeepalive = 25\n"
    )
    if dry:
        print(f"[DRY-RUN] Would append peer to {WG_CONF}")
        for ln in block.splitlines():
            print(f"[DRY-RUN]   {ln}")
        return
    if not WG_CONF.exists():
        print(f"[ERROR] {WG_CONF} missing; cannot add peer.", file=sys.stderr)
        return
    text = read_text(WG_CONF)
    if f"PublicKey = {client_pub.strip()}" in text:
        print("[wg-installer] Peer already present in server config; skipping.")
        return
    with open(WG_CONF, "a", encoding="utf-8") as f:
        f.write("\n" + block)
    # Apply live if interface is up (best-effort)
    subprocess.run(["wg", "setconf", WG_INT_NAME, str(WG_CONF)], check=False)

def build_client_bundle(public_host: str, pub_port: int, wg_port: int, wg_subnet: str, masking: str, dry: bool) -> tuple[Path, str, ipaddress.IPv4Address, int]:
    EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
    pkg = EXPORT_ROOT / "pkg"
    pkg.mkdir(parents=True, exist_ok=True)

    srv_pub = "<server-pub>"
    if not dry:
        srv_pub = read_text(WG_PUB).strip()

    # Compute client ip: second host
    _, client_ip, prefix = first_host_and_client(wg_subnet)

    # Grab obfuscator server key from server conf
    obf_key = "<obf-key>"
    if not dry and OBF_CONF.exists():
        for line in read_text(OBF_CONF).splitlines():
            if line.strip().startswith("key"):
                obf_key = line.split("=", 1)[1].strip()
                break

    client_obf = pkg / "client-obf.conf"
    write_file(client_obf, f'''# wg-obfuscator client config
source-if = 127.0.0.1
source-lport = {wg_port}
target = {public_host}:{pub_port}
key = {obf_key}
masking = {masking}
verbose = INFO
idle-timeout = 300
''', 0o600, dry)

    # Generate client keys
    if dry:
        cli_priv, cli_pub = "DRYRUN_CLIENT_PRIVATE_KEY", "DRYRUN_CLIENT_PUBLIC_KEY"
    else:
        cli_priv = subprocess.check_output(["wg", "genkey"], text=True).strip()
        p = subprocess.Popen(["wg", "pubkey"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        cli_pub, _ = p.communicate(cli_priv)

    client_wg = pkg / "client-wg.conf"
    write_file(client_wg, f'''[Interface]
PrivateKey = {cli_priv}
Address = {client_ip}/{prefix}
DNS = 1.1.1.1

[Peer]
PublicKey = {srv_pub}
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:{wg_port}
PersistentKeepalive = 25
''', 0o600, dry)

    readme = pkg / "README.txt"
    write_file(readme, f'''WireGuard + Obfuscator Client Bundle
====================================

Server: {public_host}
Obfuscator public UDP: {pub_port}
WG internal (loopback-only on server): {wg_port}

Files:
  - client-obf.conf    (wg-obfuscator CLIENT -> talks to {public_host}:{pub_port})
  - client-wg.conf     (WireGuard -> connects to 127.0.0.1:{wg_port})

Linux/macOS quickstart:
  1) Start obfuscator client:
       sudo wg-obfuscator --config ./client-obf.conf
  2) Start WireGuard:
       sudo wg-quick up ./client-wg.conf
  3) Stop:
       sudo wg-quick down ./client-wg.conf
''', 0o644, dry)

    zip_name = f"wg-client-{public_host.replace(':','_')}-{pub_port}.zip"
    zip_path = EXPORT_ROOT / zip_name
    if dry:
        print(f"[DRY-RUN] Would create ZIP {zip_path}")
    else:
        if zip_path.exists():
            zip_path.unlink()
        shutil.make_archive(zip_path.with_suffix(""), "zip", root_dir=pkg)
        with open(EXPORT_ROOT / "SHA256SUMS.txt", "w") as sums:
            h = subprocess.check_output(["sha256sum", str(zip_path)], text=True).strip()
            sums.write(h + "\n")

    json_put("client_zip", str(zip_path), dry)
    return zip_path, cli_pub, client_ip, prefix

def qr_print_and_png(text: str, png_path: Path, dry: bool):
    if dry:
        print(f"[DRY-RUN] Would generate QR for: {text}")
        return
    # PNG
    img = qrcode.make(text)
    png_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(png_path)
    # ANSI block print
    qr = qrcode.QRCode(border=1)
    qr.add_data(text)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    print()
    for row in matrix:
        print("".join("  " if not cell else "██" for cell in row))
    print()

class QuietHTTP(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

def share_over_http(public_host: str, port: int, dry: bool):
    # Use EXPORT_ROOT as docroot
    if dry:
        print(f"[DRY-RUN] Would start HTTP server on 0.0.0.0:{port} serving {EXPORT_ROOT}")
        return

    os.chdir(EXPORT_ROOT)
    httpd = ThreadingHTTPServer(("0.0.0.0", port), QuietHTTP)
    print(f"[wg-installer] HTTP share on http://{public_host}:{port} (Ctrl+C to stop)")

    stop_event = threading.Event()

    def signal_handler(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)

    def _serve():
        try:
            while not stop_event.is_set():
                httpd.handle_request()
        except Exception:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    try:
        while t.is_alive() and not stop_event.is_set():
            time.sleep(0.2)
    finally:
        httpd.shutdown()
        t.join()

def add_temp_nft_input_rule(port: int, dry: bool) -> str | None:
    if dry:
        print(f"[DRY-RUN] nft add rule inet {NFT_TABLE_FILT} input tcp dport {port} accept comment wg-share")
        return None
    try:
        run(["nft", "add", "rule", "inet", NFT_TABLE_FILT, "input", "tcp", "dport", str(port), "accept", "comment", "wg-share"], dry=False)
        out = subprocess.check_output(["nft", "--handle", "list", "chain", "inet", NFT_TABLE_FILT, "input"], text=True)
        for line in out.splitlines():
            if "wg-share" in line:
                m = re.search(r'handle\s+(\d+)', line)
                if m:
                    return m.group(1)
    except Exception:
        print("[WARN] Could not add/parse temporary nft rule (port may already be open?).")
    return None

def del_temp_nft_rule(handle: str | None, dry: bool):
    if dry or handle is None:
        return
    try:
        run(["nft", "delete", "rule", "inet", NFT_TABLE_FILT, "input", "handle", handle], dry=False, check=False)
    except Exception:
        pass


def ask(prompt: str, default: str, tr: Translator) -> str:
    """Prompt the user for input while supporting mocks in tests."""
    try:
        text = input(f"{tr.t(prompt)} [{default}]: ")
    except EOFError:
        return default
    response = text.strip()
    return response or default


# ---------- CLI ----------

def udp_port_in_use(port: int) -> bool:
    try:
        out = subprocess.check_output(["ss", "-H", "-u", "-n", "-l"], text=True)
    except Exception:
        return False
    for line in out.splitlines():
        if f":{port} " in line or line.rstrip().endswith(f":{port}"):
            return True
    return False

def main():
    parser = build_parser()
    args = parser.parse_args()
    tr = init_i18n(args)
    installer = Installer(args, tr)
    installer.run_installation()

if __name__ == "__main__":
    main()
