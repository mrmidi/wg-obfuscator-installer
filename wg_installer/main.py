#!/usr/bin/env python3
import ipaddress
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

import qrcode
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
    # Parse `ip -4 route show default` and `ip -4 addr show dev ...`
    try:
        out = subprocess.check_output(["ip", "-4", "route", "show", "default"], text=True)
        wan_iface = out.strip().split()[-1]
    except Exception:
        raise SystemExit("No default IPv4 route found. IPv4 is required for wg-obfuscator.")
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show", "dev", wan_iface], text=True)
        for tok in out.split():
            if tok.startswith("inet"):
                # format: inet 203.0.113.5/24
                # find token that looks like 1.2.3.4/nn
                pass
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                cidr = line.split()[1]
                return wan_iface, cidr
    except Exception:
        raise SystemExit(f"No IPv4 address on {wan_iface}. wg-obfuscator is IPv4-only on the public side.")
    raise SystemExit("Failed to parse WAN IPv4.")

def first_host_and_client(nets: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, int]:
    net = ipaddress.ip_network(nets, strict=False)
    hosts = list(net.hosts())
    if len(hosts) < 2:
        raise SystemExit("Subnet too small for server+client.")
    server_ip, client_ip = hosts[0], hosts[1]
    return server_ip, client_ip, net.prefixlen

def ensure_packages(dry: bool):
    pkgs = [
        "wireguard", "wireguard-tools", "nftables", "iproute2",
        "curl", "git", "build-essential"
    ]
    print("[wg-installer] Updating APT and installing packages...")
    run(["apt-get", "update", "-y"], dry)
    run(["apt-get", "upgrade", "-y"], dry)
    run(["apt-get", "install", "-y", "--no-install-recommends", *pkgs], dry)
    # Optional: try kernel module
    run(["modprobe", "wireguard"], dry, check=False)

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

def systemctl(cmd: str, dry: bool):
    run(["systemctl", *cmd.split()], dry, check=False)

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

def create_wg_conf(server_ip: ipaddress.IPv4Address, prefix: int, wg_port: int, dry: bool):
    content = f'''[Interface]
Address = {server_ip}/{prefix}
ListenPort = {wg_port}
PrivateKey = {wg_private_key_text(dry)}
SaveConfig = false
MTU = 1420
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
After=network.target wg-quick @{WG_INT_NAME}.service
Wants=wg-quick @{WG_INT_NAME}.service

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

def enable_services(dry: bool):
    systemctl(f"enable wg-quick @{WG_INT_NAME}.service", dry)
    systemctl(f"start wg-quick @{WG_INT_NAME}.service", dry)
    systemctl("daemon-reload", dry)
    systemctl("enable wg-obfuscator.service", dry)
    systemctl("restart wg-obfuscator.service", dry)

def build_client_bundle(public_host: str, pub_port: int, wg_port: int, wg_subnet: str, masking: str, dry: bool) -> Path:
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
    return zip_path

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

    def _serve():
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    try:
        while t.is_alive():
            time.sleep(0.2)
    finally:
        httpd.shutdown()
        t.join()

def add_temp_nft_input_rule(port: int, dry: bool) -> str | None:
    # Add temporary accept rule with a comment for cleanup
    if dry:
        print(f"[DRY-RUN] nft add rule inet {NFT_TABLE_FILT} input tcp dport {port} accept comment wg-share")
        return None
    try:
        run(["nft", "add", "rule", "inet", NFT_TABLE_FILT, "input", "tcp", "dport", str(port), "accept", "comment", "wg-share"], dry=False)
        out = subprocess.check_output(["nft", "--handle", "list", "chain", "inet", NFT_TABLE_FILT, "input"], text=True)
        for line in out.splitlines():
            if "wg-share" in line and "handle" in line:
                # last token is handle
                handle = line.strip().split()[-1]
                return handle
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

# ---------- CLI ----------
from wg_installer.cli import build_parser, init_i18n

def main():
    parser = build_parser()
    args = parser.parse_args()
    tr = init_i18n(args)

    dry = args.dry_run

    # Preflight
    if not Path("/dev/net/tun").exists():
        print(tr.t("error.no_tun"), file=sys.stderr)
        sys.exit(1)

    wan_iface, wan_cidr = detect_wan_iface_and_ip()
    json_put("wan_iface", wan_iface, dry)
    json_put("wan_addr", wan_cidr, dry)
    print(f"[wg-installer] {tr.t('log.detect_wan')}: {wan_iface}")
    print(f"[wg-installer] {tr.t('log.wan_ip')}: {wan_cidr}")

    # Prompts
    try:
        default_host = wan_cidr.split("/")[0]
    except Exception:
        default_host = "127.0.0.1"

    pub_port = DEFAULT_PUB_PORT
    wg_port = DEFAULT_WG_PORT
    wg_subnet = DEFAULT_SUBNET
    masking = DEFAULT_MASKING

    def ask(prompt: str, default: str) -> str:
        try:
            s = input(f"{tr.t(prompt)} [{default}]: ").strip()
            return s or default
        except EOFError:
            return default

    pub_port = int(ask("prompt.public_port", str(pub_port)))
    wg_port = int(ask("prompt.wg_port", str(wg_port)))
    wg_subnet = ask("prompt.subnet", wg_subnet)
    masking = ask("prompt.masking", masking)
    public_host = ask("prompt.public_host", default_host)

    json_put("public_port", str(pub_port), dry)
    json_put("wg_port", str(wg_port), dry)
    json_put("wg_subnet", wg_subnet, dry)
    json_put("masking", masking, dry)

    # Install system packages and enable forwarding
    ensure_packages(dry)
    # Enable IPv4 forwarding
    sysctl_drop = Path("/etc/sysctl.d/99-wg-installer.conf")
    write_file(sysctl_drop, "net.ipv4.ip_forward = 1\n", 0o644, dry)
    if not dry:
        run(["sysctl", "-p"], dry=False, check=False)

    # Keys + confs
    ensure_keys(dry)
    server_ip, _client_ip, prefix = first_host_and_client(wg_subnet)
    create_wg_conf(server_ip, prefix, wg_port, dry)

    # Obfuscator
    ensure_obfuscator_built(dry)
    ensure_obfuscator_conf(pub_port, wg_port, masking, dry)

    # nftables
    nft_apply_snippet(wan_iface, pub_port, wg_port, wg_subnet, dry)

    # Services
    enable_services(dry)

    # Build client bundle
    zip_path = build_client_bundle(public_host, pub_port, wg_port, wg_subnet, masking, dry)

    # HTTP share (optional)
    if args.http_share:
        # Make index + QR and open port
        # URLs
        zip_file = Path(str(zip_path)).name
        url_zip = f"http://{public_host}:{HTTP_SHARE_DEFAULT_PORT}/{zip_file}"

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
        write_file(EXPORT_ROOT / "index.html", html, 0o644, dry)
        qr_dir = EXPORT_ROOT / "qr"
        qr_print_and_png(url_zip, qr_dir / "client-zip.png", dry)

        # Temp nft rule
        handle = add_temp_nft_input_rule(HTTP_SHARE_DEFAULT_PORT, dry)
        try:
            print(f"[wg-installer] ZIP URL: {url_zip}")
            share_over_http(public_host, HTTP_SHARE_DEFAULT_PORT, dry)
        finally:
            del_temp_nft_rule(handle, dry)

    # Summary
    print(tr.t("summary.title"))
    print(tr.t("summary.wireguard.title"))
    print(f"  {tr.t("summary.wireguard.interface")}: {WG_INT_NAME}")
    print(f"  {tr.t("summary.wireguard.config")}: {WG_CONF}")
    print(f"  {tr.t("summary.wireguard.subnet")}: {wg_subnet}")
    print(f"  {tr.t("summary.wireguard.listen")}: 127.0.0.1:{wg_port} ({tr.t("summary.wireguard.listen_enforced")})")
    print("")
    print(tr.t("summary.obfuscator.title"))
    print(f"  {tr.t("summary.obfuscator.binary")}: {OBF_BIN}")
    print(f"  {tr.t("summary.obfuscator.config")}: {OBF_CONF}")
    print(f"  {tr.t("summary.obfuscator.public")}: 0.0.0.0:{pub_port}")
    print(f"  {tr.t("summary.obfuscator.masking")}: {masking}")
    print("")
    print(tr.t("summary.firewall.title"))
    print(f"  {tr.t("summary.firewall.snippet")}: {NFT_SNIPPET}")
    print(f"  {tr.t("summary.firewall.nat")}: {tr.t('summary.firewall.nat_masquerade', subnet=wg_subnet, wan=wan_iface)}")
    print("")
    print(tr.t("summary.client_bundle.title"))
    print(f"  {tr.t("summary.client_bundle.zip")}: {zip_path}")

if __name__ == "__main__":
    main()
