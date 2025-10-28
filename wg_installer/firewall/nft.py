from __future__ import annotations
from pathlib import Path
from wg_installer.core.fs import write_file, append_file
from wg_installer.core.runner import Runner

NFT_DIR = Path("/etc/nftables.d")
NFT_MAIN = Path("/etc/nftables.conf")
NFT_SNIPPET = NFT_DIR / "50-wg-installer.nft"
NFT_TABLE_FILT = "wginst"
NFT_TABLE_NAT  = "wginst_nat"

def apply_rules(wan: str, pub_port: int, wg_port: int, wg_subnet: str, r: Runner) -> None:
    snippet = f"""# Managed by wg-installer. Do not edit manually.
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
    iifname "wg0" oifname "{wan}" accept
    iifname "{wan}" oifname "wg0" accept
  }}
}}
table ip {NFT_TABLE_NAT} {{
  chain postrouting {{
    type nat hook postrouting priority 100;
    oifname "{wan}" ip saddr {wg_subnet} masquerade
  }}
}}
"""
    write_file(NFT_SNIPPET, snippet, 0o644, r.dry_run)
    if r.dry_run:
        print(f"[DRY-RUN] nft -c -f '{NFT_SNIPPET}' && nft -f '{NFT_SNIPPET}'")
    else:
        r.run(["nft", "-c", "-f", str(NFT_SNIPPET)])
        r.run(["nft", "-f", str(NFT_SNIPPET)])
    if not NFT_MAIN.exists():
        append_file(NFT_MAIN, f'include "{NFT_DIR}/*.nft"\n', 0o644, r.dry_run)
    else:
        if f'{NFT_DIR}/*.nft' not in NFT_MAIN.read_text():
            append_file(NFT_MAIN, f'include "{NFT_DIR}/*.nft"\n', 0o644, r.dry_run)
    r.run(["systemctl", "enable", "nftables"], check=False)

def add_temp_http_rule(port: int, r: Runner) -> str | None:
    if r.dry_run:
        print(f"[DRY-RUN] nft add rule inet {NFT_TABLE_FILT} input tcp dport {port} accept comment wg-share")
        return None
    r.run(["nft","add","rule","inet",NFT_TABLE_FILT,"input","tcp","dport",str(port),"accept","comment","wg-share"], check=False)
    out = r.run(["nft","--handle","list","chain","inet",NFT_TABLE_FILT,"input"], capture=True, check=False).stdout
    for line in out.splitlines():
        if "wg-share" in line and "handle" in line:
            return line.strip().split()[-1]
    return None

def del_temp_http_rule(handle: str | None, r: Runner) -> None:
    if not handle or r.dry_run:
        return
    r.run(["nft","delete","rule","inet",NFT_TABLE_FILT,"input","handle",handle], check=False)