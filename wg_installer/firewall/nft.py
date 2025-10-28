from __future__ import annotations
from pathlib import Path
import re
import ipaddress
from wg_installer.core.fs import write_file, append_file
from wg_installer.core.runner import Runner

NFT_DIR = Path("/etc/nftables.d")
NFT_MAIN = Path("/etc/nftables.conf")
NFT_SNIPPET = NFT_DIR / "50-wg-installer.nft"
NFT_TABLE_FILT = "wginst"
NFT_TABLE_NAT = "wginst_nat"


def _ensure_include_present(r: Runner) -> None:
        """Append include line to /etc/nftables.conf if not present (robust check)."""
        if not NFT_MAIN.exists():
                append_file(NFT_MAIN, f'include "{NFT_DIR}/*.nft"\n', 0o644, r.dry_run)
                return
        content = NFT_MAIN.read_text(encoding="utf-8")
        # Match include statements pointing at the nftables.d directory in a resilient way
        if not re.search(r'include\s+["\']?.*nftables\.d/\*\.nft["\']?', content):
                append_file(NFT_MAIN, f'include "{NFT_DIR}/*.nft"\n', 0o644, r.dry_run)


def apply_rules(config, wan: str, r: Runner) -> None:
        """Write and apply nftables rules for wg-installer.

        Behavior is controlled by config.expose_wg_port (bool):
            - False (default): secure-hide profile — drop direct WG UDP from non-loopback
                and accept only obfuscator public port. This makes wg-obfuscator the
                only public entrypoint.
            - True: open-access profile — accept WG UDP on the public interface.
        """

        # Validation: ports and subnet
        try:
                ipaddress.ip_network(config.wg_subnet, strict=False)
        except Exception as e:
                raise SystemExit(f"Invalid WG subnet: {config.wg_subnet}: {e}")
        for p in (config.pub_port, config.wg_port):
                try:
                        pv = int(p)
                except Exception:
                        raise SystemExit(f"Invalid port value: {p}")
                if not (1 <= pv <= 65535):
                        raise SystemExit(f"Port out of range: {p}")

        # Build rule body depending on desired exposure
        if getattr(config, "expose_wg_port", False):
                # Open access
                wg_rule = f"    udp dport {config.wg_port} accept\n"
        else:
                # Secure-hide: drop direct WG UDP unless loopback (force obfuscator use)
                wg_rule = f"    udp dport {config.wg_port} iifname != \"lo\" drop\n"

        snippet = f"""# Managed by wg-installer. Do not edit manually.
table inet {NFT_TABLE_FILT} {{
    chain input {{
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        ip protocol icmp icmp type echo-request accept
        iif "lo" accept
        tcp dport 22 accept
        udp dport {config.pub_port} accept
{wg_rule}  }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        iifname "wg0" oifname "{wan}" accept
        iifname "{wan}" oifname "wg0" accept
    }}
}}
table ip {NFT_TABLE_NAT} {{
    chain postrouting {{
        type nat hook postrouting priority 100;
        oifname "{wan}" ip saddr {config.wg_subnet} masquerade
    }}
}}
"""

        write_file(NFT_SNIPPET, snippet, 0o644, r.dry_run)

        # Apply safely: syntax check then apply
        if r.dry_run:
                print(f"[DRY-RUN] nft -c -f '{NFT_SNIPPET}' && nft -f '{NFT_SNIPPET}'")
        else:
                r.run(["nft", "-c", "-f", str(NFT_SNIPPET)])
                r.run(["nft", "-f", str(NFT_SNIPPET)])

        # Ensure main includes our directory (robust)
        _ensure_include_present(r)

        # Ensure nftables is enabled and reloaded
        r.run(["systemctl", "enable", "nftables"], check=False)
        r.run(["systemctl", "reload-or-restart", "nftables"], check=False)

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