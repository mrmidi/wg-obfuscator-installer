from __future__ import annotations
from . import __init__  # keep package import happy
from wg_installer.core.runner import Runner

def detect_wan_iface_and_cidr(r: Runner) -> tuple[str, str]:
    out = r.run(["ip", "-4", "route", "show", "default"], capture=True, check=False).stdout.strip()
    if not out:
        raise SystemExit("No default IPv4 route found.")
    wan_iface = out.split()[-1]
    out2 = r.run(["ip", "-4", "addr", "show", "dev", wan_iface], capture=True, check=False).stdout
    cidr = None
    for line in out2.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            # e.g. "inet 107.174.36.35/25 brd ..."
            cidr = line.split()[1]
            break
    if not cidr:
        raise SystemExit(f"No IPv4 address on {wan_iface}.")
    return wan_iface, cidr