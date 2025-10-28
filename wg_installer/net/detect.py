from __future__ import annotations
from wg_installer.core.runner import Runner

def detect_wan_iface_and_cidr(r: Runner) -> tuple[str, str]:
    """
    Return (wan_iface, wan_cidr)

    wan_iface: e.g. "eth0"
    wan_cidr:  e.g. "107.174.36.35/25"

    Fatal-exits with SystemExit if we can't determine a usable IPv4 uplink.
    """

    # Ask kernel for default IPv4 route (typically: "default via X.X.X.X dev eth0 src X.X.X.X ...")
    res_route = r.run(
        ["ip", "-4", "route", "show", "default"],
        capture=True,
        check=False,
    )

    # Normalize stdout to str
    route_out = res_route.stdout.decode("utf-8", "replace").strip() if isinstance(res_route.stdout, (bytes, bytearray)) else str(res_route.stdout).strip()

    if not route_out:
        raise SystemExit("No default IPv4 route found. IPv4 is required for wg-obfuscator.")

    # We take the last token as iface ("dev eth0" ... but some distros include extra fields).
    # Safer approach: scan tokens after the literal "dev".
    tokens = route_out.split()
    wan_iface = None
    for i, tok in enumerate(tokens):
        if tok == "dev" and i + 1 < len(tokens):
            wan_iface = tokens[i + 1]
            break
    if wan_iface is None:
        # fallback: last token
        wan_iface = tokens[-1]

    # Now query address info for that iface
    res_addr = r.run(
        ["ip", "-4", "addr", "show", "dev", wan_iface],
        capture=True,
        check=False,
    )

    addr_out = res_addr.stdout.decode("utf-8", "replace") if isinstance(res_addr.stdout, (bytes, bytearray)) else str(res_addr.stdout)

    wan_cidr = None
    for raw_line in addr_out.splitlines():
        line = raw_line.strip()
        # we're looking for: "inet 107.174.36.35/25 brd 107.174.36.127 scope global eth0"
        if line.startswith("inet "):
            parts = line.split()
            # parts[0] = "inet"
            # parts[1] = "107.174.36.35/25"
            if len(parts) > 1 and "/" in parts[1]:
                wan_cidr = parts[1]
                break

    if wan_cidr is None:
        raise SystemExit(f"No IPv4 address on {wan_iface}. wg-obfuscator is IPv4-only on the public side.")

    return wan_iface, wan_cidr