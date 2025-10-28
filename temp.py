import subprocess

def _run(cmd: list[str]) -> str:
    """Run a command and return stdout as text, stripped. Raise if fails."""
    out = subprocess.check_output(cmd, text=True)
    return out.strip()

def get_default_iface() -> str:
    """
    Returns the interface name used for the default IPv4 route, e.g. 'eth0'.
    Equivalent to: ip -4 route show default | awk '/default/ {print $5; exit}'
    """
    route_out = _run(["ip", "-4", "route", "show", "default"])
    # example: "default via 203.0.113.1 dev eth0 proto dhcp src 203.0.113.5 metric 100"
    for token in route_out.split():
        # "dev eth0" pattern -> grab the word after "dev"
        # (this is slightly more robust than 'last field')
        # We'll scan for "dev" and return the next token.
        if token == "dev":
            # get index of "dev"
            tokens = route_out.split()
            for i, t in enumerate(tokens):
                if t == "dev" and i + 1 < len(tokens):
                    return tokens[i + 1]
    # Fallback: last field heuristic
    return route_out.split()[-1]

def get_iface_ipv4_cidr(iface: str) -> str:
    """
    Returns first IPv4 CIDR on the interface, e.g. '203.0.113.5/24'.
    Equivalent to: ip -4 addr show dev eth0 | awk '/inet / {print $2; exit}'
    """
    addr_out = _run(["ip", "-4", "addr", "show", "dev", iface])
    for line in addr_out.splitlines():
        line = line.strip()
        # lines look like: "inet 203.0.113.5/24 brd 203.0.113.255 scope global eth0"
        if line.startswith("inet "):
            parts = line.split()
            # parts[1] should be '203.0.113.5/24'
            if len(parts) > 1:
                return parts[1]
    raise RuntimeError(f"No IPv4 address found on {iface}")

def get_iface_ipv4_addr_only(cidr: str) -> str:
    """
    From '203.0.113.5/24' return just '203.0.113.5'.
    """
    return cidr.split("/", 1)[0]

def get_primary_ipv4() -> tuple[str, str, str]:
    """
    High-level helper:
    - detect default iface
    - get its first IPv4 (CIDR + raw IP)
    Returns (iface, ip_addr, ip_cidr)
    """
    iface = get_default_iface()
    cidr = get_iface_ipv4_cidr(iface)
    ip_only = get_iface_ipv4_addr_only(cidr)
    return iface, ip_only, cidr

if __name__ == "__main__":
    iface, ip_only, cidr = get_primary_ipv4()
    print(f"Interface: {iface}")
    print(f"IPv4:      {ip_only}")
    print(f"CIDR:      {cidr}")
