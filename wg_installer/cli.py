from __future__ import annotations
import argparse
import sys
from pathlib import Path
from wg_installer.i18n.i18n import Translator
from wg_installer.core.runner import Runner
from wg_installer.core.config import Config, first_host_and_client
from wg_installer.net.detect import detect_wan_iface_and_cidr
from wg_installer.wireguard.manager import ensure_keys, create_wg_conf
from wg_installer.obfuscator.manager import ensure_obfuscator_built, ensure_obfuscator_conf, enable_services
from wg_installer.firewall.nft import apply_rules
from wg_installer.core.fs import write_file
from wg_installer.tui.wizard import run_tui

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wg-installer", add_help=True)
    p.add_argument("--lang", default="auto", help="Language code (e.g. cs, ru, en) or 'auto'")
    p.add_argument("--list-langs", action="store_true", help="List available languages and exit")
    p.add_argument("--dry-run", action="store_true", help="Show actions without changing system")
    p.add_argument("--no-tui", action="store_true", help="Run in CLI mode instead of TUI")
    p.add_argument("--http-share", action="store_true", help="Start temporary HTTP share with QR codes")
    return p

def init_i18n(args) -> Translator:
    locales_dir = Path(__file__).parent / "i18n" / "locales"
    tr = Translator(locales_dir, args.lang)
    if args.list_langs:
        for code, name in tr.available().items():
            print(f"{code}\t{name}")
        raise SystemExit(0)
    return tr

def detect_public_host(r: Runner) -> str:
    """Detect public host (WAN IP) for clients.

    Strict behavior: only use the locally-detected WAN IPv4 address. If that
    is not available, abort and tell the user to provide the public host
    explicitly (no external HTTP fallback, no default to localhost).
    """
    wan_iface, wan_cidr = detect_wan_iface_and_cidr(r)
    if wan_cidr:
        return wan_cidr.split('/')[0]
    raise SystemExit(
        "Unable to detect WAN IPv4 address. Please provide a public hostname or IPv4 address explicitly."
    )

def ensure_packages(r: Runner) -> None:
    """Install required system packages."""
    import shutil
    if shutil.which("apt-get") is None or shutil.which("dpkg-query") is None:
        print("[wg-installer] Skipping Debian package checks (apt/dpkg not found).")
        return

    needed = [
        "wireguard", "wireguard-tools", "nftables", "iproute2",
        "curl", "git", "build-essential"
    ]
    missing = []
    for pkg in needed:
        res = r.run(
            ["dpkg-query", "-W", "-f=${Status}", pkg],
            capture=True, check=False
        )
        if "install ok installed" not in res.stdout:
            missing.append(pkg)

    if not missing:
        print("[wg-installer] All required packages present.")
        # Best-effort kernel module load
        r.run(["modprobe", "wireguard"], check=False)
        return

    print(f"[wg-installer] Installing missing packages: {' '.join(missing)}")
    if r.dry_run:
        print(f"[DRY-RUN] apt-get install -y --no-install-recommends {' '.join(missing)}")
        return

    # Try to install without a global system upgrade
    res = r.run(
        ["apt-get", "install", "-y", "--no-install-recommends"] + missing,
        check=False
    )
    if res.returncode != 0:
        print("[wg-installer] apt-get install failed. You may need to run:", file=sys.stderr)
        print("  sudo apt-get update && sudo apt-get install -y --no-install-recommends " + " ".join(missing), file=sys.stderr)
        raise SystemExit(res.returncode)

    r.run(["modprobe", "wireguard"], check=False)
    """Generate random obfuscator key. Reuses logic from bash script."""
    if r.dry_run:
        return "DRYRUN_OBF_KEY"
    # head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
    import subprocess
    result = subprocess.run(
        ["sh", "-c", "head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \\n'"],
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip()

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    tr = init_i18n(args)

    r = Runner(dry_run=args.dry_run)

    # Detect WAN
    wan_iface, wan_cidr = detect_wan_iface_and_cidr(r)
    print(f"WAN: {wan_iface} {wan_cidr}")

    # Defaults for TUI
    defaults = {
        "host": "auto",
        "pub_port": 3478,
        "wg_port": 51820,
        "wg_subnet": "10.0.0.0/24",
        "masking": "STUN",
        "mtu": 1420,
    }

    # Run TUI or CLI
    if not args.no_tui:
        tui_config = run_tui(tr, defaults)
        if tui_config is None:
            raise SystemExit("TUI cancelled")
        config = Config(
            public_host=tui_config.public_host,
            pub_port=tui_config.pub_port,
            wg_port=tui_config.wg_port,
            wg_subnet=tui_config.wg_subnet,
            masking=tui_config.masking,
            mtu=tui_config.mtu,
        )
    else:
        # CLI mode - use defaults for now
        config = Config(
            public_host="auto",  # Will be detected
            pub_port=3478,
            wg_port=51820,
            wg_subnet="10.0.0.0/24",
            masking="STUN"
        )

    # Detect public host if auto
    if config.public_host == "auto":
        config.public_host = detect_public_host(r)
        print(f"Detected public host: {config.public_host}")

    # Install system packages and enable forwarding
    ensure_packages(r)
    # Enable IPv4 forwarding
    sysctl_drop = Path("/etc/sysctl.d/99-wg-installer.conf")
    write_file(sysctl_drop, "net.ipv4.ip_forward = 1\n", 0o644, r.dry_run)
    if not r.dry_run:
        r.run(["sysctl", "-p", str(sysctl_drop)], check=False)

    # Ensure keys
    ensure_keys(r)

    # Create WG conf
    create_wg_conf(config, r)

    # Build obfuscator
    ensure_obfuscator_built(r)

    # Create obfuscator conf
    obf_key = ensure_obfuscator_conf(config, r)

    # Enable services
    enable_services(r)

    # Apply firewall rules
    apply_rules(config, wan_iface, r)

    # Build client bundle
    server_ip, client_ip, prefix = first_host_and_client(config.wg_subnet)
    zip_path = build_client_bundle(
        public_host=config.public_host,
        pub_port=config.pub_port,
        wg_port=config.wg_port,
        client_ip=client_ip,
        prefix=prefix,
        masking=config.masking,
        obf_key=obf_key,
        r=r
    )

    if args.http_share:
        # TODO: start HTTP share
        pass

    print("Installation complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())
