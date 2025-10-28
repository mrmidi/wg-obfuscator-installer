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
from wg_installer.export.bundle import build_client_bundle
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

def generate_obf_key(r: Runner) -> str:
    """Generate random obfuscator key. Reuses logic from bash script."""
    if r.dry_run:
        return "DRYRUN_OBF_KEY"
    # head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
    result = r.run(["head", "-c", "16", "/dev/urandom"], capture=True)
    result2 = r.run(["od", "-An", "-tx1"], input=result.stdout, capture=True)
    key = result2.stdout.replace(' ', '').replace('\n', '')
    return key

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    tr = init_i18n(args)

    r = Runner(dry_run=args.dry_run)

    # Detect WAN
    wan_iface, wan_cidr = detect_wan_iface_and_cidr(r)
    print(f"WAN: {wan_iface} {wan_cidr}")

    # Run TUI or CLI
    if not args.no_tui:
        config = run_tui(tr)
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

    # Generate obf key
    obf_key = generate_obf_key(r)

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
