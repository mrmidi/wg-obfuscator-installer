from __future__ import annotations
import argparse
import sys
import secrets
from pathlib import Path
from wg_installer.i18n.i18n import Translator
from wg_installer.core.runner import Runner
from wg_installer.core.config import Config, first_host_and_client
from wg_installer.net.detect import detect_wan_iface_and_cidr
from wg_installer.wireguard.manager import ensure_keys, create_wg_conf
from wg_installer.obfuscator.manager import ensure_obfuscator_built, ensure_obfuscator_conf, enable_services
from wg_installer.firewall.nft import apply_rules
from wg_installer.core.fs import write_file
from wg_installer.export.bundle import build_client_bundle
from wg_installer.export.http_share import serve_files
from wg_installer.tui.wizard import run_tui
from wg_installer.tui.textual_wizard import run_textual_wizard, Config as TuiConfig
from wg_installer.core.state import StateDB

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wg-installer", add_help=True)
    p.add_argument("--lang", default="auto", help="Language code (e.g. cs, ru, en) or 'auto'")
    p.add_argument("--list-langs", action="store_true", help="List available languages and exit")
    p.add_argument("--dry-run", action="store_true", help="Show actions without changing system")
    p.add_argument("--no-tui", action="store_true", help="Run in CLI mode instead of TUI")
    p.add_argument("--http-share", action="store_true", help="Start temporary HTTP share with QR codes")
    p.add_argument("--http-port", type=int, default=8080, help="Port for HTTP share")
    p.add_argument("--uninstall", action="store_true", help="Revert installation (stop services, remove files)")
    p.add_argument("--build-apk", action="store_true", help="Build Android APK with injected config")
    p.add_argument("--apk-output-dir", type=Path, default=None, help="Directory to save the built APK")
    # We do not provide an option to block WireGuard externally. WireGuard
    # UDP port is exposed so wg-obfuscator can obfuscate live connections.
    # New: allow passing a specific obfuscator key as text. If provided,
    # that exact text will be used. For non-interactive installs you can
    # use --obf-key "<key>". For older behavior (auto-generate a key),
    # use --create-obf-key which will create a random key and include it.
    p.add_argument("--obf-key", type=str, default=None,
                   help="Set obfuscator key (text). If omitted, no key line will be written.")
    p.add_argument("--create-obf-key", action="store_true", default=False,
                   help="Generate a random wg-obfuscator key and include it in configs")
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


def uninstall(r: Runner) -> None:
    """Best-effort revert of what the installer does. Requires explicit confirmation.

    This will stop/disable services, delete installed binaries/configs/snippets and
    remove the export/state directory. It's intentionally conservative and best-effort.
    """
    if not r.dry_run:
        ans = input("This will attempt to remove wg-obfuscator, WireGuard config and installer state. Type 'yes' to proceed: ")
        if ans.strip().lower() != "yes":
            print("Aborting uninstall.")
            return

    print("[wg-installer] Stopping and disabling services (best-effort)")
    r.run(["systemctl", "stop", "wg-obfuscator.service"], check=False)
    r.run(["systemctl", "disable", "wg-obfuscator.service"], check=False)
    r.run(["systemctl", "stop", "wg-quick@wg0.service"], check=False)
    r.run(["systemctl", "disable", "wg-quick@wg0.service"], check=False)
    r.run(["systemctl", "daemon-reload"], check=False)

    # Remove installed binaries and config files
    candidates = ["/usr/bin/wg-obfuscator", "/usr/local/bin/wg-obfuscator", "/etc/wg-obfuscator.conf", "/etc/systemd/system/wg-obfuscator.service", "/etc/nftables.d/50-wg-installer.nft"]
    for p in candidates:
        print(f"[wg-installer] Removing {p} (if exists)")
        r.run(["rm", "-f", p], check=False)

    # WireGuard server files (do not remove whole /etc/wireguard unless explicit)
    print("[wg-installer] Removing generated WireGuard files: /etc/wireguard/wg0.conf /etc/wireguard/privatekey /etc/wireguard/publickey (if they exist)")
    r.run(["rm", "-f", "/etc/wireguard/wg0.conf"], check=False)
    r.run(["rm", "-f", "/etc/wireguard/privatekey"], check=False)
    r.run(["rm", "-f", "/etc/wireguard/publickey"], check=False)

    # Remove export and state
    print("[wg-installer] Removing state and export directory /var/lib/wg-installer (if exists)")
    r.run(["rm", "-rf", "/var/lib/wg-installer"], check=False)

    # Reload nftables/systemd so changes take effect
    r.run(["systemctl", "restart", "nftables"], check=False)
    r.run(["systemctl", "daemon-reload"], check=False)
    print("[wg-installer] Uninstall steps completed (best-effort). You may want to review system state manually.")

def ensure_packages(r: Runner) -> None:
    """Install required system packages."""
    import shutil
    if shutil.which("apt-get") is None or shutil.which("dpkg-query") is None:
        print("[wg-installer] Skipping Debian package checks (apt/dpkg not found).")
        return

    needed = [
        "wireguard", "wireguard-tools", "nftables", "iproute2",
        "curl", "git", "build-essential", "default-jdk", "unzip"
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
    return

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    tr = init_i18n(args)

    r = Runner(dry_run=args.dry_run)

    # If uninstall requested, run uninstall flow and exit
    if args.uninstall:
        uninstall(r)
        return 0

    # Detect WAN
    wan_iface, wan_cidr = detect_wan_iface_and_cidr(r)
    print(f"WAN: {wan_iface} {wan_cidr}")

    # Defaults for TUI
    defaults = {
        # Default to auto-detect the public host; the installer will only
        # try to detect a WAN address when `public_host` == "auto".
        "host": "auto",
        "pub_port": 3478,
        "wg_port": 51820,
        "wg_subnet": "10.7.0.0/24",
        "masking": "STUN",
        "mtu": 1420,
    }

    # Run TUI or CLI
    if not args.no_tui:
        cfg = run_textual_wizard(
            default_public_host=defaults["host"],
            default_pub_port=defaults["pub_port"],
            default_wg_port=defaults["wg_port"],
            default_wg_subnet=defaults["wg_subnet"],
            default_masking=defaults["masking"],
            default_mtu=defaults["mtu"],
            default_http_share=False,
            default_build_apk=False,
            # block_wg removed — we always expose WireGuard public port
            default_create_obf_key=False,
        )
        if cfg is None:
            # fallback to old TUI
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
                # block_wg removed
                create_obf_key=getattr(tui_config, "create_obf_key", None),
            )
            args.http_share = args.http_share or tui_config.http_share
            args.build_apk = args.build_apk or tui_config.build_apk
        else:
            config = Config(
                public_host=cfg.public_host,
                pub_port=cfg.pub_port,
                wg_port=cfg.wg_port,
                wg_subnet=cfg.wg_subnet,
                masking=cfg.masking,
                mtu=cfg.mtu,
                # block_wg removed
                create_obf_key=getattr(cfg, "create_obf_key", None),
            )
            args.http_share = args.http_share or cfg.http_share
            args.build_apk = args.build_apk or cfg.build_apk
    else:
        # CLI mode - use defaults for now
        # Determine obfuscator key for non-interactive CLI mode. Priority:
        # 1) --obf-key explicit string
        # 2) --create-obf-key -> generate a random key
        # 3) omitted -> None (no key line will be written)
        obf_key_val = None
        if getattr(args, "obf_key", None):
            obf_key_val = args.obf_key.strip() or None
        elif getattr(args, "create_obf_key", False):
            # generate a reasonably random URL-safe token
            obf_key_val = secrets.token_urlsafe(24)

        config = Config(
            public_host="auto",
            pub_port=3478,
            wg_port=51820,
            wg_subnet="10.7.0.0/24",
            masking="STUN",
            mtu=1420,
            # block_wg removed
            create_obf_key=obf_key_val,
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
    apk_name = None
    if args.build_apk:
        from wg_installer.android.builder import AndroidAPKBuilder, AndroidBuildConfig
        state_db = StateDB(Path("/var/lib/wg-installer/state.json"))
        build_config = AndroidBuildConfig(apk_output_dir=args.apk_output_dir or Path("/var/lib/wg-installer/export"))
        builder = AndroidAPKBuilder(build_config, r, state_db)
        apk_path = builder.build_apk(config)
        apk_name = Path(apk_path).name if apk_path is not None else None
        print(f"APK built: {apk_path}")

    if args.http_share:
        # If we built an APK, share both APK and ZIP; otherwise share only ZIP
        serve_files(config.public_host, args.http_port, zip_path.name, apk_name, r)

    print("Installation complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())
