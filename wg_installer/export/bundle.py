from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from wg_installer.core.fs import write_file
from wg_installer.core.runner import Runner
from wg_installer.wireguard.manager import WG_PUB

EXPORT_ROOT = Path("/var/lib/wg-installer/export")


def _ensure_clean_pkg_dir(pkg: Path, dry_run: bool) -> None:
    """Make sure the export package directory exists and is empty."""
    if pkg.exists():
        if dry_run:
            print(f"[DRY-RUN] Would remove existing bundle directory {pkg}")
        else:
            shutil.rmtree(pkg)
    pkg.mkdir(parents=True, exist_ok=True)


def _read_server_public_key(dry_run: bool) -> str:
    if dry_run:
        return "<server-pub>"
    return WG_PUB.read_text(encoding="utf-8").strip()


def _generate_client_private_key(r: Runner) -> str:
    if r.dry_run:
        print("[DRY-RUN] wg genkey")
        return "DRYRUN_CLIENT_PRIVATE_KEY"
    return r.run(["wg", "genkey"], capture=True).stdout.strip()


def _write_client_configs(
    pkg: Path,
    *,
    public_host: str,
    pub_port: int,
    wg_port: int,
    client_ip: str,
    prefix: int,
    masking: str,
    obf_key: str,
    srv_pub: str,
    client_private_key: str,
    dry_run: bool,
) -> None:
    client_obf = pkg / "client-obf.conf"
    # Write client obfuscator config. Omit the `key` line if obf_key is
    # falsy (installer chose not to create a separate obfuscation key).
    obf_lines = [
        "# wg-obfuscator client config",
        "source-if = 127.0.0.1",
        f"source-lport = {wg_port}",
        f"target = {public_host}:{pub_port}",
    ]
    if obf_key:
        obf_lines.append(f"key = {obf_key}")
    obf_lines.extend([
        f"masking = {masking}",
        "verbose = INFO",
        "idle-timeout = 300",
    ])
    write_file(client_obf, "\n".join(obf_lines) + "\n", 0o600, dry_run)

    client_wg = pkg / "client-wg.conf"
    write_file(
        client_wg,
        """[Interface]
PrivateKey = {private_key}
Address = {client_ip}/{prefix}
DNS = 1.1.1.1

[Peer]
PublicKey = {server_public}
AllowedIPs = 0.0.0.0/0
Endpoint = {public_host}:{wg_port}
PersistentKeepalive = 25
""".format(
            private_key=client_private_key,
            client_ip=client_ip,
            prefix=prefix,
            server_public=srv_pub,
            public_host=public_host,
            wg_port=wg_port,
        ),
        0o600,
        dry_run,
    )

    readme = pkg / "README.txt"
    write_file(
        readme,
        """WireGuard + Obfuscator Client Bundle
    Server: {public_host}
    Obfuscator UDP: {pub_port}
    WG (public): {wg_port}
    """.format(
            public_host=public_host,
            pub_port=pub_port,
            wg_port=wg_port,
        ),
        0o644,
        dry_run,
    )


def _make_zip_archive(pkg: Path, export_root: Path, zip_name: str, dry_run: bool) -> Path:
    zip_path = export_root / zip_name
    if dry_run:
        print(f"[DRY-RUN] Would create ZIP {zip_path}")
        return zip_path

    if zip_path.exists():
        zip_path.unlink()

    base_name = str(zip_path.with_suffix(""))
    shutil.make_archive(base_name, "zip", root_dir=pkg)
    return zip_path


def _write_checksum(zip_path: Path, export_root: Path, dry_run: bool) -> None:
    if dry_run:
        print(f"[DRY-RUN] Would compute SHA256 for {zip_path}")
        return

    sha256 = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    sums_path = export_root / "SHA256SUMS.txt"
    sums_path.write_text(f"{sha256}  {zip_path.name}\n", encoding="utf-8")


def build_client_bundle(
    *,
    public_host: str,
    pub_port: int,
    wg_port: int,
    client_ip: str,
    prefix: int,
    masking: str,
    obf_key: str,
    r: Runner,
) -> Path:
    """Create a distributable client bundle containing WireGuard and obfuscator configs."""

    EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
    pkg_dir = EXPORT_ROOT / "pkg"
    _ensure_clean_pkg_dir(pkg_dir, r.dry_run)

    srv_pub = _read_server_public_key(r.dry_run)
    client_private_key = _generate_client_private_key(r)

    _write_client_configs(
        pkg_dir,
        public_host=public_host,
        pub_port=pub_port,
        wg_port=wg_port,
        client_ip=client_ip,
        prefix=prefix,
        masking=masking,
        obf_key=obf_key,
        srv_pub=srv_pub,
        client_private_key=client_private_key,
        dry_run=r.dry_run,
    )

    zip_filename = f"wg-client-{public_host.replace(':', '_')}-{pub_port}.zip"
    zip_path = _make_zip_archive(pkg_dir, EXPORT_ROOT, zip_filename, r.dry_run)
    _write_checksum(zip_path, EXPORT_ROOT, r.dry_run)

    return zip_path
