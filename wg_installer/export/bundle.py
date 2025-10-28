from __future__ import annotations
import shutil
from pathlib import Path
from wg_installer.core.fs import write_file
from wg_installer.core.runner import Runner
from wg_installer.wireguard.manager import WG_PUB

EXPORT_ROOT = Path("/var/lib/wg-installer/export")

def build_client_bundle(public_host: str, pub_port: int, wg_port: int,
                        client_ip: str, prefix: int, masking: str,
                        obf_key: str, r: Runner) -> Path:
    EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
    pkg = EXPORT_ROOT / "pkg"
    pkg.mkdir(parents=True, exist_ok=True)

    srv_pub = "<server-pub>" if r.dry_run else WG_PUB.read_text().strip()

    client_obf = pkg / "client-obf.conf"
    write_file(client_obf, f"""# wg-obfuscator client config
source-if = 127.0.0.1
source-lport = {wg_port}
target = {public_host}:{pub_port}
key = {obf_key}
masking = {masking}
verbose = INFO
idle-timeout = 300
""", 0o600, r.dry_run)

    if r.dry_run:
        cli_priv = "DRYRUN_CLIENT_PRIVATE_KEY"
    else:
        cli_priv = r.run(["wg","genkey"], capture=True).stdout.strip()

    client_wg = pkg / "client-wg.conf"
    write_file(client_wg, f"""[Interface]
PrivateKey = {cli_priv}
Address = {client_ip}/{prefix}
DNS = 1.1.1.1

[Peer]
PublicKey = {srv_pub}
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:{wg_port}
PersistentKeepalive = 25
""", 0o600, r.dry_run)

    readme = pkg / "README.txt"
    write_file(readme, f"""WireGuard + Obfuscator Client Bundle
Server: {public_host}
Obfuscator UDP: {pub_port}
WG (local): {wg_port}
""", 0o644, r.dry_run)

    zip_path = EXPORT_ROOT / f"wg-client-{public_host.replace(':','_')}-{pub_port}.zip"
    if r.dry_run:
        print(f"[DRY-RUN] Would create ZIP {zip_path}")
    else:
        if zip_path.exists(): zip_path.unlink()
        shutil.make_archive(zip_path.with_suffix(""), "zip", root_dir=pkg)
        sums = (EXPORT_ROOT / "SHA256SUMS.txt")
        sums.write_text(r.shell(f"sha256sum {zip_path}", capture=True).stdout)

    return zip_path