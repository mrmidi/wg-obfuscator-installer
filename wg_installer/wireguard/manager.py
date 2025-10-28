from __future__ import annotations
from pathlib import Path
from wg_installer.core.fs import write_file
from wg_installer.core.runner import Runner

WG_DIR = Path("/etc/wireguard")
WG_PRIV = WG_DIR / "privatekey"
WG_PUB  = WG_DIR / "publickey"
WG_CONF = WG_DIR / "wg0.conf"
WG_INT  = "wg0"

def ensure_keys(r: Runner) -> None:
    WG_DIR.mkdir(parents=True, exist_ok=True)
    if WG_PRIV.exists() and WG_PUB.exists():
        print("[wg-installer] Existing WireGuard keys found; keeping.")
        return
    if r.dry_run:
        print(f"[DRY-RUN] Would generate WireGuard keys at {WG_PRIV} / {WG_PUB}")
        return
    priv = r.run(["wg", "genkey"], capture=True).stdout
    (WG_PRIV).write_text(priv)
    pub = r.run(["bash","-lc", f"printf %s '{priv}' | wg pubkey"], capture=True).stdout
    (WG_PUB).write_text(pub)
    (WG_PRIV).chmod(0o600)
    (WG_PUB).chmod(0o644)
    print("[wg-installer] Generated WireGuard server keys.")

def wg_private_key_text(r: Runner) -> str:
    return "<kept-existing-or-generated>" if r.dry_run else WG_PRIV.read_text().strip()

def create_server_conf(server_ip: str, prefix: int, wg_port: int, mtu: int, r: Runner) -> None:
    content = (
        f"[Interface]\n"
        f"Address = {server_ip}/{prefix}\n"
        f"ListenPort = {wg_port}\n"
        f"PrivateKey = {wg_private_key_text(r)}\n"
        f"SaveConfig = false\n"
        f"MTU = {mtu}\n"
    )
    if WG_CONF.exists():
        print("[wg-installer] Keeping existing", WG_CONF)
        return
    write_file(WG_CONF, content, 0o600, r.dry_run)