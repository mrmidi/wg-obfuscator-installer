from __future__ import annotations
from pathlib import Path
from wg_installer.core.fs import write_file
from wg_installer.core.runner import Runner

OBF_BIN = "/usr/local/bin/wg-obfuscator"
OBF_CONF = Path("/etc/wg-obfuscator.conf")
OBF_SERVICE = Path("/etc/systemd/system/wg-obfuscator.service")
WG_INT  = "wg0"

def ensure_obfuscator_built(r: Runner) -> None:
    if Path(OBF_BIN).exists():
        print("[wg-installer] wg-obfuscator binary already present; skipping build.")
        return
    src = "/usr/local/src/wg-obfuscator"
    r.run(["rm", "-rf", src], check=False)
    r.run(["git", "clone", "--depth=1", "https://github.com/ClusterM/wg-obfuscator", src])
    r.run(["make", "-C", src])
    r.run(["make", "-C", src, "install"])

def ensure_obfuscator_conf(config, r: Runner) -> str:
    if OBF_CONF.exists():
        print("[wg-installer] Keeping existing", OBF_CONF)
        return "existing"  # dummy
    obf_key = "<random-generated-on-apply>" if r.dry_run else r.shell(
        "head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'", capture=True).stdout.strip()
    content = (
        "# wg-obfuscator server config (IPv4-only public edge)\n"
        f"source-if = 0.0.0.0\n"
        f"source-lport = {config.pub_port}\n"
        f"target = 127.0.0.1:{config.wg_port}\n"
        f"key = {obf_key}\n"
        f"masking = {config.masking}\n"
        "verbose = INFO\n"
        "idle-timeout = 300\n"
    )
    write_file(OBF_CONF, content, 0o600, r.dry_run)

    service = (
        "[Unit]\n"
        "Description=WireGuard Obfuscator\n"
        f"After=network.target wg-quick@{WG_INT}.service\n"
        f"Wants=wg-quick@{WG_INT}.service\n\n"
        "[Service]\n"
        f"ExecStart={OBF_BIN} --config={OBF_CONF}\n"
        "Type=simple\n"
        "Restart=always\n"
        "RestartSec=2s\n"
        "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n"
        "NoNewPrivileges=true\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    write_file(OBF_SERVICE, service, 0o644, r.dry_run)
    return obf_key

def enable_services(r: Runner) -> None:
    r.run(["systemctl", "enable", f"wg-quick@{WG_INT}.service"], check=False)
    r.run(["systemctl", "start",  f"wg-quick@{WG_INT}.service"], check=False)
    r.run(["systemctl", "daemon-reload"], check=False)
    r.run(["systemctl", "enable", "wg-obfuscator.service"], check=False)
    r.run(["systemctl", "restart", "wg-obfuscator.service"], check=False)