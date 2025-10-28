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
        # If a config already exists, try to read the server key from it so
        # the client bundle can use the same key.
        print("[wg-installer] Keeping existing", OBF_CONF)
        try:
            text = OBF_CONF.read_text(encoding="utf-8")
            for line in text.splitlines():
                ln = line.strip()
                if ln.startswith("key"):
                    # format: key = <value>
                    parts = ln.split("=", 1)
                    if len(parts) > 1:
                        return parts[1].strip()
        except Exception:
            pass
        return "existing"  # fallback
    # The obfuscator key is optional. If `create_obf_key` is provided as a
    # non-empty string it will be used verbatim. If it is None/empty we omit
    # the `key =` line.
    obf_key = ""
    key_val = getattr(config, "create_obf_key", None)
    if key_val:
        # Use the provided key string (strip whitespace).
        obf_key = str(key_val).strip()

    parts = [
        "# wg-obfuscator server config (IPv4-only public edge)\n",
        f"source-if = 0.0.0.0\n",
        f"source-lport = {config.pub_port}\n",
        # Forward obfuscated UDP to the WireGuard listener on the server's
        # public IP so obfuscator can hand traffic to WireGuard directly.
        f"target = {config.public_host}:{config.wg_port}\n",
    ]
    if obf_key:
        parts.append(f"key = {obf_key}\n")
    parts.extend([
        f"masking = {config.masking}\n",
        "verbose = INFO\n",
        "idle-timeout = 300\n",
    ])
    content = "".join(parts)
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