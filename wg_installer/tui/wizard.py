from __future__ import annotations
from dataclasses import dataclass
import sys
try:
    import questionary
except Exception:
    questionary = None

@dataclass(frozen=True)
class TuiConfig:
    public_host: str
    pub_port: int
    wg_port: int
    wg_subnet: str
    masking: str
    mtu: int
    http_share: bool
    build_apk: bool
    create_obf_key: bool

def run_tui(tr, defaults) -> TuiConfig | None:
    if questionary is None or not sys.stdin.isatty() or not sys.stdout.isatty():
        return None
    def portv(x: str):
        try:
            p = int(x)
            return 1 <= p <= 65535
        except: return False
    def cidrv(x: str):
        import ipaddress
        try:
            n = ipaddress.ip_network(x, strict=False)
            return n.version == 4 and n.num_addresses >= 4
        except: return False
    public_host = questionary.text(tr.t("tui.public_host"), default=defaults["host"]).ask()
    if public_host is None: return None
    pub_port = questionary.text(tr.t("tui.public_port"), default=str(defaults["pub_port"]),
                                validate=lambda v: portv(v) or tr.t("tui.port_out_of_range")).ask()
    if pub_port is None: return None
    wg_port = questionary.text(tr.t("tui.wg_port"), default=str(defaults["wg_port"]),
                               validate=lambda v: portv(v) or tr.t("tui.port_out_of_range")).ask()
    if wg_port is None: return None
    wg_subnet = questionary.text(tr.t("tui.wg_subnet"), default=defaults["wg_subnet"],
                                 validate=lambda v: cidrv(v) or tr.t("tui.invalid_cidr")).ask()
    if wg_subnet is None: return None
    mtu = questionary.text(tr.t("tui.mtu"), default=str(defaults["mtu"]),
                           validate=lambda v: v.isdigit() and 1200 <= int(v) <= 9200 or tr.t("tui.mtu_out_of_range")).ask()
    if mtu is None: return None
    masking = questionary.select(tr.t("tui.masking"),
                                 choices=["STUN","AUTO","NONE"],
                                 default=defaults["masking"]).ask()
    if masking is None: return None
    # Android APK option is hidden for now. Re-enable if needed.
    # build_apk = questionary.confirm(tr.t("tui.build_apk"), default=False).ask()
    # if build_apk is None: return None
    http_share = questionary.confirm(tr.t("tui.http_share"), default=False).ask()
    if http_share is None: return None

    # We no longer ask to block WireGuard; it is intentionally exposed for obfuscation.

    # Ask for an optional obfuscator key (text). Leave empty to omit.
    create_obf_key = questionary.text("Obfuscator key (leave empty to omit)", default="").ask()
    if create_obf_key is None: return None

    return TuiConfig(public_host.strip(), int(pub_port), int(wg_port), wg_subnet.strip(),
                     masking.strip().upper(), int(mtu), bool(http_share), False, (create_obf_key.strip() or None))