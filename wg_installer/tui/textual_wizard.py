from __future__ import annotations
import ipaddress
import json
import os
import sys
from dataclasses import dataclass
from typing import Optional

# Soft import: if Textual is missing or no TTY, we fall back to None return.
try:
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, Input, Select, Switch, Button, Label
    from textual.containers import Grid
    from textual.message import Message
    TEXTUAL_AVAILABLE = True
except Exception:
    TEXTUAL_AVAILABLE = False

ALLOWED_MASKING = ("STUN", "AUTO", "NONE")

@dataclass(frozen=True)
class Config:
    public_host: str
    pub_port: int
    wg_port: int
    wg_subnet: str
    masking: str
    mtu: int
    http_share: bool
    build_apk: bool
    create_obf_key: bool

def _validate_port(value: str) -> tuple[bool, str]:
    try:
        p = int(value)
    except ValueError:
        return False, "Port must be numeric."
    if not (1 <= p <= 65535):
        return False, "Port out of range (1..65535)."
    return True, ""

def _validate_cidr(value: str) -> tuple[bool, str]:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False, "Invalid IPv4 CIDR."
    if net.version != 4:
        return False, "IPv4 only."
    if net.num_addresses < 4:
        return False, "Subnet too small (need ≥ 4 addresses)."
    return True, ""

def _validate_mtu(value: str) -> tuple[bool, str]:
    try:
        m = int(value)
    except ValueError:
        return False, "MTU must be numeric."
    if not (1200 <= m <= 1420):
        return False, "MTU out of range (1200..1420)."
    return True, ""

class _FormSubmitted(Message):
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        super().__init__()

class WgWizard(App):
    # Simplified, minimal styling to mimic ncurses-like appearance.
    CSS = """
    Screen { align: center middle; }
    Grid { grid-size: 2; grid-gutter: 1 2; width: 80; }
    .error { color: red; height: 1; }
    """

    def __init__(
        self,
        default_public_host: str,
        default_pub_port: int,
        default_wg_port: int,
        default_wg_subnet: str,
        default_masking: str,
        default_mtu: int,
        default_http_share: bool,
        default_build_apk: bool,
        default_create_obf_key: str | None = None,
    ) -> None:
        super().__init__()
        self._defaults = dict(
            public_host=str(default_public_host),
            pub_port=str(default_pub_port),
            wg_port=str(default_wg_port),
            wg_subnet=str(default_wg_subnet),
            masking=(default_masking if default_masking in ALLOWED_MASKING else "STUN"),
            mtu=str(default_mtu),
            http_share=bool(default_http_share),
            build_apk=bool(default_build_apk),
            create_obf_key=(default_create_obf_key or "") if default_create_obf_key is not None else "",
        )
        self.result_cfg: Optional[Config] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Grid(
            Label("Public host (IP/DNS):"), Input(self._defaults["public_host"], id="public_host"),
            Label("Public UDP port:"),     Input(self._defaults["pub_port"], id="pub_port"),
            Label("WG internal port:"),    Input(self._defaults["wg_port"], id="wg_port"),
            Label("WG server subnet:"),    Input(self._defaults["wg_subnet"], id="wg_subnet"),
            Label("MTU:"),                 Input(self._defaults["mtu"], id="mtu"),
            Label("Masking:"),             Select(((m, m) for m in ALLOWED_MASKING), id="masking", value=self._defaults["masking"]),
            Label("HTTP share?"),          Switch(value=self._defaults["http_share"], id="http_share"),
            # Android APK option hidden for now. Re-enable if needed:
            # Label("Build Android APK?"),   Switch(value=self._defaults["build_apk"], id="build_apk"),
            Label("Obfuscator key (leave empty to omit):"), Input(self._defaults.get("create_obf_key", ""), id="create_obf_key"),
            Label("", id="err", classes="error", expand=False),
            Button("Submit", id="submit"), Button("Cancel", id="cancel"),
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.exit(None)
            return
        if event.button.id == "submit":
            self._submit()

    def _submit(self) -> None:
        def val(widget_id: str) -> str:
            w = self.query_one(f"#{widget_id}")
            if isinstance(w, Input):
                return w.value.strip()
            if isinstance(w, Select):
                return (w.value or "STUN").strip().upper()
            if isinstance(w, Switch):
                return "true" if w.value else "false"
            return ""

        public_host = val("public_host")
        pub_port_s  = val("pub_port")
        wg_port_s   = val("wg_port")
        wg_subnet   = val("wg_subnet")
        mtu_s       = val("mtu")
        masking     = val("masking")
        http_share  = (val("http_share") == "true")
        # build_apk UI is hidden; keep default False unless provided programmatically
        build_apk   = (val("build_apk") == "true") if self._defaults.get("build_apk", False) else False
        create_obf_key = val("create_obf_key")

        if not public_host:
            return self._error("Public host must not be empty.")
        ok, msg = _validate_port(pub_port_s)
        if not ok: return self._error(msg)
        ok, msg = _validate_port(wg_port_s)
        if not ok: return self._error(msg)
        ok, msg = _validate_cidr(wg_subnet)
        if not ok: return self._error(msg)
        ok, msg = _validate_mtu(mtu_s)
        if not ok: return self._error(msg)
        if masking == "STUTN": masking = "STUN"
        if masking not in ALLOWED_MASKING:
            return self._error(f"Invalid masking. Allowed: {ALLOWED_MASKING}")

        cfg = Config(
            public_host=public_host,
            pub_port=int(pub_port_s),
            wg_port=int(wg_port_s),
            wg_subnet=wg_subnet,
            masking=masking,
            mtu=int(mtu_s),
            http_share=http_share,
            build_apk=build_apk,
            create_obf_key=create_obf_key.strip() if create_obf_key and create_obf_key.strip() else None,
        )
        self.result_cfg = cfg
        # Write JSON to stdout so caller can consume non-interactively if desired
        print(json.dumps(cfg.__dict__, indent=2), flush=True)
        self.exit(cfg)

    def _error(self, msg: str) -> None:
        self.query_one("#err", Label).update(msg)

def run_textual_wizard(
    *,
    default_public_host: str,
    default_pub_port: int,
    default_wg_port: int,
    default_wg_subnet: str,
    default_masking: str,
    default_mtu: int = 1420,
    default_http_share: bool = False,
    default_build_apk: bool = False,
    default_create_obf_key: bool = False,
) -> Optional[Config]:
    """
    Returns Config if completed, None if cancelled or Textual/TTY unavailable.
    """
    if not TEXTUAL_AVAILABLE:
        return None
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return None
    app = WgWizard(
        default_public_host, default_pub_port, default_wg_port,
        default_wg_subnet, default_masking, default_mtu,
        default_http_share, default_build_apk,
        default_create_obf_key,
    )
    # Textual runs its own event loop; return the captured result.
    app.run()  # blocks until exit
    return app.result_cfg