# wg_installer/tui.py
from __future__ import annotations

import ipaddress
import os
import sys
from dataclasses import dataclass
from typing import Optional

try:
    import questionary  # lightweight TUI over prompt_toolkit
except Exception:  # pragma: no cover
    questionary = None  # optional

from .i18n.i18n import Translator


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


ALLOWED_MASKING = ("STUN", "AUTO", "NONE")


def _validate_port(value: str, tr: Translator) -> bool | str:
    try:
        p = int(value)
    except ValueError:
        return tr.t("tui.port_must_be_numeric")
    if not (1 <= p <= 65535):
        return tr.t("tui.port_out_of_range")
    return True


def _validate_cidr(value: str, tr: Translator) -> bool | str:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return tr.t("tui.invalid_cidr")
    if net.version != 4:
        return tr.t("tui.ipv4_only")
    if net.num_addresses < 4:
        return tr.t("tui.subnet_too_small")
    return True


def _validate_masking(value: str, tr: Translator) -> bool | str:
    value = value.strip().upper()
    if value == "STUTN":  # typo guard
        value = "STUN"
    if value not in ALLOWED_MASKING:
        return tr.t("tui.invalid_masking") + f" {ALLOWED_MASKING}"
    return True


def _validate_mtu(value: str, tr: Translator) -> bool | str:
    try:
        m = int(value)
    except ValueError:
        return tr.t("tui.mtu_must_be_numeric")
    # WG commonly uses 1280..1420; allow sane envelope
    if not (1200 <= m <= 1420):
        return tr.t("tui.mtu_out_of_range")
    return True


def run_tui(
    tr: Translator,
    *,
    default_public_host: str,
    default_pub_port: int,
    default_wg_port: int,
    default_wg_subnet: str,
    default_masking: str,
    default_mtu: int = 1420,
    default_http_share: bool = False,
    default_build_apk: bool = False,
) -> Optional[Config]:
    """
    Show an interactive TUI wizard. Returns Config or None if cancelled.
    Falls back to None if TTY is unavailable or questionary missing.
    """
    if not sys.stdin.isatty() or not sys.stdout.isatty() or questionary is None:
        return None  # caller will fall back to non-interactive path

    # Step 1: host
    public_host = questionary.text(
        tr.t("tui.public_host"),
        default=str(default_public_host),
        validate=lambda v: True if v.strip() else tr.t("tui.non_empty"),
    ).ask()
    if public_host is None:
        return None

    # Step 2: ports
    pub_port_s = questionary.text(
        tr.t("tui.public_port"),
        default=str(default_pub_port),
        validate=lambda v: _validate_port(v, tr),
    ).ask()
    if pub_port_s is None:
        return None

    wg_port_s = questionary.text(
        tr.t("tui.wg_port"),
        default=str(default_wg_port),
        validate=lambda v: _validate_port(v, tr),
    ).ask()
    if wg_port_s is None:
        return None

    # Step 3: subnet + MTU
    wg_subnet = questionary.text(
        tr.t("tui.wg_subnet"),
        default=str(default_wg_subnet),
        validate=lambda v: _validate_cidr(v, tr),
    ).ask()
    if wg_subnet is None:
        return None

    mtu_s = questionary.text(
        tr.t("tui.mtu"),
        default=str(default_mtu),
        validate=lambda v: _validate_mtu(v, tr),
    ).ask()
    if mtu_s is None:
        return None

    # Step 4: masking
    masking = questionary.select(
        tr.t("tui.masking"),
        choices=[
            questionary.Choice("STUN", "STUN"),
            questionary.Choice("AUTO", "AUTO"),
            questionary.Choice("NONE", "NONE"),
        ],
        default=(default_masking if default_masking in ALLOWED_MASKING else "STUN"),
    ).ask()
    if masking is None:
        return None

    # Step 5: extras
    http_share = questionary.confirm(
        tr.t("tui.http_share"),
        default=bool(default_http_share),
    ).ask()
    if http_share is None:
        return None

    build_apk = questionary.confirm(
        tr.t("tui.build_apk"),
        default=bool(default_build_apk),
    ).ask()
    if build_apk is None:
        return None

    # TODO: Implement build_apk functionality for Android APK generation

    return Config(
        public_host=public_host.strip(),
        pub_port=int(pub_port_s),
        wg_port=int(wg_port_s),
        wg_subnet=wg_subnet.strip(),
        masking=masking.strip().upper(),
        mtu=int(mtu_s),
        http_share=bool(http_share),
        build_apk=bool(build_apk),
    )
