# wg_installer/i18n/i18n.py
from __future__ import annotations
import json, locale, os
from pathlib import Path
from typing import Dict, Any, Iterable

DEFAULT_LANG = "en"

def _split_lang_chain(lang: str) -> Iterable[str]:
    # "cs_CZ.UTF-8" -> ["cs_CZ", "cs"]
    lang = lang.replace(".", "_")
    parts = lang.split("_")
    if len(parts) >= 2:
        yield f"{parts[0]}_{parts[1]}"
    if parts:
        yield parts[0]

def detect_lang(explicit: str | None = None) -> str:
    if explicit and explicit.lower() != "auto":
        return explicit
    for key in ("WG_INSTALLER_LANG", "LANGUAGE", "LC_ALL", "LANG"):
        val = os.environ.get(key)
        if val:
            return val
    sys_lang, _ = locale.getdefaultlocale()  # type: ignore[assignment]
    return sys_lang or DEFAULT_LANG

class Translator:
    def __init__(self, locales_dir: Path, lang: str | None = None):
        self.locales_dir = locales_dir
        self.requested = detect_lang(lang)
        self._catalog = self._load_catalog(self.requested)

    def _load_json(self, code: str) -> Dict[str, str]:
        path = self.locales_dir / f"{code}.json"
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _load_catalog(self, requested: str) -> Dict[str, str]:
        merged: Dict[str, str] = {}
        # Fallback order: requested → reduced forms → en
        tried: list[str] = []
        def merge(code: str):
            nonlocal merged
            tried.append(code)
            merged = {**merged, **self._load_json(code)}
        # exact (strip encoding)
        base = requested.split(".")[0]
        merge(base)
        for variant in _split_lang_chain(base):
            merge(variant)
        if DEFAULT_LANG not in tried:
            merge(DEFAULT_LANG)
        return merged

    def t(self, key: str, **kwargs: Any) -> str:
        msg = self._catalog.get(key, key)
        # no angle-bracket placeholders; use {name} only
        try:
            return msg.format(**kwargs)
        except Exception:
            return msg

    def available(self) -> Dict[str, str]:
        # returns { "en": "English", ... } if present in catalogs
        names: Dict[str, str] = {}
        for p in sorted(self.locales_dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                code = p.stem
                names[code] = data.get("_meta.language_name", code)
            except Exception:
                continue
        return names
