from __future__ import annotations
import argparse
from pathlib import Path
from wg_installer.i18n.i18n import Translator

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wg-installer", add_help=True)
    p.add_argument("--lang", default="auto", help="Language code (e.g. cs, ru, en) or 'auto'")
    p.add_argument("--list-langs", action="store_true", help="List available languages and exit")
    p.add_argument("--dry-run", action="store_true", help="Show actions without changing system")
    p.add_argument("--http-share", action="store_true", help="Start temporary HTTP share with QR codes")
    p.add_argument("--tui", action="store_true", help="Run interactive TUI wizard")
    return p

def init_i18n(args) -> Translator:
    locales_dir = Path(__file__).parent / "i18n" / "locales"
    tr = Translator(locales_dir, args.lang)
    if args.list_langs:
        for code, name in tr.available().items():
            print(f"{code}\t{name}")
        raise SystemExit(0)
    return tr
