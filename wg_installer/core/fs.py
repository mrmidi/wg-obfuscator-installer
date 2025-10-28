from __future__ import annotations
import json
import os
from pathlib import Path

def write_file(path: Path, content: str, mode: int, dry: bool) -> None:
    if dry:
        print(f"[DRY-RUN] Would write file: {path} (mode {oct(mode)})")
        for line in content.splitlines():
            print(f"[DRY-RUN]   {line}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, mode)

def append_file(path: Path, content: str, mode: int, dry: bool) -> None:
    if dry:
        print(f"[DRY-RUN] Would append to file: {path} (mode {oct(mode)})")
        for line in content.splitlines():
            print(f"[DRY-RUN]   {line}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, mode)