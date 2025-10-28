from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict

class StateDB:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def put(self, key: str, value: Any, dry: bool) -> None:
        if dry:
            print(f"[DRY-RUN] Would set state: {key}={value} in {self.path}")
            return
        data: Dict[str, Any] = {}
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
            except Exception:
                data = {}
        data[key] = value
        self.path.write_text(json.dumps(data, indent=2))