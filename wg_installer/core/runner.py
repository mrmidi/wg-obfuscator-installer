from __future__ import annotations
import subprocess
from dataclasses import dataclass
from typing import Sequence, Optional

@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str

class Runner:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def run(self, args: Sequence[str], *, check: bool = True, capture: bool = False, **subprocess_kwargs) -> RunResult:
        """Run a subprocess command.

        Accepts optional keyword args passed through to subprocess.run (e.g. cwd, env).
        If capture=True, stdout/stderr are captured and returned in the RunResult (text mode).
        """
        text = " ".join(map(str, args))
        if self.dry_run:
            print(f"[DRY-RUN] {text}")
            return RunResult(0, "", "")
        if capture:
            c = subprocess.run(args, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **subprocess_kwargs)
            return RunResult(c.returncode, c.stdout, c.stderr)
        c = subprocess.run(args, check=check, **subprocess_kwargs)
        return RunResult(c.returncode, "", "")

    def shell(self, cmd: str, *, check: bool = True, capture: bool = False) -> RunResult:
        if self.dry_run:
            print(f"[DRY-RUN] {cmd}")
            return RunResult(0, "", "")
        c = subprocess.run(cmd, shell=True, check=check,
                           stdout=subprocess.PIPE if capture else None,
                           stderr=subprocess.PIPE if capture else None,
                           text=True)
        return RunResult(c.returncode, c.stdout if capture else "", c.stderr if capture else "")