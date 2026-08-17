from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
BUILD = EXAMPLES / "build"


def ensure_examples() -> None:
    first = BUILD / "firmware_v1.elf"
    second = BUILD / "firmware_v2.elf"
    if first.exists() and second.exists():
        return
    subprocess.run(["python3", str(EXAMPLES / "build_examples.py")], check=True, cwd=ROOT)


def example_elf(version: str) -> Path:
    ensure_examples()
    return BUILD / f"firmware_{version}.elf"


def example_map(version: str) -> Path:
    ensure_examples()
    return BUILD / f"firmware_{version}.map"

