from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .constants import DEFAULT_MEMORY_CONFIG
from .errors import InputValidationError
from .models import MemoryRegion

_SIZE_RE = re.compile(r"^\s*(0[xX][0-9a-fA-F]+|\d+)\s*([kKmMgG](?:[iI]?[bB])?)?\s*$")


def parse_integer(value: int | str, *, field_name: str = "value") -> int:
    if isinstance(value, bool):
        raise InputValidationError(f"{field_name} must be an integer")
    if isinstance(value, int):
        return value
    text = str(value).strip().replace("_", "")
    match = _SIZE_RE.match(text)
    if not match:
        raise InputValidationError(f"Invalid numeric value for {field_name}: {value}")
    number_text, suffix = match.groups()
    number = int(number_text, 0)
    multiplier = 1
    if suffix:
        prefix = suffix[0].lower()
        multiplier = {"k": 1024, "m": 1024**2, "g": 1024**3}[prefix]
    return number * multiplier


def parse_memory_regions(config: dict[str, Any] | None) -> list[MemoryRegion]:
    source = config or DEFAULT_MEMORY_CONFIG
    raw_regions = source.get("regions")
    if not isinstance(raw_regions, list) or not raw_regions:
        raise InputValidationError("At least one memory region is required")
    regions: list[MemoryRegion] = []
    seen_names: set[str] = set()
    for index, raw in enumerate(raw_regions):
        if not isinstance(raw, dict):
            raise InputValidationError(f"Memory region #{index + 1} must be an object")
        name = str(raw.get("name", "")).strip()
        if not name:
            raise InputValidationError(f"Memory region #{index + 1} has no name")
        normalized = name.casefold()
        if normalized in seen_names:
            raise InputValidationError(f"Duplicate memory region name: {name}")
        seen_names.add(normalized)
        origin = parse_integer(raw.get("origin", 0), field_name=f"{name}.origin")
        length = parse_integer(raw.get("length", 0), field_name=f"{name}.length")
        if origin < 0:
            raise InputValidationError(f"{name}.origin cannot be negative")
        if length <= 0:
            raise InputValidationError(f"{name}.length must be greater than zero")
        permissions = str(raw.get("permissions", "rwx")).lower()
        if any(char not in "rwx-" for char in permissions):
            raise InputValidationError(f"Invalid permissions for {name}: {permissions}")
        regions.append(
            MemoryRegion(
                name=name,
                origin=origin,
                length=length,
                permissions=permissions,
                description=str(raw.get("description", "")).strip(),
            )
        )
    regions.sort(key=lambda item: item.origin)
    for current, following in zip(regions, regions[1:]):
        if current.end > following.origin:
            raise InputValidationError(
                f"Memory regions overlap: {current.name} and {following.name}"
            )
    return regions


def load_json_file(path: str | os.PathLike[str]) -> dict[str, Any]:
    file_path = Path(path)
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputValidationError(f"Cannot read configuration: {file_path}") from exc
    except json.JSONDecodeError as exc:
        raise InputValidationError(f"Invalid JSON configuration: {exc}") from exc
    if not isinstance(payload, dict):
        raise InputValidationError("Configuration root must be an object")
    return payload


def default_workspace() -> Path:
    configured = os.environ.get("RVFPA_WORKSPACE", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.cwd() / "workspace").resolve()


def normalize_memory_config(config: dict[str, Any] | None) -> dict[str, Any]:
    regions = parse_memory_regions(config)
    architecture = str((config or {}).get("architecture", "auto"))
    return {
        "architecture": architecture,
        "regions": [
            {
                "name": item.name,
                "origin": f"0x{item.origin:x}",
                "length": item.length,
                "permissions": item.permissions,
                "description": item.description,
            }
            for item in regions
        ],
    }

