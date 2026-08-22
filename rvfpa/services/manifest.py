"""固件文件身份、构建信息和分析指纹追溯清单生成。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..constants import SOFTWARE_NAME, SOFTWARE_VERSION
from ..models import FirmwareAnalysis, utc_now_iso


def _stable_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _file_record(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    file_path = Path(path).expanduser().resolve()
    if not file_path.is_file():
        return {
            "path": str(file_path),
            "exists": False,
            "size": 0,
            "sha256": "",
        }
    digest = hashlib.sha256()
    with file_path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return {
        "path": str(file_path),
        "file_name": file_path.name,
        "exists": True,
        "size": file_path.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def build_firmware_manifest(
    analysis: FirmwareAnalysis,
    *,
    elf_path: str | Path | None = None,
    map_path: str | Path | None = None,
) -> dict[str, Any]:
    regions = [
        {
            "name": item.region.name,
            "origin": item.region.origin,
            "length": item.region.length,
            "used_bytes": item.used_bytes,
            "usage_percent": item.usage_percent,
        }
        for item in analysis.region_usage
    ]
    release_summary = analysis.metadata.get("release_check_summary", {})
    system_usage = analysis.metadata.get("system_usage", {})
    payload = {
        "schema": "rvfpa-firmware-manifest-v1",
        "generator": {
            "software": SOFTWARE_NAME,
            "version": SOFTWARE_VERSION,
            "generated_at": utc_now_iso(),
        },
        "inputs": {
            "elf": _file_record(elf_path),
            "map": _file_record(map_path),
        },
        "identity": {
            "file_name": analysis.identity.file_name,
            "sha256": analysis.identity.sha256,
            "architecture": analysis.identity.architecture,
            "abi": analysis.identity.abi,
            "entry_point": analysis.identity.entry_point,
            "build_id": analysis.identity.build_id,
            "compiler_comment": analysis.identity.comment,
        },
        "resources": {
            "sizes": analysis.size_summary.__dict__ if hasattr(analysis.size_summary, "__dict__") else {
                field: getattr(analysis.size_summary, field)
                for field in analysis.size_summary.__dataclass_fields__
            },
            "regions": regions,
            "instruction_count": analysis.instruction_profile.total,
            "compressed_percent": analysis.instruction_profile.compressed_percent,
            "extensions": analysis.instruction_profile.extensions,
            "symbol_count": len(analysis.symbols),
            "function_count": len(analysis.function_profiles),
            "string_count": len(analysis.firmware_strings),
            "csr_instruction_count": system_usage.get("csr_instruction_count", 0),
        },
        "quality": {
            "diagnostic_count": len(analysis.diagnostics),
            "release_checks": release_summary,
            "decode_failures": analysis.instruction_profile.decode_failures,
        },
        "toolchain": analysis.toolchain,
    }
    fingerprint_source = {
        "identity": payload["identity"],
        "resources": payload["resources"],
        "quality": payload["quality"],
        "toolchain": payload["toolchain"],
    }
    payload["analysis_fingerprint"] = hashlib.sha256(
        _stable_json(fingerprint_source)
    ).hexdigest()
    return payload
