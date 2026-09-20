"""把领域模型整理成Web接口需要的JSON数据。

项目和快照列表只需要少量摘要字段，不应反复传输整份固件分析结果。这里负责
裁剪和转换这些数据，不处理路由、文件上传或固件分析。
"""

from __future__ import annotations

import json
from typing import Any

from .models import ProjectRecord, SnapshotRecord, to_primitive


def json_bytes(payload: Any) -> bytes:
    return json.dumps(
        to_primitive(payload), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def project_payload(project: ProjectRecord) -> dict[str, Any]:
    return to_primitive(project)


def analysis_summary(analysis: Any) -> dict[str, Any] | None:
    if analysis is None:
        return None
    payload = analysis.to_dict() if hasattr(analysis, "to_dict") else analysis
    if not isinstance(payload, dict):
        return None
    identity = payload.get("identity") or {}
    size_summary = payload.get("size_summary") or {}
    instruction_profile = payload.get("instruction_profile") or {}
    return {
        "identity": {"file_name": identity.get("file_name", "")},
        "size_summary": {"code_bytes": size_summary.get("code_bytes", 0)},
        "instruction_profile": {"total": instruction_profile.get("total", 0)},
    }


def snapshot_payload(
    snapshot: SnapshotRecord,
    include_paths: bool = False,
) -> dict[str, Any]:
    payload = {
        "id": snapshot.id,
        "project_id": snapshot.project_id,
        "version_name": snapshot.version_name,
        "notes": snapshot.notes,
        "created_at": snapshot.created_at,
        "analysis": analysis_summary(snapshot.analysis),
    }
    if include_paths:
        payload["elf_path"] = snapshot.elf_path
        payload["map_path"] = snapshot.map_path
    return payload
