"""把领域模型整理成Web接口需要的JSON数据。

项目和快照列表只需要少量摘要字段，不应反复传输整份固件分析结果。这里负责
裁剪和转换这些数据，不处理路由、文件上传或固件分析。
"""

from __future__ import annotations

import json
from typing import Any

from .models import ProjectRecord, SnapshotRecord, to_primitive


def json_bytes(payload: Any) -> bytes:
    """将领域对象转换为紧凑的UTF-8 JSON字节串。"""

    return json.dumps(
        to_primitive(payload), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def project_payload(project: ProjectRecord) -> dict[str, Any]:
    """生成项目列表和项目详情共用的JSON对象。"""

    return to_primitive(project)


def analysis_summary(analysis: Any) -> dict[str, Any] | None:
    """提取版本列表所需的文件名、程序空间和指令数量。

    版本列表只展示三个摘要字段，避免把段、符号和指令明细重复传给前端。
    """

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
    """生成快照响应；仅在详情接口明确要求时暴露工作区文件路径。"""

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
