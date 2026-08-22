"""GCC栈使用结果的汇总与预算检查模块。

文本解析、文件发现和数据模型已拆分到 ``stack_parser`` 与 ``stack_models``；
本模块保留跨文件去重、来源汇总、直方图、预算判定及命令级编排，并继续
重新导出原有公共名称，保证已有调用代码无需修改。
"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from ..config import parse_integer
from ..errors import InputValidationError
from .stack_models import StackUsageDocument, StackUsageRecord
from .stack_parser import (
    discover_stack_usage_files,
    parse_stack_usage_file,
    parse_stack_usage_text,
)


def _deduplicate(
    records: Iterable[StackUsageRecord],
) -> list[StackUsageRecord]:
    """按函数源位置去重，同一记录保留较大的栈占用值。"""
    selected: dict[tuple[str, str, int, int], StackUsageRecord] = {}
    for record in records:
        previous = selected.get(record.identity)
        if previous is None or record.stack_bytes > previous.stack_bytes:
            selected[record.identity] = record
    return sorted(
        selected.values(),
        key=lambda item: (
            item.stack_bytes,
            item.function_name,
            item.source_path,
        ),
        reverse=True,
    )


def _source_summary(
    records: list[StackUsageRecord],
) -> list[dict[str, Any]]:
    groups: dict[str, list[StackUsageRecord]] = defaultdict(list)
    for record in records:
        groups[record.source_path].append(record)
    result: list[dict[str, Any]] = []
    for source_path, values in groups.items():
        ordered = sorted(
            values,
            key=lambda item: item.stack_bytes,
            reverse=True,
        )
        result.append(
            {
                "source_path": source_path,
                "source_name": Path(source_path).name,
                "function_count": len(values),
                "sum_stack_bytes": sum(
                    item.stack_bytes for item in values
                ),
                "maximum_stack_bytes": ordered[0].stack_bytes,
                "largest_function": ordered[0].function_name,
                "dynamic_count": sum(
                    item.allocation == "dynamic" for item in values
                ),
                "unbounded_count": sum(
                    not item.bounded for item in values
                ),
            }
        )
    return sorted(
        result,
        key=lambda item: (
            item["maximum_stack_bytes"],
            item["source_path"],
        ),
        reverse=True,
    )


def _stack_histogram(
    records: list[StackUsageRecord],
) -> dict[str, int]:
    buckets = {
        "0-31": 0,
        "32-63": 0,
        "64-127": 0,
        "128-255": 0,
        "256-511": 0,
        "512-1023": 0,
        "1024-2047": 0,
        "2048+": 0,
    }
    for record in records:
        size = record.stack_bytes
        if size < 32:
            bucket = "0-31"
        elif size < 64:
            bucket = "32-63"
        elif size < 128:
            bucket = "64-127"
        elif size < 256:
            bucket = "128-255"
        elif size < 512:
            bucket = "256-511"
        elif size < 1024:
            bucket = "512-1023"
        elif size < 2048:
            bucket = "1024-2047"
        else:
            bucket = "2048+"
        buckets[bucket] += 1
    return buckets


def _budget_result(
    records: list[StackUsageRecord],
    maximum_stack_bytes: int | str | None,
) -> dict[str, Any]:
    if maximum_stack_bytes is None:
        return {
            "enabled": False,
            "status": "not-configured",
            "maximum_stack_bytes": None,
            "violation_count": 0,
            "violations": [],
        }
    limit = parse_integer(
        maximum_stack_bytes,
        field_name="maximum_stack_bytes",
    )
    if limit < 0:
        raise InputValidationError(
            "maximum_stack_bytes cannot be negative"
        )
    violations = [
        item for item in records if item.stack_bytes > limit
    ]
    return {
        "enabled": True,
        "status": "pass" if not violations else "fail",
        "maximum_stack_bytes": limit,
        "violation_count": len(violations),
        "violations": [
            {
                "function_name": item.function_name,
                "stack_bytes": item.stack_bytes,
                "location": item.location,
                "allocation": item.allocation,
                "bounded": item.bounded,
            }
            for item in violations[:100]
        ],
    }


def analyze_stack_documents(
    documents: Iterable[StackUsageDocument],
    *,
    maximum_stack_bytes: int | str | None = None,
) -> dict[str, Any]:
    """汇总多个解析文档并形成函数、来源、直方图与预算结果。"""
    document_list = list(documents)
    records = _deduplicate(
        record
        for document in document_list
        for record in document.records
    )
    allocation_counts = Counter(
        record.allocation for record in records
    )
    warnings = [
        f"{document.path}: {warning}"
        for document in document_list
        for warning in document.warnings
    ]
    dynamic = [
        record
        for record in records
        if record.allocation == "dynamic"
    ]
    unbounded = [
        record
        for record in records
        if not record.bounded
    ]
    total = sum(record.stack_bytes for record in records)
    average = round(total / len(records), 3) if records else 0.0
    return {
        "file_count": len(document_list),
        "record_count": len(records),
        "warning_count": len(warnings),
        "maximum_stack_bytes": (
            records[0].stack_bytes if records else 0
        ),
        "average_stack_bytes": average,
        "sum_stack_bytes": total,
        "static_count": allocation_counts.get("static", 0),
        "dynamic_count": len(dynamic),
        "unbounded_count": len(unbounded),
        "allocation_counts": dict(allocation_counts),
        "histogram": _stack_histogram(records),
        "top_functions": [
            item.to_dict() for item in records[:100]
        ],
        "source_files": _source_summary(records),
        "dynamic_functions": [
            item.to_dict() for item in dynamic[:100]
        ],
        "unbounded_functions": [
            item.to_dict() for item in unbounded[:100]
        ],
        "budget": _budget_result(
            records,
            maximum_stack_bytes,
        ),
        "warnings": warnings[:200],
    }


def analyze_stack_usage(
    root: str | Path,
    *,
    recursive: bool = True,
    maximum_files: int = 5000,
    maximum_stack_bytes: int | str | None = None,
) -> dict[str, Any]:
    """从文件或目录开始执行完整的GCC栈使用分析流程。"""
    root_path = Path(root).expanduser().resolve()
    files = discover_stack_usage_files(
        root_path,
        recursive=recursive,
        maximum_files=maximum_files,
    )
    documents = [
        parse_stack_usage_file(path) for path in files
    ]
    result = analyze_stack_documents(
        documents,
        maximum_stack_bytes=maximum_stack_bytes,
    )
    result["root_path"] = str(root_path)
    result["files"] = [str(path) for path in files]
    return result
