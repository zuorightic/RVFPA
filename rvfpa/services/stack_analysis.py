from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..config import parse_integer
from ..errors import InputValidationError


_LOCATION_RE = re.compile(
    r"^(?P<source>.*?):(?P<line>\d+):(?P<column>\d+):(?P<function>.*)$"
)
_KNOWN_QUALIFIERS = {"static", "dynamic", "bounded"}


@dataclass(slots=True)
class StackUsageRecord:
    source_path: str
    line: int
    column: int
    function_name: str
    stack_bytes: int
    allocation: str
    bounded: bool
    usage_file: str
    qualifiers: list[str] = field(default_factory=list)

    @property
    def source_name(self) -> str:
        return Path(self.source_path).name

    @property
    def location(self) -> str:
        return f"{self.source_path}:{self.line}:{self.column}"

    @property
    def identity(self) -> tuple[str, str, int, int]:
        return (
            self.function_name,
            self.source_path,
            self.line,
            self.column,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "source_name": self.source_name,
            "line": self.line,
            "column": self.column,
            "function_name": self.function_name,
            "stack_bytes": self.stack_bytes,
            "allocation": self.allocation,
            "bounded": self.bounded,
            "usage_file": self.usage_file,
            "qualifiers": self.qualifiers,
            "location": self.location,
        }


@dataclass(slots=True)
class StackUsageDocument:
    path: Path
    records: list[StackUsageRecord]
    warnings: list[str] = field(default_factory=list)

    @property
    def maximum_stack_bytes(self) -> int:
        return max((item.stack_bytes for item in self.records), default=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "record_count": len(self.records),
            "maximum_stack_bytes": self.maximum_stack_bytes,
            "records": [item.to_dict() for item in self.records],
            "warnings": self.warnings,
        }


def _split_usage_line(text: str) -> tuple[str, str, str] | None:
    tab_fields = text.rstrip("\r\n").split("\t")
    if len(tab_fields) >= 3:
        return (
            tab_fields[0].strip(),
            tab_fields[1].strip(),
            "\t".join(tab_fields[2:]).strip(),
        )
    whitespace_fields = text.strip().rsplit(maxsplit=2)
    if len(whitespace_fields) == 3:
        return (
            whitespace_fields[0],
            whitespace_fields[1],
            whitespace_fields[2],
        )
    return None


def _parse_location(value: str) -> tuple[str, int, int, str] | None:
    match = _LOCATION_RE.match(value)
    if not match:
        return None
    source_path = match.group("source").strip()
    function_name = match.group("function").strip()
    if not source_path or not function_name:
        return None
    return (
        source_path,
        int(match.group("line")),
        int(match.group("column")),
        function_name,
    )


def _parse_qualifiers(value: str) -> tuple[str, bool, list[str], list[str]]:
    qualifiers = [
        item
        for item in value.replace(" ", "").lower().split(",")
        if item
    ]
    if "dynamic" in qualifiers:
        allocation = "dynamic"
    elif "static" in qualifiers:
        allocation = "static"
    else:
        allocation = "unknown"
    bounded = allocation == "static" or "bounded" in qualifiers
    unknown = [item for item in qualifiers if item not in _KNOWN_QUALIFIERS]
    return allocation, bounded, qualifiers, unknown


def parse_stack_usage_text(
    text: str,
    *,
    source_name: str = "<memory>",
) -> StackUsageDocument:
    path = Path(source_name)
    records: list[StackUsageRecord] = []
    warnings: list[str] = []
    for input_line, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip():
            continue
        fields = _split_usage_line(raw_line)
        if fields is None:
            warnings.append(
                f"Line {input_line}: expected location, stack size and qualifiers"
            )
            continue
        raw_location, raw_size, raw_qualifiers = fields
        location = _parse_location(raw_location)
        if location is None:
            warnings.append(f"Line {input_line}: invalid source location")
            continue
        try:
            stack_bytes = int(raw_size, 0)
        except ValueError:
            warnings.append(
                f"Line {input_line}: invalid stack size {raw_size!r}"
            )
            continue
        if stack_bytes < 0:
            warnings.append(
                f"Line {input_line}: stack size cannot be negative"
            )
            continue
        source_path, source_line, column, function_name = location
        allocation, bounded, qualifiers, unknown = _parse_qualifiers(
            raw_qualifiers
        )
        if unknown:
            warnings.append(
                f"Line {input_line}: unknown qualifier {', '.join(unknown)}"
            )
        records.append(
            StackUsageRecord(
                source_path=source_path,
                line=source_line,
                column=column,
                function_name=function_name,
                stack_bytes=stack_bytes,
                allocation=allocation,
                bounded=bounded,
                usage_file=str(path),
                qualifiers=qualifiers,
            )
        )
    return StackUsageDocument(
        path=path,
        records=records,
        warnings=warnings,
    )


def parse_stack_usage_file(path: str | Path) -> StackUsageDocument:
    file_path = Path(path).expanduser().resolve()
    if not file_path.is_file():
        raise InputValidationError(
            f"Stack usage file does not exist: {file_path}"
        )
    if file_path.suffix.casefold() != ".su":
        raise InputValidationError(
            f"Expected a .su stack usage file: {file_path}"
        )
    try:
        text = file_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise InputValidationError(
            f"Cannot read stack usage file: {file_path}"
        ) from exc
    return parse_stack_usage_text(
        text,
        source_name=str(file_path),
    )


def discover_stack_usage_files(
    root: str | Path,
    *,
    recursive: bool = True,
    maximum_files: int = 5000,
) -> list[Path]:
    root_path = Path(root).expanduser().resolve()
    if root_path.is_file():
        if root_path.suffix.casefold() != ".su":
            raise InputValidationError(
                f"Expected a .su file or directory: {root_path}"
            )
        return [root_path]
    if not root_path.is_dir():
        raise InputValidationError(
            f"Stack usage root does not exist: {root_path}"
        )
    iterator: Iterable[Path]
    if recursive:
        iterator = root_path.rglob("*.su")
    else:
        iterator = root_path.glob("*.su")
    files = sorted(
        (item.resolve() for item in iterator if item.is_file()),
        key=lambda item: str(item).casefold(),
    )
    if len(files) > maximum_files:
        raise InputValidationError(
            f"Stack usage file count exceeds limit {maximum_files}: {len(files)}"
        )
    return files


def _deduplicate(
    records: Iterable[StackUsageRecord],
) -> list[StackUsageRecord]:
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

