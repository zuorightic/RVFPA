"""查找并解析GCC生成的 ``.su`` 栈使用文件。

GCC输出可能使用制表符或普通空格分隔字段，解析时两种格式都支持。格式有误的
行会留下警告并跳过；目录扫描只检查范围、扩展名和文件数量，不做统计。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ..errors import InputValidationError
from .stack_models import StackUsageDocument, StackUsageRecord


_LOCATION_RE = re.compile(
    r"^(?P<source>.*?):(?P<line>\d+):(?P<column>\d+):(?P<function>.*)$"
)
_KNOWN_QUALIFIERS = {"static", "dynamic", "bounded"}


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
        return whitespace_fields[0], whitespace_fields[1], whitespace_fields[2]
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
        item for item in value.replace(" ", "").lower().split(",") if item
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
            warnings.append(f"Line {input_line}: invalid stack size {raw_size!r}")
            continue
        if stack_bytes < 0:
            warnings.append(f"Line {input_line}: stack size cannot be negative")
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
    return StackUsageDocument(path=path, records=records, warnings=warnings)


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
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise InputValidationError(
            f"Cannot read stack usage file: {file_path}"
        ) from exc
    return parse_stack_usage_text(text, source_name=str(file_path))


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
