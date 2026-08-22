"""GNU链接MAP文本解析器。

提取Memory Configuration、输出段、输入段、目标文件贡献、符号和链接警告，
作为ELF资源画像的来源补充。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import MapParseError
from ..models import MapContribution

_OUTPUT_SECTION_RE = re.compile(
    r"^(?P<section>\.[A-Za-z0-9_.$+\-]+)\s+"
    r"(?P<address>0x[0-9a-fA-F]+)\s+(?P<size>0x[0-9a-fA-F]+)(?:\s+.*)?$"
)
_INPUT_SECTION_RE = re.compile(
    r"^\s+(?P<section>\.[A-Za-z0-9_.$+\-]+)\s+"
    r"(?P<address>0x[0-9a-fA-F]+)\s+(?P<size>0x[0-9a-fA-F]+)\s+"
    r"(?P<object>.+?)\s*$"
)
_INPUT_SECTION_WRAPPED_RE = re.compile(r"^\s+(?P<section>\.[A-Za-z0-9_.$+\-]+)\s*$")
_ADDRESS_SIZE_OBJECT_RE = re.compile(
    r"^\s+(?P<address>0x[0-9a-fA-F]+)\s+(?P<size>0x[0-9a-fA-F]+)\s+"
    r"(?P<object>.+?)\s*$"
)
_SYMBOL_RE = re.compile(
    r"^\s+(?P<address>0x[0-9a-fA-F]+)\s+(?P<symbol>[A-Za-z_.$][\w.$@+-]*)\s*$"
)
_MEMORY_REGION_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<origin>0x[0-9a-fA-F]+)\s+"
    r"(?P<length>0x[0-9a-fA-F]+)\s+(?P<attributes>\S+)\s*$"
)


@dataclass(slots=True)
class MapMemoryRegion:
    name: str
    origin: int
    length: int
    attributes: str


@dataclass(slots=True)
class GNUMapDocument:
    path: Path
    contributions: list[MapContribution] = field(default_factory=list)
    memory_regions: list[MapMemoryRegion] = field(default_factory=list)
    discarded_sections: list[str] = field(default_factory=list)
    output_sections: dict[str, tuple[int, int]] = field(default_factory=dict)
    load_objects: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def by_object(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for item in self.contributions:
            result[item.object_path] = result.get(item.object_path, 0) + item.size
        return result

    def by_section(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for item in self.contributions:
            result[item.section_name] = result.get(item.section_name, 0) + item.size
        return result


def _split_archive_path(value: str) -> tuple[str, str]:
    text = value.strip()
    if "(" in text and text.endswith(")"):
        archive, member = text.rsplit("(", 1)
        return archive, member[:-1]
    return "", text


def parse_map_text(text: str, *, path: Path | None = None) -> GNUMapDocument:
    document = GNUMapDocument(path=path or Path("<memory>"))
    mode = "preamble"
    current_output_section = ""
    pending_input_section = ""
    latest_contribution: MapContribution | None = None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()
        if stripped == "Memory Configuration":
            mode = "memory"
            continue
        if stripped == "Linker script and memory map":
            mode = "map"
            continue
        if stripped.startswith("Discarded input sections"):
            mode = "discarded"
            continue
        if stripped.startswith("LOAD "):
            document.load_objects.append(stripped[5:].strip())
            continue
        if mode == "memory":
            match = _MEMORY_REGION_RE.match(stripped)
            if match and match.group("name") != "Name":
                document.memory_regions.append(
                    MapMemoryRegion(
                        name=match.group("name"),
                        origin=int(match.group("origin"), 16),
                        length=int(match.group("length"), 16),
                        attributes=match.group("attributes"),
                    )
                )
            continue
        if mode == "discarded":
            if stripped.startswith("."):
                document.discarded_sections.append(stripped)
            continue
        if mode != "map" or not stripped:
            continue
        output_match = _OUTPUT_SECTION_RE.match(stripped)
        if output_match and not line.startswith((" ", "\t")):
            current_output_section = output_match.group("section")
            document.output_sections[current_output_section] = (
                int(output_match.group("address"), 16),
                int(output_match.group("size"), 16),
            )
            latest_contribution = None
            continue
        input_match = _INPUT_SECTION_RE.match(line)
        if input_match:
            archive, object_path = _split_archive_path(input_match.group("object"))
            latest_contribution = MapContribution(
                section_name=input_match.group("section") or current_output_section,
                object_path=object_path,
                archive_path=archive,
                address=int(input_match.group("address"), 16),
                size=int(input_match.group("size"), 16),
            )
            document.contributions.append(latest_contribution)
            pending_input_section = ""
            continue
        wrapped_match = _INPUT_SECTION_WRAPPED_RE.match(line)
        if wrapped_match:
            pending_input_section = wrapped_match.group("section")
            continue
        if pending_input_section:
            continuation = _ADDRESS_SIZE_OBJECT_RE.match(line)
            if continuation:
                archive, object_path = _split_archive_path(continuation.group("object"))
                latest_contribution = MapContribution(
                    section_name=pending_input_section,
                    object_path=object_path,
                    archive_path=archive,
                    address=int(continuation.group("address"), 16),
                    size=int(continuation.group("size"), 16),
                )
                document.contributions.append(latest_contribution)
                pending_input_section = ""
                continue
        symbol_match = _SYMBOL_RE.match(line)
        if symbol_match and latest_contribution is not None:
            address = int(symbol_match.group("address"), 16)
            if latest_contribution.address <= address <= (
                latest_contribution.address + latest_contribution.size
            ):
                latest_contribution.symbol_name = symbol_match.group("symbol")
        if "warning:" in stripped.lower():
            document.warnings.append(f"line {line_number}: {stripped}")
    return document


def parse_map_file(path: str | Path) -> GNUMapDocument:
    file_path = Path(path).expanduser().resolve()
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise MapParseError(f"Cannot read MAP file: {file_path}") from exc
    return parse_map_text(text, path=file_path)
