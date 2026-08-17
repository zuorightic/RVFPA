from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..models import InstructionRecord

_FUNCTION_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+<(.+)>:\s*$")
_INSTRUCTION_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+"
    r"((?:[0-9a-fA-F]{2}\s+){1,8})"
    r"\s*([.A-Za-z_][\w.]*)?\s*(.*?)\s*$"
)
_INSTRUCTION_WORD_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{4,16})\s+"
    r"([.A-Za-z_][\w.]*)\s*(.*?)\s*$"
)
_SOURCE_RE = re.compile(r"^(.+?):(\d+)(?:\s+\(discriminator\s+\d+\))?$")


@dataclass(slots=True)
class ObjdumpDocument:
    path: Path | None
    records: list[InstructionRecord] = field(default_factory=list)
    functions: dict[str, tuple[int, int]] = field(default_factory=dict)
    source_locations: dict[int, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    raw_header: list[str] = field(default_factory=list)


def _bytes_from_field(value: str) -> bytes:
    compact = "".join(value.split())
    if len(compact) % 2:
        return b""
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return b""


def _bytes_from_word(value: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return b""
    if len(raw) in (2, 4, 6, 8):
        return raw[::-1]
    return raw


def parse_objdump_text(text: str, *, path: Path | None = None) -> ObjdumpDocument:
    document = ObjdumpDocument(path=path)
    current_function = ""
    function_start = 0
    source_line = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        function_match = _FUNCTION_RE.match(line)
        if function_match:
            if current_function and document.records:
                document.functions[current_function] = (
                    function_start,
                    document.records[-1].address + document.records[-1].width,
                )
            function_start = int(function_match.group(1), 16)
            current_function = function_match.group(2)
            continue
        source_match = _SOURCE_RE.match(line.strip())
        if source_match and not line.lstrip().startswith("0x"):
            source_line = line.strip()
            continue
        match = _INSTRUCTION_RE.match(line)
        raw = b""
        if match:
            address = int(match.group(1), 16)
            raw = _bytes_from_field(match.group(2))
            mnemonic = match.group(3) or ".word"
            operands = match.group(4)
        else:
            word_match = _INSTRUCTION_WORD_RE.match(line)
            if not word_match:
                if line and len(document.raw_header) < 30:
                    document.raw_header.append(line)
                continue
            address = int(word_match.group(1), 16)
            raw = _bytes_from_word(word_match.group(2))
            mnemonic = word_match.group(3)
            operands = word_match.group(4)
        width = len(raw)
        if width == 0:
            width = 2 if mnemonic.startswith("c.") else 4
        document.records.append(
            InstructionRecord(
                address=address,
                raw=raw,
                width=width,
                mnemonic=mnemonic,
                operands=operands,
                category="",
                extension="",
                function_name=current_function,
                source_line=source_line,
            )
        )
        if source_line:
            document.source_locations[address] = source_line
    if current_function and document.records:
        document.functions[current_function] = (
            function_start,
            document.records[-1].address + document.records[-1].width,
        )
    return document

