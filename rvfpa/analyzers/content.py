"""固件字符串和节区内容特征分析。

负责提取ASCII、UTF-16文本，按用途分类内容线索，并计算节区熵、零字节和
可打印字符比例；结果只用于内容复核，不直接作漏洞结论。
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable

from ..models import FirmwareString, SectionEntropy, SectionRecord
from ..parsers.elf import ELFDocument

_URL_RE = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
_PATH_RE = re.compile(r"^(?:/|[A-Za-z]:\\|\.\.?/)")
_FORMAT_RE = re.compile(r"%(?:[-+0 #]*\d*(?:\.\d+)?[diuoxXfFeEgGaAcspn%])")
_DIAGNOSTIC_WORDS = {
    "error",
    "warning",
    "failed",
    "failure",
    "invalid",
    "timeout",
    "panic",
    "assert",
    "fault",
    "debug",
    "trace",
}
_SENSITIVE_WORDS = {
    "password",
    "passwd",
    "secret",
    "token",
    "private key",
    "api_key",
    "apikey",
    "credential",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 5)


def _printable(value: int) -> bool:
    return value in (9, 10, 13) or 32 <= value <= 126


def _classify_string(text: str) -> str:
    lowered = text.casefold()
    if _URL_RE.match(text):
        return "url"
    if _PATH_RE.match(text):
        return "path"
    if any(word in lowered for word in _SENSITIVE_WORDS):
        return "sensitive-keyword"
    if any(word in lowered for word in _DIAGNOSTIC_WORDS):
        return "diagnostic"
    if _FORMAT_RE.search(text):
        return "format-string"
    if text.isidentifier():
        return "identifier"
    return "text"


def _extract_ascii_strings(
    data: bytes,
    *,
    section_name: str,
    base_address: int,
    minimum_length: int,
) -> list[FirmwareString]:
    result: list[FirmwareString] = []
    start = 0
    cursor = 0
    while cursor <= len(data):
        if cursor < len(data) and _printable(data[cursor]):
            cursor += 1
            continue
        if cursor - start >= minimum_length:
            raw = data[start:cursor]
            text = raw.decode("ascii", errors="ignore").strip()
            if len(text) >= minimum_length:
                result.append(
                    FirmwareString(
                        section_name=section_name,
                        address=base_address + start,
                        offset=start,
                        text=text,
                        encoding="ascii",
                        category=_classify_string(text),
                        length=len(text),
                    )
                )
        cursor += 1
        start = cursor
    return result


def _extract_utf16le_strings(
    data: bytes,
    *,
    section_name: str,
    base_address: int,
    minimum_length: int,
) -> list[FirmwareString]:
    result: list[FirmwareString] = []
    for alignment in (0, 1):
        start = alignment
        cursor = alignment
        chars: list[int] = []
        while cursor + 1 < len(data):
            low, high = data[cursor], data[cursor + 1]
            if high == 0 and _printable(low):
                chars.append(low)
                cursor += 2
                continue
            if len(chars) >= minimum_length:
                text = bytes(chars).decode("ascii", errors="ignore").strip()
                if len(text) >= minimum_length:
                    result.append(
                        FirmwareString(
                            section_name=section_name,
                            address=base_address + start,
                            offset=start,
                            text=text,
                            encoding="utf-16le",
                            category=_classify_string(text),
                            length=len(text),
                        )
                    )
            chars = []
            cursor += 2
            start = cursor
    return result


def extract_firmware_strings(
    document: ELFDocument,
    *,
    minimum_length: int = 5,
    maximum_count: int = 5000,
) -> list[FirmwareString]:
    result: list[FirmwareString] = []
    for section in document.sections:
        if section.nobits or section.size == 0:
            continue
        if not section.allocated and not section.name.startswith((".comment", ".debug_str")):
            continue
        data = document.section_data(section)
        result.extend(
            _extract_ascii_strings(
                data,
                section_name=section.name,
                base_address=section.address,
                minimum_length=minimum_length,
            )
        )
        result.extend(
            _extract_utf16le_strings(
                data,
                section_name=section.name,
                base_address=section.address,
                minimum_length=minimum_length,
            )
        )
        if len(result) >= maximum_count:
            break
    unique: dict[tuple[str, int, str], FirmwareString] = {}
    for item in result:
        unique[(item.section_name, item.address, item.text)] = item
    return sorted(unique.values(), key=lambda item: (item.address, item.text))[:maximum_count]


def analyze_section_entropy(document: ELFDocument) -> list[SectionEntropy]:
    result: list[SectionEntropy] = []
    for section in document.sections:
        if section.nobits or section.size == 0:
            continue
        data = document.section_data(section)
        if not data:
            continue
        zero_percent = round(data.count(0) * 100.0 / len(data), 3)
        printable_percent = round(sum(_printable(value) for value in data) * 100.0 / len(data), 3)
        entropy = shannon_entropy(data)
        if entropy >= 7.5:
            classification = "high-entropy"
        elif zero_percent >= 80:
            classification = "zero-dominant"
        elif printable_percent >= 70:
            classification = "text-dominant"
        elif entropy <= 2.0:
            classification = "low-entropy"
        else:
            classification = "mixed"
        result.append(
            SectionEntropy(
                section_name=section.name,
                address=section.address,
                size=section.size,
                entropy=entropy,
                zero_percent=zero_percent,
                printable_percent=printable_percent,
                classification=classification,
            )
        )
    return sorted(result, key=lambda item: item.size, reverse=True)


def string_category_summary(strings: Iterable[FirmwareString]) -> dict[str, int]:
    return dict(Counter(item.category for item in strings).most_common())
