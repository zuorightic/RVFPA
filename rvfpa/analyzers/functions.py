"""函数规模、复杂度和调用关系画像。

把函数符号与反汇编指令关联，统计大小、指令数、分支、叶函数以及调用方和
被调用方，为版本增长定位提供函数级依据。
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from ..models import FunctionProfile, InstructionRecord, SymbolRecord

_TARGET_RE = re.compile(r"<([^>]+)>")
_DIRECT_ADDRESS_RE = re.compile(r"(?:^|,)\s*(?:0x)?([0-9a-fA-F]{6,16})(?:\s|$)")
_CONDITIONAL_BRANCHES = {
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",
    "c.beqz",
    "c.bnez",
}
_CALL_MNEMONICS = {"call", "tail"}
_JUMP_MNEMONICS = {"jal", "jalr", "c.jal", "c.jalr"}
_RETURN_MNEMONICS = {"ret", "c.jr"}


@dataclass(slots=True)
class _FunctionAccumulator:
    name: str
    address: int = 0
    symbol_size: int = 0
    records: list[InstructionRecord] = field(default_factory=list)
    categories: Counter[str] = field(default_factory=Counter)
    extensions: Counter[str] = field(default_factory=Counter)
    callees: set[str] = field(default_factory=set)
    source_lines: set[str] = field(default_factory=set)
    branch_count: int = 0
    call_count: int = 0
    load_count: int = 0
    store_count: int = 0
    compressed_count: int = 0


def _normalize_name(value: str) -> str:
    name = value.strip()
    if "+0x" in name:
        name = name.split("+0x", 1)[0]
    if "-0x" in name:
        name = name.split("-0x", 1)[0]
    return name


def _symbol_indexes(symbols: Iterable[SymbolRecord]) -> tuple[dict[str, SymbolRecord], list[SymbolRecord]]:
    functions = [
        item
        for item in symbols
        if item.symbol_type == "FUNC" and item.value and item.section_name != "UND"
    ]
    by_name = {item.name: item for item in functions}
    by_address = sorted(functions, key=lambda item: item.value)
    return by_name, by_address


def _name_for_address(address: int, symbols: list[SymbolRecord]) -> str:
    candidate = ""
    for symbol in symbols:
        if symbol.value > address:
            break
        if symbol.size and address >= symbol.value + symbol.size:
            continue
        candidate = symbol.name
    return candidate


def _extract_call_target(
    record: InstructionRecord,
    by_address: list[SymbolRecord],
) -> str:
    target_match = _TARGET_RE.search(record.operands)
    if target_match:
        return _normalize_name(target_match.group(1))
    address_match = _DIRECT_ADDRESS_RE.search(record.operands)
    if address_match:
        try:
            return _name_for_address(int(address_match.group(1), 16), by_address)
        except ValueError:
            return ""
    return ""


def _is_call(record: InstructionRecord) -> bool:
    mnemonic = record.mnemonic.lower()
    if mnemonic in _CALL_MNEMONICS:
        return True
    if mnemonic in _JUMP_MNEMONICS:
        operands = record.operands.replace(" ", "")
        if mnemonic in {"jal", "c.jal"}:
            return not operands.startswith("zero,")
        if mnemonic in {"jalr", "c.jalr"}:
            return operands.startswith("ra,") or mnemonic == "c.jalr"
    return False


def _profile_from_accumulator(
    accumulator: _FunctionAccumulator,
    callers: dict[str, set[str]],
) -> FunctionProfile:
    records = sorted(accumulator.records, key=lambda item: item.address)
    if records:
        byte_count = sum(max(1, item.width) for item in records)
        inferred_size = records[-1].address + records[-1].width - records[0].address
        address = accumulator.address or records[0].address
    else:
        byte_count = 0
        inferred_size = 0
        address = accumulator.address
    size = accumulator.symbol_size or inferred_size or byte_count
    complexity = 1 + accumulator.branch_count
    return FunctionProfile(
        name=accumulator.name,
        address=address,
        size=size,
        instruction_count=len(records),
        byte_count=byte_count,
        compressed_count=accumulator.compressed_count,
        branch_count=accumulator.branch_count,
        call_count=accumulator.call_count,
        load_count=accumulator.load_count,
        store_count=accumulator.store_count,
        estimated_complexity=complexity,
        is_leaf=accumulator.call_count == 0,
        categories=dict(accumulator.categories.most_common()),
        extensions=dict(accumulator.extensions.most_common()),
        callees=sorted(accumulator.callees),
        callers=sorted(callers.get(accumulator.name, set())),
        source_lines=sorted(accumulator.source_lines)[:50],
    )


def build_function_profiles(
    records: Iterable[InstructionRecord], symbols: Iterable[SymbolRecord]
) -> list[FunctionProfile]:
    by_name, by_address = _symbol_indexes(symbols)
    accumulators: dict[str, _FunctionAccumulator] = {}
    for symbol in by_name.values():
        accumulators[symbol.name] = _FunctionAccumulator(
            name=symbol.name,
            address=symbol.value,
            symbol_size=symbol.size,
        )
    for record in records:
        function_name = _normalize_name(record.function_name)
        if not function_name:
            function_name = _name_for_address(record.address, by_address)
        if not function_name:
            function_name = f"sub_{record.address:x}"
        accumulator = accumulators.setdefault(
            function_name,
            _FunctionAccumulator(name=function_name, address=record.address),
        )
        accumulator.records.append(record)
        accumulator.categories[record.category or "unknown"] += 1
        accumulator.extensions[record.extension or "unknown"] += 1
        if record.width == 2 or record.mnemonic.lower().startswith("c."):
            accumulator.compressed_count += 1
        if record.category == "load":
            accumulator.load_count += 1
        if record.category == "store":
            accumulator.store_count += 1
        if record.mnemonic.lower() in _CONDITIONAL_BRANCHES:
            accumulator.branch_count += 1
        if record.source_line:
            accumulator.source_lines.add(record.source_line)
        if _is_call(record):
            accumulator.call_count += 1
            target = _extract_call_target(record, by_address)
            if target and target != function_name:
                accumulator.callees.add(target)
    callers: dict[str, set[str]] = defaultdict(set)
    for accumulator in accumulators.values():
        for callee in accumulator.callees:
            callers[callee].add(accumulator.name)
    profiles = [
        _profile_from_accumulator(accumulator, callers)
        for accumulator in accumulators.values()
        if accumulator.records or accumulator.symbol_size
    ]
    return sorted(
        profiles,
        key=lambda item: (item.instruction_count, item.size, item.name),
        reverse=True,
    )


def function_call_edges(profiles: Iterable[FunctionProfile]) -> list[tuple[str, str]]:
    edges: list[tuple[str, str]] = []
    for profile in profiles:
        edges.extend((profile.name, callee) for callee in profile.callees)
    return sorted(set(edges))


def function_summary(profiles: Iterable[FunctionProfile]) -> dict[str, int | float]:
    values = list(profiles)
    total = len(values)
    leaf = sum(item.is_leaf for item in values)
    return {
        "function_count": total,
        "leaf_function_count": leaf,
        "non_leaf_function_count": total - leaf,
        "call_edge_count": len(function_call_edges(values)),
        "maximum_complexity": max((item.estimated_complexity for item in values), default=0),
        "average_complexity": round(
            sum(item.estimated_complexity for item in values) / max(1, total), 3
        ),
        "maximum_instruction_count": max(
            (item.instruction_count for item in values), default=0
        ),
    }
