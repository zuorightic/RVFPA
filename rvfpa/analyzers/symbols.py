"""符号大小补全与MAP来源信息合并。"""

from __future__ import annotations

from collections import defaultdict

from ..models import MapContribution, SymbolRecord


def estimate_zero_size_symbols(symbols: list[SymbolRecord]) -> list[SymbolRecord]:
    by_section: dict[str, list[SymbolRecord]] = defaultdict(list)
    for symbol in symbols:
        if symbol.value and symbol.section_name not in {"", "UND", "ABS"}:
            by_section[symbol.section_name].append(symbol)
    for values in by_section.values():
        values.sort(key=lambda item: (item.value, item.name))
        for index, symbol in enumerate(values[:-1]):
            if symbol.size == 0:
                following = values[index + 1]
                distance = following.value - symbol.value
                if 0 < distance < 64 * 1024 * 1024:
                    symbol.size = distance
    return symbols


def enrich_symbols_from_map(
    symbols: list[SymbolRecord], contributions: list[MapContribution]
) -> list[SymbolRecord]:
    if not contributions:
        return estimate_zero_size_symbols(symbols)
    contribution_by_symbol = {
        item.symbol_name: item for item in contributions if item.symbol_name
    }
    existing_names = {item.name for item in symbols}
    for symbol in symbols:
        contribution = contribution_by_symbol.get(symbol.name)
        if contribution and symbol.size == 0:
            symbol.size = contribution.size
            symbol.source = contribution.object_path or "map"
    for name, contribution in contribution_by_symbol.items():
        if name in existing_names:
            continue
        symbols.append(
            SymbolRecord(
                name=name,
                value=contribution.address,
                size=contribution.size,
                symbol_type="NOTYPE",
                binding="UNKNOWN",
                visibility="DEFAULT",
                section_index=-1,
                section_name=contribution.section_name,
                source=contribution.object_path or "map",
            )
        )
    return estimate_zero_size_symbols(symbols)


def group_symbol_sizes(symbols: list[SymbolRecord]) -> dict[str, int]:
    totals: dict[str, int] = defaultdict(int)
    for symbol in symbols:
        totals[symbol.symbol_type] += symbol.size
    return dict(sorted(totals.items(), key=lambda item: item[1], reverse=True))
