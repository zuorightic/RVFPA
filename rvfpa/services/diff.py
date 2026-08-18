from __future__ import annotations

from dataclasses import fields
from typing import Any, Callable, Iterable, TypeVar

from ..models import (
    Diagnostic,
    FirmwareAnalysis,
    FirmwareDiff,
    NamedDelta,
    ValueDelta,
    utc_now_iso,
)

T = TypeVar("T")


def _index_by(items: Iterable[T], key: Callable[[T], str]) -> dict[str, T]:
    result: dict[str, T] = {}
    for item in items:
        name = key(item)
        existing = result.get(name)
        if existing is None or getattr(item, "size", 0) > getattr(existing, "size", 0):
            result[name] = item
    return result


def _named_size_deltas(
    baseline: Iterable[T],
    target: Iterable[T],
    *,
    key: Callable[[T], str],
    size: Callable[[T], int],
    address: Callable[[T], int | None],
    kind: Callable[[T], str],
) -> list[NamedDelta]:
    old = _index_by(baseline, key)
    new = _index_by(target, key)
    result: list[NamedDelta] = []
    for name in sorted(old.keys() | new.keys()):
        old_item = old.get(name)
        new_item = new.get(name)
        if old_item is None:
            status = "added"
        elif new_item is None:
            status = "removed"
        elif size(old_item) != size(new_item) or address(old_item) != address(new_item):
            status = "changed"
        else:
            status = "unchanged"
        reference = new_item or old_item
        result.append(
            NamedDelta(
                name=name,
                status=status,
                before_size=size(old_item) if old_item else 0,
                after_size=size(new_item) if new_item else 0,
                before_address=address(old_item) if old_item else None,
                after_address=address(new_item) if new_item else None,
                kind=kind(reference) if reference else "",
            )
        )
    return sorted(
        result,
        key=lambda item: (
            item.status == "unchanged",
            -abs(item.delta),
            item.name,
        ),
    )


def _size_deltas(
    baseline: FirmwareAnalysis, target: FirmwareAnalysis
) -> dict[str, ValueDelta]:
    result: dict[str, ValueDelta] = {}
    for field in fields(baseline.size_summary):
        before = getattr(baseline.size_summary, field.name)
        after = getattr(target.size_summary, field.name)
        result[field.name] = ValueDelta(before=before, after=after)
    return result


def _instruction_deltas(
    baseline: FirmwareAnalysis, target: FirmwareAnalysis
) -> dict[str, ValueDelta]:
    old = baseline.instruction_profile.categories
    new = target.instruction_profile.categories
    result = {
        name: ValueDelta(before=old.get(name, 0), after=new.get(name, 0))
        for name in sorted(old.keys() | new.keys())
    }
    result["total"] = ValueDelta(
        before=baseline.instruction_profile.total,
        after=target.instruction_profile.total,
    )
    result["compressed"] = ValueDelta(
        before=baseline.instruction_profile.compressed,
        after=target.instruction_profile.compressed,
    )
    return result


def _extension_changes(
    baseline: FirmwareAnalysis, target: FirmwareAnalysis
) -> dict[str, str]:
    old = set(baseline.instruction_profile.extensions)
    new = set(target.instruction_profile.extensions)
    changes: dict[str, str] = {}
    for extension in sorted(old | new):
        if extension not in old:
            changes[extension] = "added"
        elif extension not in new:
            changes[extension] = "removed"
        else:
            before = baseline.instruction_profile.extensions.get(extension, 0)
            after = target.instruction_profile.extensions.get(extension, 0)
            if before != after:
                changes[extension] = "changed"
    return changes


def _identity_changes(
    baseline: FirmwareAnalysis, target: FirmwareAnalysis
) -> dict[str, dict[str, Any]]:
    keys = [
        "file_name",
        "file_size",
        "sha256",
        "elf_class",
        "byte_order",
        "architecture",
        "entry_point",
        "flags",
        "abi",
        "build_id",
        "comment",
    ]
    result: dict[str, dict[str, Any]] = {}
    for key in keys:
        before = getattr(baseline.identity, key)
        after = getattr(target.identity, key)
        if before != after:
            result[key] = {"before": before, "after": after}
    return result


def _diff_diagnostics(
    baseline: FirmwareAnalysis,
    target: FirmwareAnalysis,
    size_deltas: dict[str, ValueDelta],
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    code_delta = size_deltas["code_bytes"]
    if code_delta.absolute > 0 and (code_delta.percent or 0) >= 10:
        diagnostics.append(
            Diagnostic(
                severity="warning",
                code="code_growth",
                title="Code size increased significantly",
                detail=(
                    f"Executable code increased by {code_delta.absolute} bytes "
                    f"({code_delta.percent}%)."
                ),
                suggestion="Inspect the largest changed functions and compiler options.",
            )
        )
    ram_before = (
        baseline.size_summary.initialized_data_bytes
        + baseline.size_summary.zero_fill_bytes
    )
    ram_after = (
        target.size_summary.initialized_data_bytes + target.size_summary.zero_fill_bytes
    )
    ram_delta = ValueDelta(ram_before, ram_after)
    if ram_delta.absolute > 0 and (ram_delta.percent or 0) >= 10:
        diagnostics.append(
            Diagnostic(
                severity="warning",
                code="ram_growth",
                title="Static RAM demand increased significantly",
                detail=f"Static RAM demand increased by {ram_delta.absolute} bytes.",
                suggestion="Inspect new global variables and enlarged buffers.",
            )
        )
    old_errors = sum(item.severity == "error" for item in baseline.diagnostics)
    new_errors = sum(item.severity == "error" for item in target.diagnostics)
    if new_errors > old_errors:
        diagnostics.append(
            Diagnostic(
                severity="error",
                code="new_analysis_errors",
                title="The target version introduces analysis errors",
                detail=f"Error count changed from {old_errors} to {new_errors}.",
                suggestion="Resolve new layout errors before releasing the firmware.",
            )
        )
    return diagnostics


def compare_firmware(
    baseline: FirmwareAnalysis,
    target: FirmwareAnalysis,
    *,
    baseline_id: int = 0,
    target_id: int = 0,
) -> FirmwareDiff:
    section_deltas = _named_size_deltas(
        baseline.sections,
        target.sections,
        key=lambda item: item.name,
        size=lambda item: item.size,
        address=lambda item: item.address,
        kind=lambda item: item.section_type,
    )
    symbol_deltas = _named_size_deltas(
        (item for item in baseline.symbols if item.size),
        (item for item in target.symbols if item.size),
        key=lambda item: item.name,
        size=lambda item: item.size,
        address=lambda item: item.value,
        kind=lambda item: item.symbol_type,
    )
    region_deltas = _named_size_deltas(
        baseline.region_usage,
        target.region_usage,
        key=lambda item: item.region.name,
        size=lambda item: item.used_bytes,
        address=lambda item: item.region.origin,
        kind=lambda _item: "memory-region",
    )
    size_deltas = _size_deltas(baseline, target)
    diagnostics = _diff_diagnostics(baseline, target, size_deltas)
    changed_symbols = [item for item in symbol_deltas if item.status != "unchanged"]
    changed_sections = [item for item in section_deltas if item.status != "unchanged"]
    summary = {
        "changed_section_count": len(changed_sections),
        "changed_symbol_count": len(changed_symbols),
        "added_symbol_count": sum(item.status == "added" for item in symbol_deltas),
        "removed_symbol_count": sum(item.status == "removed" for item in symbol_deltas),
        "code_delta": size_deltas["code_bytes"].absolute,
        "runtime_delta": size_deltas["runtime_bytes"].absolute,
        "file_delta": size_deltas["file_bytes"].absolute,
        "largest_symbol_growth": [
            item.name
            for item in sorted(symbol_deltas, key=lambda value: value.delta, reverse=True)
            if item.delta > 0
        ][:10],
        "largest_symbol_reduction": [
            item.name
            for item in sorted(symbol_deltas, key=lambda value: value.delta)
            if item.delta < 0
        ][:10],
    }
    return FirmwareDiff(
        baseline_id=baseline_id,
        target_id=target_id,
        created_at=utc_now_iso(),
        identity_changes=_identity_changes(baseline, target),
        size_deltas=size_deltas,
        section_deltas=section_deltas,
        symbol_deltas=symbol_deltas,
        region_deltas=region_deltas,
        instruction_deltas=_instruction_deltas(baseline, target),
        extension_changes=_extension_changes(baseline, target),
        diagnostics=diagnostics,
        summary=summary,
    )
