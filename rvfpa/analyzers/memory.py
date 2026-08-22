"""节区到内存区域的映射与布局检查。

根据FLASH、RAM等区域的地址、容量和权限统计占用，并诊断段越界、区域重叠
及读写执行权限不匹配。
"""

from __future__ import annotations

from collections import defaultdict

from ..models import Diagnostic, MemoryRegion, RegionUsage, SectionRecord


def _section_required_permissions(section: SectionRecord) -> set[str]:
    required = {"r"}
    if section.writable:
        required.add("w")
    if section.executable:
        required.add("x")
    return required


def _find_overlaps(sections: list[SectionRecord]) -> list[tuple[SectionRecord, SectionRecord]]:
    allocated = sorted(
        (item for item in sections if item.allocated and item.size),
        key=lambda item: (item.address, item.end_address),
    )
    overlaps: list[tuple[SectionRecord, SectionRecord]] = []
    for index, current in enumerate(allocated):
        for following in allocated[index + 1 :]:
            if following.address >= current.end_address:
                break
            if following.end_address > current.address:
                overlaps.append((current, following))
    return overlaps


def analyze_memory_layout(
    sections: list[SectionRecord], regions: list[MemoryRegion]
) -> tuple[list[RegionUsage], list[Diagnostic]]:
    diagnostics: list[Diagnostic] = []
    region_sections: dict[str, list[SectionRecord]] = defaultdict(list)
    uncovered: list[SectionRecord] = []
    for section in sections:
        if not section.allocated or section.size == 0:
            continue
        matched = [
            region for region in regions if region.contains(section.address, section.size)
        ]
        if not matched:
            uncovered.append(section)
            diagnostics.append(
                Diagnostic(
                    severity="error",
                    code="section_outside_regions",
                    title="Section is outside configured memory",
                    detail=(
                        f"{section.name} occupies 0x{section.address:x}-"
                        f"0x{section.end_address:x}, which is not fully covered by a region."
                    ),
                    subject=section.name,
                    address=section.address,
                    suggestion="Adjust the memory configuration or linker script.",
                )
            )
            continue
        region = matched[0]
        region_sections[region.name].append(section)
        required = _section_required_permissions(section)
        available = set(region.permissions.replace("-", ""))
        missing = required - available
        if missing:
            diagnostics.append(
                Diagnostic(
                    severity="warning",
                    code="permission_mismatch",
                    title="Section permissions do not match region",
                    detail=(
                        f"{section.name} requires {''.join(sorted(required))}, while "
                        f"{region.name} provides {region.permissions}."
                    ),
                    subject=section.name,
                    address=section.address,
                    suggestion="Review region permissions and section placement.",
                )
            )
    usages: list[RegionUsage] = []
    for region in regions:
        assigned = region_sections.get(region.name, [])
        intervals = sorted(
            (section.address, section.end_address, section) for section in assigned
        )
        merged: list[tuple[int, int]] = []
        for start, end, _section in intervals:
            if not merged or start > merged[-1][1]:
                merged.append((start, end))
            else:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        used_bytes = sum(end - start for start, end in merged)
        file_bytes = sum(section.size for section in assigned if not section.nobits)
        usage = RegionUsage(
            region=region,
            used_bytes=used_bytes,
            file_bytes=file_bytes,
            section_names=[section.name for section in assigned],
            uncovered_sections=[section.name for section in uncovered],
        )
        usages.append(usage)
        if usage.usage_percent >= 100:
            diagnostics.append(
                Diagnostic(
                    severity="error",
                    code="region_exhausted",
                    title="Memory region is exhausted",
                    detail=f"{region.name} usage is {usage.usage_percent}%.",
                    subject=region.name,
                    address=region.origin,
                    suggestion="Reduce firmware size or enlarge the region.",
                )
            )
        elif usage.usage_percent >= 90:
            diagnostics.append(
                Diagnostic(
                    severity="warning",
                    code="region_near_capacity",
                    title="Memory region is near capacity",
                    detail=f"{region.name} usage is {usage.usage_percent}%.",
                    subject=region.name,
                    address=region.origin,
                    suggestion="Reserve additional space for future firmware growth.",
                )
            )
    for first, second in _find_overlaps(sections):
        diagnostics.append(
            Diagnostic(
                severity="error",
                code="section_overlap",
                title="Allocated sections overlap",
                detail=(
                    f"{first.name} (0x{first.address:x}-0x{first.end_address:x}) overlaps "
                    f"{second.name} (0x{second.address:x}-0x{second.end_address:x})."
                ),
                subject=f"{first.name}, {second.name}",
                address=max(first.address, second.address),
                suggestion="Inspect the linker script and section addresses.",
            )
        )
    entry_sections = [
        section
        for section in sections
        if section.allocated and section.executable and section.size
    ]
    if not entry_sections:
        diagnostics.append(
            Diagnostic(
                severity="warning",
                code="no_executable_section",
                title="No executable section found",
                detail="The ELF file contains no allocated executable section.",
                suggestion="Verify that the selected file is a linked firmware image.",
            )
        )
    return usages, diagnostics
