from __future__ import annotations

from ..models import ProgramSegment, SectionRecord, SizeSummary


def _is_debug_section(name: str) -> bool:
    return name.startswith((".debug", ".zdebug", ".gdb", ".stab"))


def _is_metadata_section(section: SectionRecord) -> bool:
    if section.allocated:
        return False
    return section.name.startswith(
        (
            ".symtab",
            ".strtab",
            ".shstrtab",
            ".comment",
            ".note",
            ".riscv.attributes",
            ".rela",
            ".rel",
        )
    )


def summarize_sizes(
    sections: list[SectionRecord], segments: list[ProgramSegment], file_size: int
) -> SizeSummary:
    result = SizeSummary(file_bytes=file_size)
    result.load_bytes = sum(
        item.file_size for item in segments if item.segment_type == "LOAD"
    )
    result.runtime_bytes = sum(
        item.memory_size for item in segments if item.segment_type == "LOAD"
    )
    for section in sections:
        if _is_debug_section(section.name):
            result.debug_bytes += section.size
            continue
        if _is_metadata_section(section):
            result.metadata_bytes += section.size
            continue
        if not section.allocated:
            continue
        if section.executable:
            result.code_bytes += section.size
        elif section.writable and section.nobits:
            result.zero_fill_bytes += section.size
        elif section.writable:
            result.initialized_data_bytes += section.size
        else:
            result.readonly_bytes += section.size
    if result.runtime_bytes == 0:
        result.runtime_bytes = (
            result.code_bytes
            + result.readonly_bytes
            + result.initialized_data_bytes
            + result.zero_fill_bytes
        )
    if result.load_bytes == 0:
        result.load_bytes = (
            result.code_bytes + result.readonly_bytes + result.initialized_data_bytes
        )
    return result

