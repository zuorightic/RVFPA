"""单个RISC-V固件的完整分析编排服务。

按固定次序连接ELF/MAP解析、工具链、资源、内存、指令、函数、内容和发布
检查，使命令行与Web接口获得一致的分析结果。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..analyzers.memory import analyze_memory_layout
from ..analyzers.content import (
    analyze_section_entropy,
    extract_firmware_strings,
    string_category_summary,
)
from ..analyzers.functions import build_function_profiles, function_summary
from ..analyzers.release import build_release_checks, release_check_summary
from ..analyzers.raw_decode import decode_executable_sections
from ..analyzers.riscv import architecture_string, build_instruction_profile
from ..analyzers.size import summarize_sizes
from ..analyzers.symbols import enrich_symbols_from_map, group_symbol_sizes
from ..analyzers.system_usage import analyze_system_usage
from ..config import parse_memory_regions
from ..errors import InputValidationError, ToolExecutionError
from ..models import Diagnostic, FirmwareAnalysis, MemoryRegion
from ..parsers.elf import ELFDocument, parse_elf
from ..parsers.mapfile import GNUMapDocument, parse_map_file
from .toolchain import RiscVToolchain


def _map_regions(document: GNUMapDocument | None) -> list[MemoryRegion]:
    """把MAP文件中的内存区域转换为统一领域模型。"""
    if document is None:
        return []
    return [
        MemoryRegion(
            name=item.name,
            origin=item.origin,
            length=item.length,
            permissions=item.attributes.lower(),
            description="Imported from GNU linker MAP file",
        )
        for item in document.memory_regions
        if item.length > 0
    ]


def _entry_point_diagnostic(document: ELFDocument) -> list[Diagnostic]:
    """检查入口地址是否落在已分配、可执行的节区内。"""
    entry = document.identity.entry_point
    if entry == 0:
        return [
            Diagnostic(
                severity="warning",
                code="zero_entry_point",
                title="ELF entry point is zero",
                detail="The firmware does not declare a non-zero entry point.",
                suggestion="Check the linker entry symbol and startup file.",
            )
        ]
    executable = [
        item
        for item in document.sections
        if item.allocated
        and item.executable
        and item.address <= entry < item.end_address
    ]
    if executable:
        return []
    return [
        Diagnostic(
            severity="error",
            code="entry_outside_code",
            title="Entry point is outside executable sections",
            detail=f"Entry point 0x{entry:x} is not covered by an executable section.",
            address=entry,
            suggestion="Review the linker ENTRY directive and executable section addresses.",
        )
    ]


def _symbol_diagnostics(document: ELFDocument) -> list[Diagnostic]:
    """从符号表生成重复全局符号和超大符号提示。"""
    diagnostics: list[Diagnostic] = []
    duplicate_globals: dict[str, int] = {}
    for symbol in document.symbols:
        if symbol.binding not in {"GLOBAL", "WEAK"} or symbol.section_name == "UND":
            continue
        duplicate_globals[symbol.name] = duplicate_globals.get(symbol.name, 0) + 1
    repeated = sorted(name for name, count in duplicate_globals.items() if count > 1)
    if repeated:
        diagnostics.append(
            Diagnostic(
                severity="info",
                code="duplicate_global_symbols",
                title="Multiple definitions appear in symbol tables",
                detail=", ".join(repeated[:20]),
                suggestion="Confirm whether static and dynamic symbol tables duplicate entries.",
            )
        )
    large_symbols = sorted(document.symbols, key=lambda item: item.size, reverse=True)
    if large_symbols and large_symbols[0].size >= 1024 * 1024:
        symbol = large_symbols[0]
        diagnostics.append(
            Diagnostic(
                severity="info",
                code="large_symbol",
                title="Large symbol detected",
                detail=f"{symbol.name} occupies {symbol.size} bytes in {symbol.section_name}.",
                subject=symbol.name,
                address=symbol.value,
                suggestion="Review whether the object can be compressed, streamed, or externalized.",
            )
        )
    return diagnostics


class FirmwareAnalysisService:
    """协调解析器和各分析器，生成一份完整的固件分析结果。"""

    def __init__(self, toolchain: RiscVToolchain | None = None):
        """允许注入工具链，便于在不同主机或测试环境中复用服务。"""
        self.toolchain = toolchain or RiscVToolchain()

    def analyze(
        self,
        elf_path: str | Path,
        *,
        map_path: str | Path | None = None,
        memory_config: dict[str, Any] | None = None,
        prefer_map_regions: bool = True,
    ) -> FirmwareAnalysis:
        """分析ELF及可选MAP文件，并在objdump不可用时退回内置解码器。"""
        elf = parse_elf(elf_path)
        map_document = parse_map_file(map_path) if map_path else None
        map_regions = _map_regions(map_document)
        if prefer_map_regions and map_regions and not memory_config:
            regions = map_regions
            region_source = "map"
        else:
            regions = parse_memory_regions(memory_config)
            region_source = "configuration"
        symbols = enrich_symbols_from_map(
            elf.symbols,
            map_document.contributions if map_document else [],
        )
        disassembly_warning = ""
        raw_records = decode_executable_sections(elf)
        try:
            objdump_document = self.toolchain.disassemble(elf.path)
            instruction_profile = build_instruction_profile(objdump_document.records)
        except ToolExecutionError as exc:
            instruction_profile = build_instruction_profile(raw_records)
            disassembly_warning = str(exc)
        attributes = self.toolchain.attributes(elf.path)
        if instruction_profile.total:
            elf.identity.architecture = architecture_string(
                elf.identity.architecture, instruction_profile
            )
        if attributes.get("riscv_arch"):
            elf.identity.architecture = attributes["riscv_arch"]
        region_usage, memory_diagnostics = analyze_memory_layout(elf.sections, regions)
        diagnostics = [
            *memory_diagnostics,
            *_entry_point_diagnostic(elf),
            *_symbol_diagnostics(elf),
        ]
        if disassembly_warning:
            diagnostics.append(
                Diagnostic(
                    severity="warning",
                    code="disassembly_unavailable",
                    title="Instruction analysis is unavailable",
                    detail=disassembly_warning,
                    suggestion="Install a compatible RISC-V objdump executable.",
                )
            )
        if map_document:
            for warning in map_document.warnings[:20]:
                diagnostics.append(
                    Diagnostic(
                        severity="warning",
                        code="linker_warning",
                        title="Linker MAP warning",
                        detail=warning,
                    )
                )
        size_summary = summarize_sizes(elf.sections, elf.segments, len(elf.data))
        function_profiles = build_function_profiles(
            instruction_profile.records, symbols
        )
        firmware_strings = extract_firmware_strings(elf)
        section_entropy = analyze_section_entropy(elf)
        metadata: dict[str, Any] = {
            "region_source": region_source,
            "symbol_size_by_type": group_symbol_sizes(symbols),
            "function_count": sum(1 for item in symbols if item.symbol_type == "FUNC"),
            "object_count": sum(1 for item in symbols if item.symbol_type == "OBJECT"),
            "map_object_sizes": map_document.by_object() if map_document else {},
            "map_section_sizes": map_document.by_section() if map_document else {},
            "map_output_sections": map_document.output_sections if map_document else {},
            "discarded_section_count": (
                len(map_document.discarded_sections) if map_document else 0
            ),
            "attributes": attributes,
            "raw_decoder_instruction_count": len(raw_records),
            "objdump_instruction_count": instruction_profile.total,
            "instruction_count_delta": instruction_profile.total - len(raw_records),
            "function_summary": function_summary(function_profiles),
            "string_category_summary": string_category_summary(firmware_strings),
            "system_usage": analyze_system_usage(instruction_profile),
        }
        analysis = FirmwareAnalysis(
            identity=elf.identity,
            segments=elf.segments,
            sections=elf.sections,
            symbols=symbols,
            map_contributions=(map_document.contributions if map_document else []),
            memory_regions=regions,
            region_usage=region_usage,
            diagnostics=diagnostics,
            instruction_profile=instruction_profile,
            size_summary=size_summary,
            function_profiles=function_profiles,
            firmware_strings=firmware_strings,
            section_entropy=section_entropy,
            toolchain=self.toolchain.describe(),
            metadata=metadata,
        )
        analysis.release_checks = build_release_checks(analysis)
        analysis.metadata["release_check_summary"] = release_check_summary(
            analysis.release_checks
        )
        return analysis

    def validate_inputs(
        self, elf_path: str | Path, map_path: str | Path | None = None
    ) -> tuple[Path, Path | None]:
        """规范化输入路径，并在分析前检查ELF和MAP文件是否存在。"""
        elf = Path(elf_path).expanduser().resolve()
        if not elf.is_file():
            raise InputValidationError(f"ELF file does not exist: {elf}")
        linker_map = None
        if map_path:
            linker_map = Path(map_path).expanduser().resolve()
            if not linker_map.is_file():
                raise InputValidationError(f"MAP file does not exist: {linker_map}")
        return elf, linker_map
