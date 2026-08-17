from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

from ..constants import (
    ELF_CLASS_32,
    ELF_CLASS_64,
    ELF_DATA_BIG,
    ELF_DATA_LITTLE,
    ELF_MACHINE_RISCV,
    ELF_MAGIC,
    PROGRAM_TYPE_NAMES,
    SECTION_TYPE_NAMES,
    SYMBOL_BIND_NAMES,
    SYMBOL_TYPE_NAMES,
)
from ..errors import ELFParseError, UnsupportedFormatError
from ..models import FirmwareIdentity, ProgramSegment, SectionRecord, SymbolRecord

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_DYNSYM = 11
PN_XNUM = 0xFFFF
SHN_XINDEX = 0xFFFF

VISIBILITY_NAMES = {
    0: "DEFAULT",
    1: "INTERNAL",
    2: "HIDDEN",
    3: "PROTECTED",
}


@dataclass(slots=True)
class ELFHeader:
    elf_class: int
    data_encoding: int
    byte_order: str
    os_abi: int
    abi_version: int
    file_type: int
    machine: int
    version: int
    entry: int
    program_offset: int
    section_offset: int
    flags: int
    header_size: int
    program_entry_size: int
    program_count: int
    section_entry_size: int
    section_count: int
    section_name_index: int


@dataclass(slots=True)
class RawSectionHeader:
    name_offset: int
    section_type: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(slots=True)
class ELFDocument:
    path: Path
    data: bytes
    header: ELFHeader
    identity: FirmwareIdentity
    segments: list[ProgramSegment]
    sections: list[SectionRecord]
    symbols: list[SymbolRecord]
    raw_sections: list[RawSectionHeader]

    def section_by_name(self, name: str) -> SectionRecord | None:
        return next((item for item in self.sections if item.name == name), None)

    def section_data(self, section: SectionRecord | str) -> bytes:
        record = self.section_by_name(section) if isinstance(section, str) else section
        if record is None or record.nobits or record.size == 0:
            return b""
        end = record.offset + record.size
        if record.offset < 0 or end > len(self.data):
            raise ELFParseError(f"Section {record.name} exceeds file boundary")
        return self.data[record.offset:end]

    def executable_sections(self) -> Iterator[tuple[SectionRecord, bytes]]:
        for section in self.sections:
            if section.allocated and section.executable and section.size:
                yield section, self.section_data(section)

    def allocated_sections(self) -> Iterator[SectionRecord]:
        return (section for section in self.sections if section.allocated and section.size)


class _ELFReader:
    def __init__(self, data: bytes, path: Path):
        self.data = data
        self.path = path
        self.endian = "<"
        self.elf_class = 0

    def unpack_from(self, fmt: str, offset: int) -> tuple[int, ...]:
        try:
            return struct.unpack_from(self.endian + fmt, self.data, offset)
        except struct.error as exc:
            raise ELFParseError(
                f"Unexpected end of ELF file at offset 0x{offset:x}: {self.path.name}"
            ) from exc

    def validate_range(self, offset: int, size: int, label: str) -> None:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ELFParseError(
                f"{label} range 0x{offset:x}..0x{offset + size:x} exceeds file size"
            )

    def parse_header(self) -> ELFHeader:
        if len(self.data) < 16 or self.data[:4] != ELF_MAGIC:
            raise UnsupportedFormatError(f"Not an ELF file: {self.path.name}")
        self.elf_class = self.data[4]
        data_encoding = self.data[5]
        if self.elf_class not in (ELF_CLASS_32, ELF_CLASS_64):
            raise UnsupportedFormatError(f"Unsupported ELF class: {self.elf_class}")
        if data_encoding == ELF_DATA_LITTLE:
            self.endian = "<"
            byte_order = "little"
        elif data_encoding == ELF_DATA_BIG:
            self.endian = ">"
            byte_order = "big"
        else:
            raise UnsupportedFormatError(f"Unsupported ELF byte order: {data_encoding}")
        os_abi = self.data[7]
        abi_version = self.data[8]
        if self.elf_class == ELF_CLASS_32:
            values = self.unpack_from("HHIIIIIHHHHHH", 16)
        else:
            values = self.unpack_from("HHIQQQIHHHHHH", 16)
        (
            file_type,
            machine,
            version,
            entry,
            program_offset,
            section_offset,
            flags,
            header_size,
            program_entry_size,
            program_count,
            section_entry_size,
            section_count,
            section_name_index,
        ) = values
        minimum_header = 52 if self.elf_class == ELF_CLASS_32 else 64
        if header_size < minimum_header:
            raise ELFParseError(f"Invalid ELF header size: {header_size}")
        return ELFHeader(
            elf_class=self.elf_class,
            data_encoding=data_encoding,
            byte_order=byte_order,
            os_abi=os_abi,
            abi_version=abi_version,
            file_type=file_type,
            machine=machine,
            version=version,
            entry=entry,
            program_offset=program_offset,
            section_offset=section_offset,
            flags=flags,
            header_size=header_size,
            program_entry_size=program_entry_size,
            program_count=program_count,
            section_entry_size=section_entry_size,
            section_count=section_count,
            section_name_index=section_name_index,
        )

    def parse_raw_sections(self, header: ELFHeader) -> list[RawSectionHeader]:
        if header.section_offset == 0:
            return []
        expected_size = 40 if header.elf_class == ELF_CLASS_32 else 64
        if header.section_entry_size < expected_size:
            raise ELFParseError(
                f"Section entry size {header.section_entry_size} is smaller than expected"
            )
        provisional_count = header.section_count or 1
        self.validate_range(
            header.section_offset,
            provisional_count * header.section_entry_size,
            "Section header table",
        )
        first = self._parse_one_section(header.section_offset, header.elf_class)
        section_count = first.size if header.section_count == 0 else header.section_count
        if section_count > 1_000_000:
            raise ELFParseError(f"Unreasonable section count: {section_count}")
        self.validate_range(
            header.section_offset,
            section_count * header.section_entry_size,
            "Section header table",
        )
        sections = []
        for index in range(section_count):
            offset = header.section_offset + index * header.section_entry_size
            sections.append(self._parse_one_section(offset, header.elf_class))
        if header.section_count == 0:
            header.section_count = section_count
        if header.section_name_index == SHN_XINDEX and sections:
            header.section_name_index = sections[0].link
        if header.program_count == PN_XNUM and sections:
            header.program_count = sections[0].info
        return sections

    def _parse_one_section(self, offset: int, elf_class: int) -> RawSectionHeader:
        if elf_class == ELF_CLASS_32:
            values = self.unpack_from("IIIIIIIIII", offset)
        else:
            values = self.unpack_from("IIQQQQIIQQ", offset)
        return RawSectionHeader(*values)

    def parse_sections(
        self, header: ELFHeader, raw_sections: list[RawSectionHeader]
    ) -> list[SectionRecord]:
        names = b""
        if raw_sections and 0 <= header.section_name_index < len(raw_sections):
            string_header = raw_sections[header.section_name_index]
            if string_header.section_type == SHT_STRTAB:
                self.validate_range(string_header.offset, string_header.size, "Section name table")
                names = self.data[string_header.offset : string_header.offset + string_header.size]
        result: list[SectionRecord] = []
        for index, raw in enumerate(raw_sections):
            name = self._read_c_string(names, raw.name_offset)
            result.append(
                SectionRecord(
                    index=index,
                    name=name or f"<section-{index}>",
                    section_type=SECTION_TYPE_NAMES.get(raw.section_type, f"TYPE_{raw.section_type}"),
                    flags=raw.flags,
                    address=raw.address,
                    offset=raw.offset,
                    size=raw.size,
                    link=raw.link,
                    info=raw.info,
                    alignment=raw.alignment,
                    entry_size=raw.entry_size,
                    allocated=bool(raw.flags & SHF_ALLOC),
                    writable=bool(raw.flags & SHF_WRITE),
                    executable=bool(raw.flags & SHF_EXECINSTR),
                    nobits=raw.section_type == SHT_NOBITS,
                )
            )
        return result

    def parse_program_headers(self, header: ELFHeader) -> list[ProgramSegment]:
        if not header.program_offset or not header.program_count:
            return []
        expected_size = 32 if header.elf_class == ELF_CLASS_32 else 56
        if header.program_entry_size < expected_size:
            raise ELFParseError(
                f"Program entry size {header.program_entry_size} is smaller than expected"
            )
        self.validate_range(
            header.program_offset,
            header.program_count * header.program_entry_size,
            "Program header table",
        )
        result: list[ProgramSegment] = []
        for index in range(header.program_count):
            offset = header.program_offset + index * header.program_entry_size
            if header.elf_class == ELF_CLASS_32:
                (
                    segment_type,
                    file_offset,
                    virtual_address,
                    physical_address,
                    file_size,
                    memory_size,
                    flags,
                    alignment,
                ) = self.unpack_from("IIIIIIII", offset)
            else:
                (
                    segment_type,
                    flags,
                    file_offset,
                    virtual_address,
                    physical_address,
                    file_size,
                    memory_size,
                    alignment,
                ) = self.unpack_from("IIQQQQQQ", offset)
            result.append(
                ProgramSegment(
                    index=index,
                    segment_type=PROGRAM_TYPE_NAMES.get(segment_type, f"TYPE_{segment_type}"),
                    offset=file_offset,
                    virtual_address=virtual_address,
                    physical_address=physical_address,
                    file_size=file_size,
                    memory_size=memory_size,
                    flags=self._program_flags(flags),
                    alignment=alignment,
                )
            )
        return result

    def parse_symbols(
        self,
        header: ELFHeader,
        raw_sections: list[RawSectionHeader],
        sections: list[SectionRecord],
    ) -> list[SymbolRecord]:
        symbols: list[SymbolRecord] = []
        seen: set[tuple[str, int, int, str]] = set()
        for raw in raw_sections:
            if raw.section_type not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            if raw.entry_size == 0 or raw.size == 0:
                continue
            if raw.link >= len(raw_sections):
                continue
            string_header = raw_sections[raw.link]
            self.validate_range(string_header.offset, string_header.size, "Symbol string table")
            strings = self.data[
                string_header.offset : string_header.offset + string_header.size
            ]
            count = raw.size // raw.entry_size
            self.validate_range(raw.offset, raw.size, "Symbol table")
            for index in range(count):
                offset = raw.offset + index * raw.entry_size
                if header.elf_class == ELF_CLASS_32:
                    name_offset, value, size, info, other, section_index = self.unpack_from(
                        "IIIBBH", offset
                    )
                else:
                    name_offset, info, other, section_index, value, size = self.unpack_from(
                        "IBBHQQ", offset
                    )
                name = self._read_c_string(strings, name_offset)
                if not name:
                    continue
                symbol_type = SYMBOL_TYPE_NAMES.get(info & 0x0F, f"TYPE_{info & 0x0F}")
                binding = SYMBOL_BIND_NAMES.get(info >> 4, f"BIND_{info >> 4}")
                visibility = VISIBILITY_NAMES.get(other & 0x03, f"VIS_{other & 0x03}")
                section_name = ""
                if 0 <= section_index < len(sections):
                    section_name = sections[section_index].name
                elif section_index == 0:
                    section_name = "UND"
                elif section_index == 0xFFF1:
                    section_name = "ABS"
                key = (name, value, size, symbol_type)
                if key in seen:
                    continue
                seen.add(key)
                symbols.append(
                    SymbolRecord(
                        name=name,
                        value=value,
                        size=size,
                        symbol_type=symbol_type,
                        binding=binding,
                        visibility=visibility,
                        section_index=section_index,
                        section_name=section_name,
                    )
                )
        symbols.sort(key=lambda item: (item.value, item.name))
        return symbols

    def extract_build_id(
        self, raw_sections: list[RawSectionHeader], sections: list[SectionRecord]
    ) -> str:
        for raw, section in zip(raw_sections, sections):
            if raw.section_type != SHT_NOTE or raw.size < 12:
                continue
            self.validate_range(raw.offset, raw.size, f"Note section {section.name}")
            data = self.data[raw.offset : raw.offset + raw.size]
            cursor = 0
            while cursor + 12 <= len(data):
                namesz, descsz, note_type = struct.unpack_from(self.endian + "III", data, cursor)
                cursor += 12
                name_end = cursor + namesz
                name = data[cursor:name_end].rstrip(b"\0")
                cursor += (namesz + 3) & ~3
                desc_end = cursor + descsz
                desc = data[cursor:desc_end]
                cursor += (descsz + 3) & ~3
                if name == b"GNU" and note_type == 3:
                    return desc.hex()
        return ""

    @staticmethod
    def _read_c_string(data: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(data):
            return ""
        end = data.find(b"\0", offset)
        if end < 0:
            end = len(data)
        return data[offset:end].decode("utf-8", errors="replace")

    @staticmethod
    def _program_flags(flags: int) -> str:
        return (
            ("r" if flags & 0x4 else "-")
            + ("w" if flags & 0x2 else "-")
            + ("x" if flags & 0x1 else "-")
        )


def _read_file(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ELFParseError(f"Cannot read ELF file: {path}") from exc


def _extract_comment(reader: _ELFReader, sections: list[SectionRecord]) -> str:
    comment_section = next((item for item in sections if item.name == ".comment"), None)
    if comment_section is None or comment_section.nobits:
        return ""
    try:
        raw = reader.data[
            comment_section.offset : comment_section.offset + comment_section.size
        ]
    except Exception:
        return ""
    values = [
        item.decode("utf-8", errors="replace").strip()
        for item in raw.split(b"\0")
        if item.strip()
    ]
    return " | ".join(dict.fromkeys(values))


def _riscv_abi(flags: int, elf_class: int) -> str:
    float_abi = flags & 0x6
    float_name = {
        0x0: "soft-float",
        0x2: "single-float",
        0x4: "double-float",
        0x6: "quad-float",
    }.get(float_abi, "unknown-float")
    base = "ILP32" if elf_class == ELF_CLASS_32 else "LP64"
    suffix = {0x0: "", 0x2: "F", 0x4: "D", 0x6: "Q"}.get(float_abi, "")
    return f"{base}{suffix} ({float_name})"


def parse_elf(path: str | Path) -> ELFDocument:
    file_path = Path(path).expanduser().resolve()
    data = _read_file(file_path)
    reader = _ELFReader(data, file_path)
    header = reader.parse_header()
    if header.machine != ELF_MACHINE_RISCV:
        raise UnsupportedFormatError(
            f"ELF machine {header.machine} is not RISC-V ({ELF_MACHINE_RISCV})"
        )
    raw_sections = reader.parse_raw_sections(header)
    sections = reader.parse_sections(header, raw_sections)
    segments = reader.parse_program_headers(header)
    symbols = reader.parse_symbols(header, raw_sections, sections)
    build_id = reader.extract_build_id(raw_sections, sections)
    identity = FirmwareIdentity(
        file_name=file_path.name,
        file_size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        elf_class=32 if header.elf_class == ELF_CLASS_32 else 64,
        byte_order=header.byte_order,
        machine=header.machine,
        architecture="RV32" if header.elf_class == ELF_CLASS_32 else "RV64",
        entry_point=header.entry,
        flags=header.flags,
        abi=_riscv_abi(header.flags, header.elf_class),
        build_id=build_id,
        comment=_extract_comment(reader, sections),
    )
    return ELFDocument(
        path=file_path,
        data=data,
        header=header,
        identity=identity,
        segments=segments,
        sections=sections,
        symbols=symbols,
        raw_sections=raw_sections,
    )

