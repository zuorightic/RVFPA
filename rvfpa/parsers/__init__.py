"""Input parsers for firmware artifacts."""

from .elf import ELFDocument, parse_elf
from .mapfile import GNUMapDocument, parse_map_file
from .objdump import ObjdumpDocument, parse_objdump_text

__all__ = [
    "ELFDocument",
    "GNUMapDocument",
    "ObjdumpDocument",
    "parse_elf",
    "parse_map_file",
    "parse_objdump_text",
]

