"""固件输入解析器包，对外提供ELF、MAP和objdump文本解析入口。"""

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
