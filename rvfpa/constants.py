from __future__ import annotations

SOFTWARE_NAME = "RISC-V嵌入式固件资源画像与版本差异分析软件"
SOFTWARE_SHORT_NAME = "RVFPA"
SOFTWARE_VERSION = "V1.0"
DATABASE_VERSION = 1

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_PAGE_SIZE = 50
MAX_UPLOAD_BYTES = 128 * 1024 * 1024
MAX_DISASSEMBLY_LINES = 200_000
MAX_RECENT_PROJECTS = 20

ELF_MAGIC = b"\x7fELF"
ELF_CLASS_32 = 1
ELF_CLASS_64 = 2
ELF_DATA_LITTLE = 1
ELF_DATA_BIG = 2
ELF_MACHINE_RISCV = 243

SECTION_TYPE_NAMES = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    10: "SHLIB",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    16: "PREINIT_ARRAY",
    17: "GROUP",
    18: "SYMTAB_SHNDX",
}

PROGRAM_TYPE_NAMES = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    5: "SHLIB",
    6: "PHDR",
    7: "TLS",
}

SYMBOL_TYPE_NAMES = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
}

SYMBOL_BIND_NAMES = {
    0: "LOCAL",
    1: "GLOBAL",
    2: "WEAK",
    10: "GNU_UNIQUE",
}

ALLOC_SECTION_NAMES = {
    ".text",
    ".rodata",
    ".data",
    ".bss",
    ".sdata",
    ".sbss",
    ".tdata",
    ".tbss",
    ".init",
    ".fini",
    ".vectors",
}

DEFAULT_MEMORY_CONFIG = {
    "architecture": "auto",
    "regions": [
        {
            "name": "FLASH",
            "origin": "0x20000000",
            "length": "512K",
            "permissions": "rx",
            "description": "Code and read-only data",
        },
        {
            "name": "RAM",
            "origin": "0x80000000",
            "length": "256K",
            "permissions": "rwx",
            "description": "Runtime data and stack",
        },
    ],
}
