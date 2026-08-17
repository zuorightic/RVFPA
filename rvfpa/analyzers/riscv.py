from __future__ import annotations

from collections import Counter
from dataclasses import replace
from typing import Iterable

from ..models import InstructionProfile, InstructionRecord

CONTROL_FLOW = {
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",
    "j",
    "jr",
    "jal",
    "jalr",
    "ret",
    "call",
    "tail",
}

INTEGER_ARITHMETIC = {
    "add",
    "addi",
    "addw",
    "addiw",
    "sub",
    "subw",
    "neg",
    "negw",
    "slt",
    "slti",
    "sltu",
    "sltiu",
    "seqz",
    "snez",
    "sgtz",
    "sltz",
    "lui",
    "auipc",
}

INTEGER_LOGIC = {
    "and",
    "andi",
    "or",
    "ori",
    "xor",
    "xori",
    "not",
    "sll",
    "slli",
    "sllw",
    "slliw",
    "srl",
    "srli",
    "srlw",
    "srliw",
    "sra",
    "srai",
    "sraw",
    "sraiw",
}

LOADS = {
    "lb",
    "lbu",
    "lh",
    "lhu",
    "lw",
    "lwu",
    "ld",
    "flh",
    "flw",
    "fld",
    "flq",
}

STORES = {
    "sb",
    "sh",
    "sw",
    "sd",
    "fsh",
    "fsw",
    "fsd",
    "fsq",
}

MULTIPLY_DIVIDE = {
    "mul",
    "mulh",
    "mulhsu",
    "mulhu",
    "mulw",
    "div",
    "divu",
    "divw",
    "divuw",
    "rem",
    "remu",
    "remw",
    "remuw",
}

SYSTEM = {
    "ecall",
    "ebreak",
    "mret",
    "sret",
    "uret",
    "wfi",
    "fence",
    "fence.i",
    "sfence.vma",
    "hfence.gvma",
    "hfence.vvma",
    "csrrw",
    "csrrs",
    "csrrc",
    "csrrwi",
    "csrrsi",
    "csrrci",
    "csrr",
    "csrw",
    "csrs",
    "csrc",
    "csrwi",
    "csrsi",
    "csrci",
}

ATOMIC_PREFIXES = ("amo", "lr.", "sc.")
FLOAT_PREFIXES = (
    "fadd.",
    "fsub.",
    "fmul.",
    "fdiv.",
    "fsqrt.",
    "fmadd.",
    "fmsub.",
    "fnmadd.",
    "fnmsub.",
    "fmin.",
    "fmax.",
    "fsgnj.",
    "fsgnjn.",
    "fsgnjx.",
    "feq.",
    "flt.",
    "fle.",
    "fclass.",
    "fcvt.",
    "fmv.",
)
VECTOR_PREFIXES = (
    "vset",
    "vle",
    "vlse",
    "vluxei",
    "vloxei",
    "vse",
    "vsse",
    "vsuxei",
    "vsoxei",
    "vadd",
    "vsub",
    "vrsub",
    "vmul",
    "vdiv",
    "vrem",
    "vwmul",
    "vmacc",
    "vnmsac",
    "vmadd",
    "vnmsub",
    "vfm",
    "vfadd",
    "vfsub",
    "vfrsub",
    "vfmul",
    "vfdiv",
    "vfrdiv",
    "vfw",
    "vred",
    "vwred",
    "vand",
    "vor",
    "vxor",
    "vsll",
    "vsrl",
    "vsra",
    "vnsrl",
    "vnsra",
    "vmseq",
    "vmsne",
    "vmslt",
    "vmsle",
    "vmsgt",
    "vmin",
    "vmax",
    "vmerge",
    "vmv",
    "vslide",
    "vrgather",
    "vcompress",
    "viota",
    "vid",
    "vcpop",
    "vfirst",
)

BITMANIP_EXACT = {
    "andn",
    "orn",
    "xnor",
    "clz",
    "clzw",
    "ctz",
    "ctzw",
    "cpop",
    "cpopw",
    "max",
    "maxu",
    "min",
    "minu",
    "sext.b",
    "sext.h",
    "zext.h",
    "rol",
    "rolw",
    "ror",
    "rori",
    "rorw",
    "roriw",
    "orc.b",
    "rev8",
    "bclr",
    "bclri",
    "bext",
    "bexti",
    "binv",
    "binvi",
    "bset",
    "bseti",
    "sh1add",
    "sh2add",
    "sh3add",
}

CRYPTO_PREFIXES = (
    "aes",
    "sha",
    "sm3",
    "sm4",
    "xperm",
    "clmul",
    "brev8",
    "zip",
    "unzip",
    "pack",
)


def normalize_mnemonic(mnemonic: str) -> tuple[str, bool]:
    value = mnemonic.strip().lower()
    compressed = value.startswith("c.")
    if compressed:
        value = value[2:]
    return value, compressed


def classify_instruction(mnemonic: str, width: int) -> tuple[str, str]:
    name, compressed_alias = normalize_mnemonic(mnemonic)
    is_compressed = compressed_alias or width == 2
    if name in CONTROL_FLOW:
        category = "control-flow"
    elif name in LOADS or name.startswith(("vl", "fl")):
        category = "load"
    elif name in STORES or name.startswith(("vs", "fs")):
        category = "store"
    elif name in MULTIPLY_DIVIDE:
        category = "multiply-divide"
    elif name in INTEGER_ARITHMETIC:
        category = "integer-arithmetic"
    elif name in INTEGER_LOGIC:
        category = "integer-logic"
    elif name in SYSTEM or name.startswith("csr"):
        category = "system"
    elif name.startswith(ATOMIC_PREFIXES):
        category = "atomic"
    elif name.startswith(VECTOR_PREFIXES):
        category = "vector"
    elif name.startswith(FLOAT_PREFIXES):
        category = "floating-point"
    elif name in BITMANIP_EXACT:
        category = "bit-manipulation"
    elif name.startswith(CRYPTO_PREFIXES):
        category = "cryptography"
    elif name in {"nop", "mv", "li", "la", "lla"}:
        category = "pseudo"
    elif name.startswith("."):
        category = "data"
    else:
        category = "other"

    if is_compressed:
        extension = "C"
    elif name in MULTIPLY_DIVIDE:
        extension = "M"
    elif name.startswith(ATOMIC_PREFIXES):
        extension = "A"
    elif name.startswith(VECTOR_PREFIXES):
        extension = "V"
    elif name in BITMANIP_EXACT:
        extension = "B"
    elif name.startswith(CRYPTO_PREFIXES):
        extension = "K"
    elif name.startswith(FLOAT_PREFIXES) or name in LOADS | STORES:
        if name.endswith(".q") or name in {"flq", "fsq"}:
            extension = "Q"
        elif name.endswith(".d") or name in {"fld", "fsd"}:
            extension = "D"
        elif name.endswith(".h") or name in {"flh", "fsh"}:
            extension = "Zfh"
        elif name.startswith("f"):
            extension = "F"
        else:
            extension = "I"
    elif category == "system" and name == "fence.i":
        extension = "Zifencei"
    elif category == "system" and name.startswith("csr"):
        extension = "Zicsr"
    else:
        extension = "I"
    return category, extension


def build_instruction_profile(
    records: Iterable[InstructionRecord], *, record_limit: int = 5000
) -> InstructionProfile:
    categories: Counter[str] = Counter()
    extensions: Counter[str] = Counter()
    mnemonics: Counter[str] = Counter()
    normalized_records: list[InstructionRecord] = []
    compressed = 0
    failures = 0
    total = 0
    for record in records:
        total += 1
        try:
            category, extension = classify_instruction(record.mnemonic, record.width)
        except Exception:
            category, extension = "unknown", "unknown"
            failures += 1
        _, compressed_alias = normalize_mnemonic(record.mnemonic)
        if compressed_alias or record.width == 2:
            compressed += 1
        categories[category] += 1
        extensions[extension] += 1
        mnemonics[record.mnemonic.lower()] += 1
        if len(normalized_records) < record_limit:
            normalized_records.append(
                replace(record, category=category, extension=extension)
            )
    return InstructionProfile(
        total=total,
        compressed=compressed,
        categories=dict(categories.most_common()),
        extensions=dict(extensions.most_common()),
        mnemonics=dict(mnemonics.most_common()),
        records=normalized_records,
        decode_failures=failures,
    )


def architecture_string(base: str, profile: InstructionProfile) -> str:
    ordered = ["I", "M", "A", "F", "D", "Q", "C", "B", "V", "K"]
    present = set(profile.extensions)
    standard = "".join(item for item in ordered if item in present)
    multi = sorted(item for item in present if len(item) > 1 and item != "unknown")
    result = f"{base}{standard or 'I'}"
    if multi:
        result += "_" + "_".join(multi)
    return result

