from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from ..models import InstructionProfile


CSR_NAMES: dict[int, str] = {
    0x001: "fflags",
    0x002: "frm",
    0x003: "fcsr",
    0x100: "sstatus",
    0x104: "sie",
    0x105: "stvec",
    0x106: "scounteren",
    0x140: "sscratch",
    0x141: "sepc",
    0x142: "scause",
    0x143: "stval",
    0x144: "sip",
    0x180: "satp",
    0x300: "mstatus",
    0x301: "misa",
    0x302: "medeleg",
    0x303: "mideleg",
    0x304: "mie",
    0x305: "mtvec",
    0x306: "mcounteren",
    0x310: "mstatush",
    0x320: "mcountinhibit",
    0x340: "mscratch",
    0x341: "mepc",
    0x342: "mcause",
    0x343: "mtval",
    0x344: "mip",
    0x34A: "mtinst",
    0x34B: "mtval2",
    0x3A0: "pmpcfg0",
    0x3A1: "pmpcfg1",
    0x3A2: "pmpcfg2",
    0x3A3: "pmpcfg3",
    0x7A0: "tselect",
    0x7A1: "tdata1",
    0x7A2: "tdata2",
    0x7A3: "tdata3",
    0x7B0: "dcsr",
    0x7B1: "dpc",
    0x7B2: "dscratch0",
    0x7B3: "dscratch1",
    0xB00: "mcycle",
    0xB02: "minstret",
    0xC00: "cycle",
    0xC01: "time",
    0xC02: "instret",
}

CSR_NAMES.update({0x3B0 + index: f"pmpaddr{index}" for index in range(64)})
CSR_NAMES.update({0xB03 + index: f"mhpmcounter{index + 3}" for index in range(29)})
CSR_NAMES.update({0xC03 + index: f"hpmcounter{index + 3}" for index in range(29)})

NAME_TO_CSR = {name: address for address, name in CSR_NAMES.items()}
_CSR_MNEMONICS = {
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
_TRAP_MNEMONICS = {"ecall", "ebreak", "mret", "sret", "uret", "wfi"}
_FENCE_MNEMONICS = {"fence", "fence.i", "sfence.vma", "hfence.gvma", "hfence.vvma"}
_OPERAND_TOKEN = re.compile(r"(?:^|,)\s*([^,\s]+)")


def csr_privilege(address: int) -> str:
    level = (address >> 8) & 0b11
    return {0: "user", 1: "supervisor", 2: "hypervisor", 3: "machine"}[level]


def csr_access(address: int) -> str:
    return "read-only" if ((address >> 10) & 0b11) == 0b11 else "read-write"


def parse_csr_token(token: str) -> tuple[int | None, str]:
    value = token.strip().lower()
    if value in NAME_TO_CSR:
        address = NAME_TO_CSR[value]
        return address, value
    try:
        address = int(value, 0)
    except ValueError:
        return None, value
    if not 0 <= address <= 0xFFF:
        return None, value
    return address, CSR_NAMES.get(address, f"csr_0x{address:03x}")


def _csr_operand(mnemonic: str, operands: str) -> str:
    tokens = [match.group(1) for match in _OPERAND_TOKEN.finditer(operands)]
    if not tokens:
        return ""
    if mnemonic in {"csrw", "csrs", "csrc", "csrwi", "csrsi", "csrci"}:
        return tokens[0]
    if len(tokens) >= 2:
        return tokens[1]
    return tokens[0]


def analyze_system_usage(profile: InstructionProfile) -> dict[str, Any]:
    csr_counts: Counter[str] = Counter()
    privilege_counts: Counter[str] = Counter()
    access_counts: Counter[str] = Counter()
    operation_counts: Counter[str] = Counter()
    trap_counts: Counter[str] = Counter()
    fence_counts: Counter[str] = Counter()
    atomic_counts: Counter[str] = Counter()
    function_csr: dict[str, Counter[str]] = defaultdict(Counter)
    records: list[dict[str, Any]] = []

    for instruction in profile.records:
        mnemonic = instruction.mnemonic.lower()
        function_name = instruction.function_name or "<unknown>"
        if mnemonic in _CSR_MNEMONICS:
            token = _csr_operand(mnemonic, instruction.operands)
            address, name = parse_csr_token(token)
            operation_counts[mnemonic] += 1
            csr_counts[name] += 1
            function_csr[function_name][name] += 1
            privilege = csr_privilege(address) if address is not None else "unknown"
            access = csr_access(address) if address is not None else "unknown"
            privilege_counts[privilege] += 1
            access_counts[access] += 1
            records.append(
                {
                    "address": instruction.address,
                    "function": function_name,
                    "mnemonic": mnemonic,
                    "csr_token": token,
                    "csr_address": address,
                    "csr_name": name,
                    "privilege": privilege,
                    "access": access,
                }
            )
        elif mnemonic in _TRAP_MNEMONICS:
            trap_counts[mnemonic] += 1
        elif mnemonic in _FENCE_MNEMONICS:
            fence_counts[mnemonic] += 1
        elif mnemonic.startswith(("amo", "lr.", "sc.")):
            atomic_counts[mnemonic] += 1

    top_functions = sorted(
        (
            {
                "function": function,
                "total": sum(counts.values()),
                "csrs": dict(counts.most_common()),
            }
            for function, counts in function_csr.items()
        ),
        key=lambda item: (item["total"], item["function"]),
        reverse=True,
    )
    machine_level = privilege_counts.get("machine", 0)
    supervisor_level = privilege_counts.get("supervisor", 0)
    return {
        "csr_instruction_count": sum(csr_counts.values()),
        "distinct_csr_count": len(csr_counts),
        "csr_counts": dict(csr_counts.most_common()),
        "operation_counts": dict(operation_counts.most_common()),
        "privilege_counts": dict(privilege_counts.most_common()),
        "access_counts": dict(access_counts.most_common()),
        "trap_counts": dict(trap_counts.most_common()),
        "fence_counts": dict(fence_counts.most_common()),
        "atomic_counts": dict(atomic_counts.most_common()),
        "uses_machine_privilege": machine_level > 0,
        "uses_supervisor_privilege": supervisor_level > 0,
        "top_functions": top_functions[:20],
        "records": records,
    }
