from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..models import InstructionRecord
from ..parsers.elf import ELFDocument

REGISTERS = [
    "zero",
    "ra",
    "sp",
    "gp",
    "tp",
    "t0",
    "t1",
    "t2",
    "s0",
    "s1",
    "a0",
    "a1",
    "a2",
    "a3",
    "a4",
    "a5",
    "a6",
    "a7",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "s8",
    "s9",
    "s10",
    "s11",
    "t3",
    "t4",
    "t5",
    "t6",
]

FLOAT_REGISTERS = [f"f{index}" for index in range(32)]


@dataclass(slots=True)
class DecodedOperation:
    mnemonic: str
    operands: str
    recognized: bool = True


def bits(value: int, start: int, length: int) -> int:
    return (value >> start) & ((1 << length) - 1)


def sign_extend(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    return (value ^ sign) - sign


def register(index: int) -> str:
    return REGISTERS[index & 31]


def float_register(index: int) -> str:
    return FLOAT_REGISTERS[index & 31]


def _i_immediate(word: int) -> int:
    return sign_extend(bits(word, 20, 12), 12)


def _s_immediate(word: int) -> int:
    value = bits(word, 7, 5) | (bits(word, 25, 7) << 5)
    return sign_extend(value, 12)


def _b_immediate(word: int) -> int:
    value = (
        (bits(word, 8, 4) << 1)
        | (bits(word, 25, 6) << 5)
        | (bits(word, 7, 1) << 11)
        | (bits(word, 31, 1) << 12)
    )
    return sign_extend(value, 13)


def _u_immediate(word: int) -> int:
    return word & 0xFFFFF000


def _j_immediate(word: int) -> int:
    value = (
        (bits(word, 21, 10) << 1)
        | (bits(word, 20, 1) << 11)
        | (bits(word, 12, 8) << 12)
        | (bits(word, 31, 1) << 20)
    )
    return sign_extend(value, 21)


def _address(address: int) -> str:
    return f"0x{address:x}"


def _decode_load(word: int) -> DecodedOperation:
    rd = register(bits(word, 7, 5))
    rs1 = register(bits(word, 15, 5))
    immediate = _i_immediate(word)
    mnemonic = {
        0: "lb",
        1: "lh",
        2: "lw",
        3: "ld",
        4: "lbu",
        5: "lhu",
        6: "lwu",
    }.get(bits(word, 12, 3), ".word")
    return DecodedOperation(mnemonic, f"{rd},{immediate}({rs1})", mnemonic != ".word")


def _decode_store(word: int) -> DecodedOperation:
    rs1 = register(bits(word, 15, 5))
    rs2 = register(bits(word, 20, 5))
    immediate = _s_immediate(word)
    mnemonic = {0: "sb", 1: "sh", 2: "sw", 3: "sd"}.get(bits(word, 12, 3), ".word")
    return DecodedOperation(mnemonic, f"{rs2},{immediate}({rs1})", mnemonic != ".word")


def _decode_branch(word: int, address: int) -> DecodedOperation:
    rs1 = register(bits(word, 15, 5))
    rs2 = register(bits(word, 20, 5))
    target = address + _b_immediate(word)
    mnemonic = {
        0: "beq",
        1: "bne",
        4: "blt",
        5: "bge",
        6: "bltu",
        7: "bgeu",
    }.get(bits(word, 12, 3), ".word")
    return DecodedOperation(mnemonic, f"{rs1},{rs2},{_address(target)}", mnemonic != ".word")


def _decode_op_imm(word: int, rv64: bool) -> DecodedOperation:
    rd = register(bits(word, 7, 5))
    rs1 = register(bits(word, 15, 5))
    funct3 = bits(word, 12, 3)
    immediate = _i_immediate(word)
    if funct3 == 0:
        return DecodedOperation("addi", f"{rd},{rs1},{immediate}")
    if funct3 == 2:
        return DecodedOperation("slti", f"{rd},{rs1},{immediate}")
    if funct3 == 3:
        return DecodedOperation("sltiu", f"{rd},{rs1},{immediate}")
    if funct3 == 4:
        return DecodedOperation("xori", f"{rd},{rs1},{immediate}")
    if funct3 == 6:
        return DecodedOperation("ori", f"{rd},{rs1},{immediate}")
    if funct3 == 7:
        return DecodedOperation("andi", f"{rd},{rs1},{immediate}")
    shift_width = 6 if rv64 else 5
    shift = bits(word, 20, shift_width)
    if funct3 == 1 and bits(word, 26 if rv64 else 25, 6 if rv64 else 7) == 0:
        return DecodedOperation("slli", f"{rd},{rs1},{shift}")
    if funct3 == 5:
        control = bits(word, 26 if rv64 else 25, 6 if rv64 else 7)
        if control == 0:
            return DecodedOperation("srli", f"{rd},{rs1},{shift}")
        if control == 0x10 if rv64 else control == 0x20:
            return DecodedOperation("srai", f"{rd},{rs1},{shift}")
    return DecodedOperation(".word", f"0x{word:08x}", False)


def _decode_op_imm_32(word: int) -> DecodedOperation:
    rd = register(bits(word, 7, 5))
    rs1 = register(bits(word, 15, 5))
    funct3 = bits(word, 12, 3)
    shift = bits(word, 20, 5)
    if funct3 == 0:
        return DecodedOperation("addiw", f"{rd},{rs1},{_i_immediate(word)}")
    if funct3 == 1 and bits(word, 25, 7) == 0:
        return DecodedOperation("slliw", f"{rd},{rs1},{shift}")
    if funct3 == 5:
        funct7 = bits(word, 25, 7)
        if funct7 == 0:
            return DecodedOperation("srliw", f"{rd},{rs1},{shift}")
        if funct7 == 0x20:
            return DecodedOperation("sraiw", f"{rd},{rs1},{shift}")
    return DecodedOperation(".word", f"0x{word:08x}", False)


def _decode_register_op(word: int, word_operation: bool = False) -> DecodedOperation:
    rd = register(bits(word, 7, 5))
    rs1 = register(bits(word, 15, 5))
    rs2 = register(bits(word, 20, 5))
    funct3 = bits(word, 12, 3)
    funct7 = bits(word, 25, 7)
    suffix = "w" if word_operation else ""
    base = {
        (0x00, 0): "add",
        (0x20, 0): "sub",
        (0x00, 1): "sll",
        (0x00, 2): "slt",
        (0x00, 3): "sltu",
        (0x00, 4): "xor",
        (0x00, 5): "srl",
        (0x20, 5): "sra",
        (0x00, 6): "or",
        (0x00, 7): "and",
    }
    multiply = {
        0: "mul",
        1: "mulh",
        2: "mulhsu",
        3: "mulhu",
        4: "div",
        5: "divu",
        6: "rem",
        7: "remu",
    }
    if funct7 == 0x01:
        mnemonic = multiply.get(funct3, ".word")
    else:
        mnemonic = base.get((funct7, funct3), ".word")
    if word_operation and mnemonic != ".word":
        allowed = {"add", "sub", "sll", "srl", "sra", "mul", "div", "divu", "rem", "remu"}
        mnemonic = mnemonic + suffix if mnemonic in allowed else ".word"
    return DecodedOperation(mnemonic, f"{rd},{rs1},{rs2}", mnemonic != ".word")


def _decode_system(word: int) -> DecodedOperation:
    rd = register(bits(word, 7, 5))
    rs1_value = bits(word, 15, 5)
    rs1 = register(rs1_value)
    csr = bits(word, 20, 12)
    funct3 = bits(word, 12, 3)
    if funct3 == 0:
        immediate = bits(word, 20, 12)
        mnemonic = {0: "ecall", 1: "ebreak", 0x102: "sret", 0x302: "mret", 0x105: "wfi"}.get(immediate, ".word")
        return DecodedOperation(mnemonic, "", mnemonic != ".word")
    mnemonic = {
        1: "csrrw",
        2: "csrrs",
        3: "csrrc",
        5: "csrrwi",
        6: "csrrsi",
        7: "csrrci",
    }.get(funct3, ".word")
    source = str(rs1_value) if funct3 >= 5 else rs1
    return DecodedOperation(mnemonic, f"{rd},0x{csr:x},{source}", mnemonic != ".word")


def _decode_atomic(word: int) -> DecodedOperation:
    rd = register(bits(word, 7, 5))
    rs1 = register(bits(word, 15, 5))
    rs2 = register(bits(word, 20, 5))
    width = {2: "w", 3: "d"}.get(bits(word, 12, 3), "?")
    operation = {
        0x00: "amoadd",
        0x01: "amoswap",
        0x02: "lr",
        0x03: "sc",
        0x04: "amoxor",
        0x08: "amoor",
        0x0C: "amoand",
        0x10: "amomin",
        0x14: "amomax",
        0x18: "amominu",
        0x1C: "amomaxu",
    }.get(bits(word, 27, 5), ".word")
    if operation == ".word" or width == "?":
        return DecodedOperation(".word", f"0x{word:08x}", False)
    ordering = ""
    if bits(word, 26, 1):
        ordering += ".aq"
    if bits(word, 25, 1):
        ordering += ".rl"
    if operation == "lr":
        operands = f"{rd},({rs1})"
    else:
        operands = f"{rd},{rs2},({rs1})"
    return DecodedOperation(f"{operation}.{width}{ordering}", operands)


def _decode_float_load_store(word: int, load: bool) -> DecodedOperation:
    funct3 = bits(word, 12, 3)
    suffix = {1: "h", 2: "w", 3: "d", 4: "q"}.get(funct3)
    if not suffix:
        return DecodedOperation(".word", f"0x{word:08x}", False)
    rs1 = register(bits(word, 15, 5))
    if load:
        target = float_register(bits(word, 7, 5))
        immediate = _i_immediate(word)
        return DecodedOperation(f"fl{suffix}", f"{target},{immediate}({rs1})")
    source = float_register(bits(word, 20, 5))
    immediate = _s_immediate(word)
    return DecodedOperation(f"fs{suffix}", f"{source},{immediate}({rs1})")


def decode_32(word: int, address: int, *, rv64: bool = True) -> DecodedOperation:
    opcode = bits(word, 0, 7)
    rd = register(bits(word, 7, 5))
    rs1 = register(bits(word, 15, 5))
    decoders: dict[int, Callable[[], DecodedOperation]] = {
        0x03: lambda: _decode_load(word),
        0x07: lambda: _decode_float_load_store(word, True),
        0x13: lambda: _decode_op_imm(word, rv64),
        0x1B: lambda: _decode_op_imm_32(word),
        0x23: lambda: _decode_store(word),
        0x27: lambda: _decode_float_load_store(word, False),
        0x2F: lambda: _decode_atomic(word),
        0x33: lambda: _decode_register_op(word),
        0x3B: lambda: _decode_register_op(word, True),
        0x63: lambda: _decode_branch(word, address),
        0x73: lambda: _decode_system(word),
    }
    if opcode in decoders:
        return decoders[opcode]()
    if opcode == 0x17:
        return DecodedOperation("auipc", f"{rd},0x{_u_immediate(word) >> 12:x}")
    if opcode == 0x37:
        return DecodedOperation("lui", f"{rd},0x{_u_immediate(word) >> 12:x}")
    if opcode == 0x6F:
        return DecodedOperation("jal", f"{rd},{_address(address + _j_immediate(word))}")
    if opcode == 0x67 and bits(word, 12, 3) == 0:
        return DecodedOperation("jalr", f"{rd},{_i_immediate(word)}({rs1})")
    if opcode == 0x0F:
        mnemonic = "fence.i" if bits(word, 12, 3) == 1 else "fence"
        return DecodedOperation(mnemonic, "")
    if opcode == 0x57:
        return DecodedOperation("vector", f"0x{word:08x}")
    if opcode == 0x53:
        return DecodedOperation("floating", f"0x{word:08x}")
    return DecodedOperation(".word", f"0x{word:08x}", False)


def _compressed_register(value: int) -> str:
    return register(8 + (value & 7))


def _c_jump_immediate(halfword: int) -> int:
    value = (
        (bits(halfword, 3, 3) << 1)
        | (bits(halfword, 11, 1) << 4)
        | (bits(halfword, 2, 1) << 5)
        | (bits(halfword, 7, 1) << 6)
        | (bits(halfword, 6, 1) << 7)
        | (bits(halfword, 9, 2) << 8)
        | (bits(halfword, 8, 1) << 10)
        | (bits(halfword, 12, 1) << 11)
    )
    return sign_extend(value, 12)


def _c_branch_immediate(halfword: int) -> int:
    value = (
        (bits(halfword, 3, 2) << 1)
        | (bits(halfword, 10, 2) << 3)
        | (bits(halfword, 2, 1) << 5)
        | (bits(halfword, 5, 2) << 6)
        | (bits(halfword, 12, 1) << 8)
    )
    return sign_extend(value, 9)


def decode_16(halfword: int, address: int, *, rv64: bool = True) -> DecodedOperation:
    quadrant = bits(halfword, 0, 2)
    funct3 = bits(halfword, 13, 3)
    rd = register(bits(halfword, 7, 5))
    rs2 = register(bits(halfword, 2, 5))
    immediate6 = sign_extend(bits(halfword, 2, 5) | (bits(halfword, 12, 1) << 5), 6)
    if quadrant == 0:
        rd_prime = _compressed_register(bits(halfword, 2, 3))
        rs1_prime = _compressed_register(bits(halfword, 7, 3))
        if funct3 == 0:
            immediate = (
                (bits(halfword, 6, 1) << 2)
                | (bits(halfword, 5, 1) << 3)
                | (bits(halfword, 11, 2) << 4)
                | (bits(halfword, 7, 4) << 6)
            )
            return DecodedOperation("c.addi4spn", f"{rd_prime},sp,{immediate}", immediate != 0)
        if funct3 in {2, 3}:
            immediate = (bits(halfword, 6, 1) << 2) | (bits(halfword, 10, 3) << 3) | (bits(halfword, 5, 1) << 6)
            mnemonic = "c.lw" if funct3 == 2 else "c.ld"
            return DecodedOperation(mnemonic, f"{rd_prime},{immediate}({rs1_prime})")
        if funct3 in {6, 7}:
            immediate = (bits(halfword, 6, 1) << 2) | (bits(halfword, 10, 3) << 3) | (bits(halfword, 5, 1) << 6)
            mnemonic = "c.sw" if funct3 == 6 else "c.sd"
            return DecodedOperation(mnemonic, f"{_compressed_register(bits(halfword, 2, 3))},{immediate}({rs1_prime})")
    elif quadrant == 1:
        if funct3 == 0:
            return DecodedOperation("c.addi", f"{rd},{immediate6}", rd != "zero" or immediate6 != 0)
        if funct3 == 1:
            if rv64:
                return DecodedOperation("c.addiw", f"{rd},{immediate6}", rd != "zero")
            return DecodedOperation("c.jal", _address(address + _c_jump_immediate(halfword)))
        if funct3 == 2:
            return DecodedOperation("c.li", f"{rd},{immediate6}", rd != "zero")
        if funct3 == 3:
            if rd == "sp":
                immediate = sign_extend(
                    (bits(halfword, 6, 1) << 4)
                    | (bits(halfword, 2, 1) << 5)
                    | (bits(halfword, 5, 1) << 6)
                    | (bits(halfword, 3, 2) << 7)
                    | (bits(halfword, 12, 1) << 9),
                    10,
                )
                return DecodedOperation("c.addi16sp", f"sp,{immediate}", immediate != 0)
            return DecodedOperation("c.lui", f"{rd},{immediate6}", rd not in {"zero", "sp"} and immediate6 != 0)
        if funct3 == 5:
            return DecodedOperation("c.j", _address(address + _c_jump_immediate(halfword)))
        if funct3 in {6, 7}:
            mnemonic = "c.beqz" if funct3 == 6 else "c.bnez"
            rs1_prime = _compressed_register(bits(halfword, 7, 3))
            return DecodedOperation(mnemonic, f"{rs1_prime},{_address(address + _c_branch_immediate(halfword))}")
    elif quadrant == 2:
        if funct3 == 0:
            shift = bits(halfword, 2, 5) | (bits(halfword, 12, 1) << 5)
            return DecodedOperation("c.slli", f"{rd},{shift}", rd != "zero")
        if funct3 == 2:
            immediate = (bits(halfword, 4, 3) << 2) | (bits(halfword, 12, 1) << 5) | (bits(halfword, 2, 2) << 6)
            return DecodedOperation("c.lwsp", f"{rd},{immediate}(sp)", rd != "zero")
        if funct3 == 3:
            immediate = (bits(halfword, 5, 2) << 3) | (bits(halfword, 12, 1) << 5) | (bits(halfword, 2, 3) << 6)
            return DecodedOperation("c.ldsp", f"{rd},{immediate}(sp)", rd != "zero")
        if funct3 == 4:
            bit12 = bits(halfword, 12, 1)
            if bit12 == 0 and rs2 == "zero":
                return DecodedOperation("c.jr", rd, rd != "zero")
            if bit12 == 0:
                return DecodedOperation("c.mv", f"{rd},{rs2}", rd != "zero")
            if rd == "zero" and rs2 == "zero":
                return DecodedOperation("c.ebreak", "")
            if rs2 == "zero":
                return DecodedOperation("c.jalr", rd, rd != "zero")
            return DecodedOperation("c.add", f"{rd},{rs2}", rd != "zero")
        if funct3 == 6:
            immediate = (bits(halfword, 9, 4) << 2) | (bits(halfword, 7, 2) << 6)
            return DecodedOperation("c.swsp", f"{rs2},{immediate}(sp)")
        if funct3 == 7:
            immediate = (bits(halfword, 10, 3) << 3) | (bits(halfword, 7, 3) << 6)
            return DecodedOperation("c.sdsp", f"{rs2},{immediate}(sp)")
    return DecodedOperation(".hword", f"0x{halfword:04x}", False)


def decode_instruction(data: bytes, address: int, *, rv64: bool = True) -> tuple[DecodedOperation, int]:
    if len(data) < 2:
        return DecodedOperation(".byte", data.hex(), False), len(data)
    halfword = int.from_bytes(data[:2], "little")
    if halfword & 0x3 != 0x3:
        return decode_16(halfword, address, rv64=rv64), 2
    if len(data) < 4:
        return DecodedOperation(".hword", f"0x{halfword:04x}", False), 2
    word = int.from_bytes(data[:4], "little")
    return decode_32(word, address, rv64=rv64), 4


def decode_executable_sections(
    document: ELFDocument,
    *,
    maximum_records: int = 200_000,
) -> list[InstructionRecord]:
    records: list[InstructionRecord] = []
    rv64 = document.identity.elf_class == 64
    symbols = sorted(
        (
            item
            for item in document.symbols
            if item.symbol_type == "FUNC" and item.value and item.section_name != "UND"
        ),
        key=lambda item: item.value,
    )
    for section, data in document.executable_sections():
        cursor = 0
        symbol_index = 0
        current_function = ""
        while cursor < len(data) and len(records) < maximum_records:
            address = section.address + cursor
            while symbol_index < len(symbols) and symbols[symbol_index].value <= address:
                symbol = symbols[symbol_index]
                if not symbol.size or address < symbol.value + symbol.size:
                    current_function = symbol.name
                symbol_index += 1
            operation, width = decode_instruction(data[cursor:], address, rv64=rv64)
            if width <= 0:
                break
            raw = data[cursor : cursor + width]
            records.append(
                InstructionRecord(
                    address=address,
                    raw=raw,
                    width=width,
                    mnemonic=operation.mnemonic,
                    operands=operation.operands,
                    category="",
                    extension="",
                    function_name=current_function,
                )
            )
            cursor += width
    return records

