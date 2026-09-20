"""RISC-V机器码字段和立即数解码工具。

这里保存整数、浮点寄存器名称，以及32位指令常用立即数的位域规则。
``raw_decode`` 负责判断操作码含义，本模块只回答字段怎么取，二者可以分别测试。
"""

from __future__ import annotations


REGISTERS = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
]
FLOAT_REGISTERS = [f"f{index}" for index in range(32)]


def bits(value: int, start: int, length: int) -> int:

    return (value >> start) & ((1 << length) - 1)


def sign_extend(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    return (value ^ sign) - sign


def register(index: int) -> str:
    return REGISTERS[index & 31]


def float_register(index: int) -> str:
    return FLOAT_REGISTERS[index & 31]


def i_immediate(word: int) -> int:

    return sign_extend(bits(word, 20, 12), 12)


def s_immediate(word: int) -> int:

    value = bits(word, 7, 5) | (bits(word, 25, 7) << 5)
    return sign_extend(value, 12)


def b_immediate(word: int) -> int:

    value = (
        (bits(word, 8, 4) << 1)
        | (bits(word, 25, 6) << 5)
        | (bits(word, 7, 1) << 11)
        | (bits(word, 31, 1) << 12)
    )
    return sign_extend(value, 13)


def u_immediate(word: int) -> int:

    return word & 0xFFFFF000


def j_immediate(word: int) -> int:

    value = (
        (bits(word, 21, 10) << 1)
        | (bits(word, 20, 1) << 11)
        | (bits(word, 12, 8) << 12)
        | (bits(word, 31, 1) << 20)
    )
    return sign_extend(value, 21)
