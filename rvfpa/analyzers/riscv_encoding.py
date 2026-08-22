"""RISC-V机器码字段与立即数基础工具。

该模块集中保存整数、浮点寄存器名称，以及32位指令常用立即数的位域提取规则。
具体操作码分派仍由 ``raw_decode`` 完成，从而把“怎么取字段”和“字段代表什么指令”
分成两个可独立测试的层次。
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
    """从整数中提取从 ``start`` 开始的 ``length`` 个比特。"""

    return (value >> start) & ((1 << length) - 1)


def sign_extend(value: int, width: int) -> int:
    """把 ``width`` 位二进制补码扩展为Python有符号整数。"""

    sign = 1 << (width - 1)
    return (value ^ sign) - sign


def register(index: int) -> str:
    """把整数寄存器编号转换为RISC-V ABI名称。"""

    return REGISTERS[index & 31]


def float_register(index: int) -> str:
    """把浮点寄存器编号转换为 ``f0`` 至 ``f31`` 名称。"""

    return FLOAT_REGISTERS[index & 31]


def i_immediate(word: int) -> int:
    """解码I型指令的12位有符号立即数。"""

    return sign_extend(bits(word, 20, 12), 12)


def s_immediate(word: int) -> int:
    """拼接并解码S型指令的12位有符号立即数。"""

    value = bits(word, 7, 5) | (bits(word, 25, 7) << 5)
    return sign_extend(value, 12)


def b_immediate(word: int) -> int:
    """拼接并解码B型分支指令的相对偏移。"""

    value = (
        (bits(word, 8, 4) << 1)
        | (bits(word, 25, 6) << 5)
        | (bits(word, 7, 1) << 11)
        | (bits(word, 31, 1) << 12)
    )
    return sign_extend(value, 13)


def u_immediate(word: int) -> int:
    """提取U型指令已经位于高20位的立即数。"""

    return word & 0xFFFFF000


def j_immediate(word: int) -> int:
    """拼接并解码J型跳转指令的相对偏移。"""

    value = (
        (bits(word, 21, 10) << 1)
        | (bits(word, 20, 1) << 11)
        | (bits(word, 12, 8) << 12)
        | (bits(word, 31, 1) << 20)
    )
    return sign_extend(value, 21)
