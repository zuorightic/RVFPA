from __future__ import annotations

import unittest

from rvfpa.analyzers.raw_decode import (
    bits,
    decode_16,
    decode_32,
    decode_executable_sections,
    decode_instruction,
    sign_extend,
)
from rvfpa.parsers.elf import parse_elf

from .common import example_elf


class BitUtilityTests(unittest.TestCase):
    def test_extract_bits(self) -> None:
        self.assertEqual(bits(0b110101, 1, 3), 0b010)
        self.assertEqual(bits(0xFFFFFFFF, 16, 8), 0xFF)

    def test_sign_extension(self) -> None:
        self.assertEqual(sign_extend(0x7FF, 12), 2047)
        self.assertEqual(sign_extend(0x800, 12), -2048)
        self.assertEqual(sign_extend(0xFFF, 12), -1)


class Decode32Tests(unittest.TestCase):
    def test_addi(self) -> None:
        operation = decode_32(0x00150513, 0x1000)
        self.assertEqual(operation.mnemonic, "addi")
        self.assertEqual(operation.operands, "a0,a0,1")

    def test_register_arithmetic(self) -> None:
        operation = decode_32(0x00B50533, 0x1000)
        self.assertEqual(operation.mnemonic, "add")
        self.assertEqual(operation.operands, "a0,a0,a1")
        operation = decode_32(0x40B50533, 0x1000)
        self.assertEqual(operation.mnemonic, "sub")

    def test_load_and_store(self) -> None:
        load = decode_32(0x00052503, 0x1000)
        self.assertEqual(load.mnemonic, "lw")
        self.assertEqual(load.operands, "a0,0(a0)")
        store = decode_32(0x00A52023, 0x1000)
        self.assertEqual(store.mnemonic, "sw")

    def test_branch_target(self) -> None:
        branch = decode_32(0x00B50663, 0x1000)
        self.assertEqual(branch.mnemonic, "beq")
        self.assertIn("0x100c", branch.operands)

    def test_jump_and_upper_immediate(self) -> None:
        jump = decode_32(0x008000EF, 0x1000)
        self.assertEqual(jump.mnemonic, "jal")
        self.assertIn("0x1008", jump.operands)
        upper = decode_32(0x12345537, 0x1000)
        self.assertEqual(upper.mnemonic, "lui")

    def test_multiply_extension(self) -> None:
        multiply = decode_32(0x02B50533, 0x1000)
        self.assertEqual(multiply.mnemonic, "mul")

    def test_system_instructions(self) -> None:
        self.assertEqual(decode_32(0x00000073, 0).mnemonic, "ecall")
        self.assertEqual(decode_32(0x00100073, 0).mnemonic, "ebreak")
        self.assertEqual(decode_32(0x30200073, 0).mnemonic, "mret")

    def test_unknown_opcode_is_preserved(self) -> None:
        operation = decode_32(0xFFFFFFFF, 0)
        self.assertFalse(operation.recognized)
        self.assertEqual(operation.mnemonic, ".word")


class Decode16Tests(unittest.TestCase):
    def test_compressed_addi_and_jump(self) -> None:
        addi = decode_16(0x0505, 0x1000)
        self.assertEqual(addi.mnemonic, "c.addi")
        jump = decode_16(0xA001, 0x1000)
        self.assertEqual(jump.mnemonic, "c.j")

    def test_instruction_width_detection(self) -> None:
        compressed, width = decode_instruction(bytes.fromhex("0100"), 0)
        self.assertEqual(width, 2)
        self.assertTrue(compressed.mnemonic.startswith("c.") or compressed.mnemonic == ".hword")
        standard, width = decode_instruction(bytes.fromhex("13000000"), 0)
        self.assertEqual(width, 4)
        self.assertEqual(standard.mnemonic, "addi")


class ExecutableSectionDecodeTests(unittest.TestCase):
    def test_example_firmware_decodes_without_external_tool(self) -> None:
        document = parse_elf(example_elf("v1"))
        records = decode_executable_sections(document)
        self.assertGreater(len(records), 100)
        self.assertEqual(records[0].address, document.identity.entry_point)
        self.assertTrue(any(item.mnemonic == "jal" for item in records))
        self.assertTrue(any(item.width == 2 for item in records))


if __name__ == "__main__":
    unittest.main()

