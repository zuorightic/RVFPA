from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rvfpa.constants import ELF_MACHINE_RISCV
from rvfpa.errors import UnsupportedFormatError
from rvfpa.parsers.elf import parse_elf

from .common import example_elf


class ELFParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = parse_elf(example_elf("v1"))

    def test_identity_is_riscv_64_bit(self) -> None:
        identity = self.document.identity
        self.assertEqual(identity.machine, ELF_MACHINE_RISCV)
        self.assertEqual(identity.elf_class, 64)
        self.assertEqual(identity.byte_order, "little")
        self.assertEqual(identity.entry_point, 0x20000000)
        self.assertEqual(len(identity.sha256), 64)

    def test_expected_sections_exist(self) -> None:
        names = {item.name for item in self.document.sections}
        self.assertIn(".text", names)
        self.assertIn(".rodata", names)
        self.assertIn(".bss", names)
        text = self.document.section_by_name(".text")
        self.assertIsNotNone(text)
        self.assertTrue(text.allocated)
        self.assertTrue(text.executable)
        self.assertGreater(text.size, 0)

    def test_executable_section_bytes_match_size(self) -> None:
        for section, data in self.document.executable_sections():
            with self.subTest(section=section.name):
                self.assertEqual(len(data), section.size)

    def test_symbols_include_entry_and_main(self) -> None:
        symbols = {item.name: item for item in self.document.symbols}
        self.assertIn("_start", symbols)
        self.assertIn("main", symbols)
        self.assertEqual(symbols["_start"].symbol_type, "FUNC")

    def test_non_elf_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plain.bin"
            path.write_bytes(b"not-an-elf")
            with self.assertRaises(UnsupportedFormatError):
                parse_elf(path)


if __name__ == "__main__":
    unittest.main()

