from __future__ import annotations

import unittest

from rvfpa.parsers.linker_script import parse_linker_script, parse_linker_script_text, remove_comments

from .common import EXAMPLES


class LinkerScriptParserTests(unittest.TestCase):
    def test_example_regions_and_entry(self) -> None:
        document = parse_linker_script(EXAMPLES / "linker.ld")
        self.assertEqual(document.entry_symbol, "_start")
        self.assertEqual(document.output_architecture, "riscv")
        regions = {item.name: item for item in document.regions}
        self.assertEqual(regions["FLASH"].origin, 0x20000000)
        self.assertEqual(regions["FLASH"].length, 512 * 1024)
        self.assertEqual(regions["FLASH"].permissions, "rx")
        self.assertEqual(regions["RAM"].origin, 0x80000000)

    def test_comments_are_removed(self) -> None:
        text = "A /* hidden\nblock */ B // hidden line\nC"
        self.assertEqual(remove_comments(text), "A  B \nC")

    def test_region_alias_and_provided_symbol(self) -> None:
        document = parse_linker_script_text(
            """
            OUTPUT_ARCH(riscv)
            ENTRY(reset_handler)
            MEMORY { ROM (rx) : ORIGIN = 0x1000, LENGTH = 128K }
            REGION_ALIAS("TEXT", ROM)
            PROVIDE(__stack_size = 8K);
            """
        )
        self.assertEqual(document.aliases["TEXT"], "ROM")
        self.assertEqual(document.provided_symbols["__stack_size"], "8K")
        self.assertEqual(document.regions[0].length, 128 * 1024)

    def test_arithmetic_lengths(self) -> None:
        document = parse_linker_script_text(
            "MEMORY { ROM (rx) : ORIGIN = (0x1000 + 0x100), LENGTH = (64K * 2) }"
        )
        self.assertEqual(document.regions[0].origin, 0x1100)
        self.assertEqual(document.regions[0].length, 128 * 1024)

    def test_missing_memory_block_produces_warning(self) -> None:
        document = parse_linker_script_text("SECTIONS { .text : { *(.text) } }")
        self.assertEqual(document.regions, [])
        self.assertTrue(document.warnings)


if __name__ == "__main__":
    unittest.main()

