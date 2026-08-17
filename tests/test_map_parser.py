from __future__ import annotations

import unittest

from rvfpa.parsers.mapfile import parse_map_file, parse_map_text

from .common import example_map


class MapParserTests(unittest.TestCase):
    def test_example_memory_configuration(self) -> None:
        document = parse_map_file(example_map("v1"))
        regions = {item.name: item for item in document.memory_regions}
        self.assertIn("FLASH", regions)
        self.assertIn("RAM", regions)
        self.assertEqual(regions["FLASH"].origin, 0x20000000)
        self.assertEqual(regions["RAM"].origin, 0x80000000)

    def test_contributions_capture_object_files(self) -> None:
        document = parse_map_file(example_map("v2"))
        self.assertGreater(len(document.contributions), 0)
        object_sizes = document.by_object()
        self.assertTrue(any("firmware_v2" in name for name in object_sizes))

    def test_wrapped_input_section_format(self) -> None:
        text = """
Memory Configuration

Name             Origin             Length             Attributes
FLASH            0x0000000020000000 0x0000000000080000 xr

Linker script and memory map

.text            0x0000000020000000       0x40
 .text.long_name
                 0x0000000020000010       0x20 sample.o
                 0x0000000020000010                sample_function
"""
        document = parse_map_text(text)
        self.assertEqual(len(document.contributions), 1)
        item = document.contributions[0]
        self.assertEqual(item.section_name, ".text.long_name")
        self.assertEqual(item.symbol_name, "sample_function")
        self.assertEqual(item.size, 0x20)


if __name__ == "__main__":
    unittest.main()

