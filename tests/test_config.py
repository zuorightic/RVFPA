from __future__ import annotations

import unittest

from rvfpa.config import normalize_memory_config, parse_integer, parse_memory_regions
from rvfpa.errors import InputValidationError


class ParseIntegerTests(unittest.TestCase):
    def test_decimal_and_hexadecimal_values(self) -> None:
        self.assertEqual(parse_integer(42), 42)
        self.assertEqual(parse_integer("42"), 42)
        self.assertEqual(parse_integer("0x2a"), 42)
        self.assertEqual(parse_integer("0X2A"), 42)

    def test_binary_size_suffixes(self) -> None:
        self.assertEqual(parse_integer("1K"), 1024)
        self.assertEqual(parse_integer("64KiB"), 64 * 1024)
        self.assertEqual(parse_integer("2MB"), 2 * 1024 * 1024)
        self.assertEqual(parse_integer("1g"), 1024**3)

    def test_invalid_values_are_rejected(self) -> None:
        for value in ("", "12XB", "1.5K", object(), True):
            with self.subTest(value=value):
                with self.assertRaises(InputValidationError):
                    parse_integer(value)


class MemoryRegionTests(unittest.TestCase):
    def test_valid_regions_are_sorted(self) -> None:
        regions = parse_memory_regions(
            {
                "regions": [
                    {"name": "RAM", "origin": "0x80000000", "length": "128K"},
                    {"name": "FLASH", "origin": "0x20000000", "length": "512K", "permissions": "rx"},
                ]
            }
        )
        self.assertEqual([item.name for item in regions], ["FLASH", "RAM"])
        self.assertTrue(regions[0].contains(0x20000000, 32))
        self.assertFalse(regions[0].contains(0x80000000, 32))

    def test_duplicate_names_are_rejected(self) -> None:
        with self.assertRaises(InputValidationError):
            parse_memory_regions(
                {
                    "regions": [
                        {"name": "RAM", "origin": 0, "length": "4K"},
                        {"name": "ram", "origin": "0x2000", "length": "4K"},
                    ]
                }
            )

    def test_overlapping_regions_are_rejected(self) -> None:
        with self.assertRaises(InputValidationError):
            parse_memory_regions(
                {
                    "regions": [
                        {"name": "A", "origin": "0x1000", "length": "8K"},
                        {"name": "B", "origin": "0x2000", "length": "8K"},
                    ]
                }
            )

    def test_normalization_uses_stable_hex_addresses(self) -> None:
        result = normalize_memory_config(
            {
                "architecture": "rv64",
                "regions": [
                    {"name": "FLASH", "origin": 0x20000000, "length": "512K", "permissions": "rx"}
                ],
            }
        )
        self.assertEqual(result["architecture"], "rv64")
        self.assertEqual(result["regions"][0]["origin"], "0x20000000")
        self.assertEqual(result["regions"][0]["length"], 512 * 1024)


if __name__ == "__main__":
    unittest.main()

