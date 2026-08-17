from __future__ import annotations

import unittest

from rvfpa.services.analysis import FirmwareAnalysisService

from .common import example_elf, example_map


class FirmwareAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.analysis = FirmwareAnalysisService().analyze(
            example_elf("v1"), map_path=example_map("v1"), prefer_map_regions=True
        )

    def test_size_summary_is_consistent(self) -> None:
        summary = self.analysis.size_summary
        self.assertGreater(summary.code_bytes, 0)
        self.assertGreater(summary.zero_fill_bytes, 0)
        self.assertGreaterEqual(summary.runtime_bytes, summary.code_bytes)

    def test_instruction_profile_is_populated(self) -> None:
        profile = self.analysis.instruction_profile
        self.assertGreater(profile.total, 100)
        self.assertIn("I", profile.extensions)
        self.assertGreater(len(profile.records), 0)

    def test_map_regions_are_used(self) -> None:
        self.assertEqual(self.analysis.metadata["region_source"], "map")
        names = {item.region.name for item in self.analysis.region_usage}
        self.assertEqual(names, {"FLASH", "RAM"})

    def test_no_error_diagnostics_for_example(self) -> None:
        errors = [item for item in self.analysis.diagnostics if item.severity == "error"]
        self.assertEqual(errors, [])

    def test_top_symbols_returns_largest_first(self) -> None:
        symbols = self.analysis.top_symbols(limit=5)
        self.assertEqual(len(symbols), 5)
        self.assertGreaterEqual(symbols[0].size, symbols[-1].size)


if __name__ == "__main__":
    unittest.main()

