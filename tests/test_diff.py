from __future__ import annotations

import unittest

from rvfpa.services.analysis import FirmwareAnalysisService
from rvfpa.services.diff import compare_firmware

from .common import example_elf, example_map


class FirmwareDiffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        service = FirmwareAnalysisService()
        cls.v1 = service.analyze(example_elf("v1"), map_path=example_map("v1"))
        cls.v2 = service.analyze(example_elf("v2"), map_path=example_map("v2"))
        cls.diff = compare_firmware(cls.v1, cls.v2, baseline_id=1, target_id=2)

    def test_identity_change_contains_hash(self) -> None:
        self.assertIn("sha256", self.diff.identity_changes)
        self.assertEqual(self.diff.baseline_id, 1)
        self.assertEqual(self.diff.target_id, 2)

    def test_v2_has_more_code_and_runtime_memory(self) -> None:
        self.assertGreater(self.diff.size_deltas["code_bytes"].absolute, 0)
        self.assertGreater(self.diff.size_deltas["runtime_bytes"].absolute, 0)

    def test_symbol_changes_are_reported(self) -> None:
        changed = [item for item in self.diff.symbol_deltas if item.status != "unchanged"]
        names = {item.name for item in changed}
        self.assertIn("statistics", names)
        self.assertGreater(len(changed), 0)

    def test_summary_contains_growth_rankings(self) -> None:
        self.assertIn("largest_symbol_growth", self.diff.summary)
        self.assertGreater(self.diff.summary["changed_symbol_count"], 0)

    def test_serialized_deltas_include_calculated_values(self) -> None:
        payload = self.diff.to_dict()
        file_delta = payload["size_deltas"]["file_bytes"]
        self.assertEqual(file_delta["absolute"], file_delta["after"] - file_delta["before"])
        self.assertIsNotNone(file_delta["percent"])
        changed_symbol = next(
            item for item in payload["symbol_deltas"] if item["before_size"] != item["after_size"]
        )
        self.assertEqual(
            changed_symbol["delta"],
            changed_symbol["after_size"] - changed_symbol["before_size"],
        )

    def test_extension_changes_exclude_unchanged_extensions(self) -> None:
        self.assertEqual(self.diff.extension_changes["C"], "changed")
        self.assertEqual(self.diff.extension_changes["I"], "changed")
        self.assertNotIn("M", self.diff.extension_changes)


if __name__ == "__main__":
    unittest.main()
