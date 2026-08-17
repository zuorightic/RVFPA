from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from rvfpa.services.batch import (
    analyze_directory,
    discover_firmware_candidates,
    find_matching_map,
    infer_version_name,
)

from .common import example_elf, example_map


class VersionInferenceTests(unittest.TestCase):
    def test_common_version_names(self) -> None:
        cases = {
            "firmware_v1.elf": "V1",
            "controller-2.4.1.out": "V2.4.1",
            "release_12_3.axf": "V12.3",
            "plain.elf": "plain",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(infer_version_name(Path(name)), expected)


class BatchDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "nested").mkdir()
        shutil.copy2(example_elf("v1"), self.root / "device_v1.elf")
        shutil.copy2(example_map("v1"), self.root / "device_v1.map")
        shutil.copy2(example_elf("v2"), self.root / "nested" / "device_v2.elf")
        shutil.copy2(example_map("v2"), self.root / "nested" / "device_v2.map")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_recursive_discovery_pairs_maps(self) -> None:
        candidates = discover_firmware_candidates(self.root)
        self.assertEqual(len(candidates), 2)
        self.assertEqual({item.version_name for item in candidates}, {"V1", "V2"})
        self.assertTrue(all(item.map_path for item in candidates))

    def test_non_recursive_discovery(self) -> None:
        candidates = discover_firmware_candidates(self.root, recursive=False)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].version_name, "V1")

    def test_matching_map_uses_sibling_name(self) -> None:
        elf = self.root / "device_v1.elf"
        result = find_matching_map(elf, {})
        self.assertEqual(result, self.root / "device_v1.map")

    def test_batch_analysis_and_consecutive_comparison(self) -> None:
        result = analyze_directory(self.root, workers=2)
        self.assertEqual(result.summary["candidate_count"], 2)
        self.assertEqual(result.summary["success_count"], 2)
        self.assertEqual(result.summary["failure_count"], 0)
        self.assertEqual(result.summary["comparison_count"], 1)
        self.assertEqual(len(result.comparisons), 1)
        self.assertGreater(result.comparisons[0].size_deltas["code_bytes"].absolute, 0)

    def test_empty_directory_returns_empty_result(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        result = analyze_directory(empty)
        self.assertEqual(result.items, [])
        self.assertEqual(result.summary["candidate_count"], 0)


if __name__ == "__main__":
    unittest.main()

