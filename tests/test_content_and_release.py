from __future__ import annotations

import unittest
import copy

from rvfpa.analyzers.content import shannon_entropy
from rvfpa.services.analysis import FirmwareAnalysisService

from .common import example_elf, example_map


class EntropyTests(unittest.TestCase):
    def test_empty_and_uniform_data(self) -> None:
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(shannon_entropy(b"\0" * 64), 0.0)

    def test_balanced_byte_distribution(self) -> None:
        data = bytes(range(256)) * 4
        self.assertAlmostEqual(shannon_entropy(data), 8.0, places=4)


class ContentAndReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.analysis = FirmwareAnalysisService().analyze(
            example_elf("v2"), map_path=example_map("v2")
        )

    def test_firmware_strings_include_banner(self) -> None:
        texts = [item.text for item in self.analysis.firmware_strings]
        self.assertTrue(any("demonstration firmware V2" in text for text in texts))

    def test_section_entropy_covers_text_and_rodata(self) -> None:
        by_name = {item.section_name: item for item in self.analysis.section_entropy}
        self.assertIn(".text", by_name)
        self.assertIn(".rodata", by_name)
        self.assertGreater(by_name[".text"].entropy, 0)

    def test_function_profiles_include_main(self) -> None:
        functions = {item.name: item for item in self.analysis.function_profiles}
        self.assertIn("main", functions)
        self.assertGreater(functions["main"].instruction_count, 0)
        self.assertGreaterEqual(functions["main"].estimated_complexity, 1)

    def test_release_checks_have_stable_identifiers(self) -> None:
        identifiers = {item.check_id for item in self.analysis.release_checks}
        self.assertIn("layout-errors", identifiers)
        self.assertIn("memory-headroom", identifiers)
        self.assertIn("instruction-decode", identifiers)
        self.assertIn("sensitive-strings", identifiers)

    def test_example_has_no_failed_release_check(self) -> None:
        failed = [item for item in self.analysis.release_checks if item.status == "fail"]
        self.assertEqual(failed, [])

    def test_writable_executable_program_segment_is_reported(self) -> None:
        analysis = copy.deepcopy(self.analysis)
        segment = next(item for item in analysis.segments if item.memory_size)
        segment.flags = "rwx"
        from rvfpa.analyzers.release import build_release_checks

        checks = {item.check_id: item for item in build_release_checks(analysis)}
        check = checks["writable-executable"]
        self.assertEqual(check.status, "warn")
        self.assertTrue(any("程序段" in item for item in check.evidence))


if __name__ == "__main__":
    unittest.main()
