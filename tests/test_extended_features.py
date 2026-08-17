from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rvfpa.analyzers.system_usage import (
    analyze_system_usage,
    csr_access,
    csr_privilege,
    parse_csr_token,
)
from rvfpa.models import BatchItemResult, FirmwareCandidate, InstructionProfile, InstructionRecord
from rvfpa.services.manifest import build_firmware_manifest
from rvfpa.services.stack_analysis import analyze_stack_usage, parse_stack_usage_text
from rvfpa.services.trends import build_version_trends
from rvfpa.services.analysis import FirmwareAnalysisService

from .common import example_elf, example_map


class SystemUsageTests(unittest.TestCase):
    def test_csr_metadata(self) -> None:
        self.assertEqual(parse_csr_token("mstatus"), (0x300, "mstatus"))
        self.assertEqual(parse_csr_token("pmpaddr15"), (0x3BF, "pmpaddr15"))
        self.assertEqual(csr_privilege(0x300), "machine")
        self.assertEqual(csr_access(0xC00), "read-only")

    def test_instruction_usage_is_grouped(self) -> None:
        profile = InstructionProfile(
            total=3,
            records=[
                InstructionRecord(0, b"", 4, "csrr", "a0,mstatus", "system", "Zicsr", "boot"),
                InstructionRecord(4, b"", 4, "wfi", "", "system", "I", "idle"),
                InstructionRecord(8, b"", 4, "fence.i", "", "system", "Zifencei", "boot"),
            ],
        )
        result = analyze_system_usage(profile)
        self.assertEqual(result["csr_counts"], {"mstatus": 1})
        self.assertEqual(result["trap_counts"], {"wfi": 1})
        self.assertEqual(result["fence_counts"], {"fence.i": 1})


class TrendAndManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        service = FirmwareAnalysisService()
        cls.v1 = service.analyze(example_elf("v1"), map_path=example_map("v1"))
        cls.v2 = service.analyze(example_elf("v2"), map_path=example_map("v2"))

    def test_two_version_trend_grows(self) -> None:
        items = [
            BatchItemResult(FirmwareCandidate("V1", "v1.elf"), "success", self.v1),
            BatchItemResult(FirmwareCandidate("V2", "v2.elf"), "success", self.v2),
        ]
        trend = build_version_trends(items)
        self.assertEqual(trend["version_count"], 2)
        self.assertEqual(trend["metrics"]["code_bytes"]["direction"], "increasing")

    def test_manifest_fingerprint_is_stable(self) -> None:
        first = build_firmware_manifest(self.v1)
        second = build_firmware_manifest(self.v1)
        self.assertEqual(first["analysis_fingerprint"], second["analysis_fingerprint"])
        self.assertEqual(first["identity"]["sha256"], self.v1.identity.sha256)


class StackUsageTests(unittest.TestCase):
    def test_parser_accepts_static_and_dynamic_records(self) -> None:
        document = parse_stack_usage_text(
            "main.c:10:1:main\t128\tstatic\nmain.c:20:1:worker\t512\tdynamic,bounded\n"
        )
        self.assertEqual(len(document.records), 2)
        self.assertTrue(document.records[0].bounded)
        self.assertEqual(document.records[1].allocation, "dynamic")

    def test_directory_analysis_enforces_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample.su"
            path.write_text("main.c:10:1:main\t128\tstatic\n", encoding="utf-8")
            result = analyze_stack_usage(temporary, maximum_stack_bytes=64)
        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["budget"]["status"], "fail")
        self.assertEqual(result["budget"]["violation_count"], 1)


if __name__ == "__main__":
    unittest.main()
