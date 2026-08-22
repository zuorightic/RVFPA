from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rvfpa.errors import InputValidationError
from rvfpa.services.analysis import FirmwareAnalysisService
from rvfpa.services.storage import WorkspaceStore
from rvfpa.web_uploads import decode_uploaded_file
from rvfpa.webapi import _snapshot_payload

from .common import example_elf, example_map


class WebApiPayloadTests(unittest.TestCase):
    def test_snapshot_list_payload_contains_lightweight_analysis_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = WorkspaceStore(Path(temporary))
            project = store.create_project("Demo")
            analysis = FirmwareAnalysisService().analyze(
                example_elf("v1"), map_path=example_map("v1")
            )
            store.add_snapshot(
                project.id,
                version_name="V1",
                elf_source=example_elf("v1"),
                map_source=example_map("v1"),
                analysis=analysis,
            )

            snapshot = store.list_snapshots(project.id, include_analysis=True)[0]
            payload = _snapshot_payload(snapshot)

            self.assertEqual(payload["analysis"]["identity"]["file_name"], "firmware_v1.elf")
            self.assertEqual(
                payload["analysis"]["size_summary"]["code_bytes"],
                analysis.size_summary.code_bytes,
            )
            self.assertEqual(
                payload["analysis"]["instruction_profile"]["total"],
                analysis.instruction_profile.total,
            )
            self.assertNotIn("sections", payload["analysis"])


class WebUploadTests(unittest.TestCase):
    def test_optional_upload_fields_may_be_absent(self) -> None:
        self.assertIsNone(decode_uploaded_file({}, "map"))

    def test_uploaded_name_is_reduced_to_file_name(self) -> None:
        result = decode_uploaded_file(
            {"elf_name": "../firmware.elf", "elf_base64": "UklTQ1Y="},
            "elf",
        )
        self.assertEqual(result, ("firmware.elf", b"RISCV"))

    def test_invalid_base64_is_rejected(self) -> None:
        with self.assertRaises(InputValidationError):
            decode_uploaded_file(
                {"elf_name": "firmware.elf", "elf_base64": "not@base64"},
                "elf",
            )


if __name__ == "__main__":
    unittest.main()
