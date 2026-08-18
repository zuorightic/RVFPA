from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rvfpa.services.analysis import FirmwareAnalysisService
from rvfpa.services.storage import WorkspaceStore
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


if __name__ == "__main__":
    unittest.main()
