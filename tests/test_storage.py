from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rvfpa.errors import ProjectNotFoundError, SnapshotNotFoundError
from rvfpa.services.analysis import FirmwareAnalysisService
from rvfpa.services.storage import WorkspaceStore

from .common import example_elf, example_map


class WorkspaceStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = WorkspaceStore(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_project_lifecycle(self) -> None:
        project = self.store.create_project("Test firmware", "Storage test")
        self.assertGreater(project.id, 0)
        self.assertEqual(project.snapshot_count, 0)
        updated = self.store.update_project(project.id, name="Updated firmware")
        self.assertEqual(updated.name, "Updated firmware")
        self.assertEqual(len(self.store.list_projects()), 1)

    def test_snapshot_persists_files_and_analysis(self) -> None:
        project = self.store.create_project("Demo")
        analysis = FirmwareAnalysisService().analyze(
            example_elf("v1"), map_path=example_map("v1")
        )
        snapshot = self.store.add_snapshot(
            project.id,
            version_name="V1",
            elf_source=example_elf("v1"),
            map_source=example_map("v1"),
            analysis=analysis,
            notes="test",
        )
        self.assertTrue(Path(snapshot.elf_path).is_file())
        self.assertTrue(Path(snapshot.map_path).is_file())
        payload = self.store.get_analysis_dict(snapshot.id)
        self.assertEqual(payload["identity"]["sha256"], analysis.identity.sha256)
        self.assertEqual(self.store.get_project(project.id).snapshot_count, 1)

    def test_missing_records_raise_domain_errors(self) -> None:
        with self.assertRaises(ProjectNotFoundError):
            self.store.get_project(999)
        with self.assertRaises(SnapshotNotFoundError):
            self.store.get_snapshot(999)


if __name__ == "__main__":
    unittest.main()

