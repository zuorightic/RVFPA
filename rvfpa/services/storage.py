"""本地SQLite项目、固件快照和压缩分析结果持久化。

负责数据库建表、事务、项目配置、原始文件归档和分析JSON压缩，不参与固件
解析和业务判定。
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import threading
import zlib
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ..config import normalize_memory_config
from ..constants import DATABASE_VERSION, DEFAULT_MEMORY_CONFIG
from ..errors import ProjectNotFoundError, SnapshotNotFoundError, StorageError
from ..models import FirmwareAnalysis, ProjectRecord, SnapshotRecord, utc_now_iso


SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    memory_config_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    version_name TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    elf_path TEXT NOT NULL,
    map_path TEXT NOT NULL DEFAULT '',
    analysis_blob BLOB NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_snapshots_project
ON snapshots(project_id, created_at DESC);
"""


class WorkspaceStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()
        self.database_path = self.root / "rvfpa.sqlite3"
        self.artifact_root = self.root / "artifacts"
        self.report_root = self.root / "reports"
        self._lock = threading.RLock()
        self.root.mkdir(parents=True, exist_ok=True)
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.report_root.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._lock, self.connection() as connection:
            connection.executescript(SCHEMA)
            connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)",
                (str(DATABASE_VERSION),),
            )

    @staticmethod
    def _pack_analysis(analysis: FirmwareAnalysis | dict[str, Any]) -> bytes:
        payload = analysis.to_dict() if isinstance(analysis, FirmwareAnalysis) else analysis
        encoded = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        return zlib.compress(encoded, level=6)

    @staticmethod
    def _unpack_analysis(blob: bytes) -> dict[str, Any]:
        try:
            return json.loads(zlib.decompress(blob).decode("utf-8"))
        except (zlib.error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StorageError("Stored analysis data is corrupted") from exc

    def create_project(
        self,
        name: str,
        description: str = "",
        memory_config: dict[str, Any] | None = None,
    ) -> ProjectRecord:
        clean_name = name.strip()
        if not clean_name:
            raise StorageError("Project name cannot be empty")
        normalized = normalize_memory_config(memory_config or DEFAULT_MEMORY_CONFIG)
        now = utc_now_iso()
        with self._lock, self.connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO projects(name, description, memory_config_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    clean_name,
                    description.strip(),
                    json.dumps(normalized, ensure_ascii=False),
                    now,
                    now,
                ),
            )
            project_id = int(cursor.lastrowid)
        (self.artifact_root / str(project_id)).mkdir(parents=True, exist_ok=True)
        return self.get_project(project_id)

    def list_projects(self) -> list[ProjectRecord]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT p.*, COUNT(s.id) AS snapshot_count
                FROM projects p
                LEFT JOIN snapshots s ON s.project_id = p.id
                GROUP BY p.id
                ORDER BY p.updated_at DESC, p.id DESC
                """
            ).fetchall()
        return [self._project_from_row(row) for row in rows]

    def get_project(self, project_id: int) -> ProjectRecord:
        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT p.*, COUNT(s.id) AS snapshot_count
                FROM projects p
                LEFT JOIN snapshots s ON s.project_id = p.id
                WHERE p.id = ?
                GROUP BY p.id
                """,
                (project_id,),
            ).fetchone()
        if row is None:
            raise ProjectNotFoundError(f"Project {project_id} does not exist")
        return self._project_from_row(row)

    def update_project(
        self,
        project_id: int,
        *,
        name: str | None = None,
        description: str | None = None,
        memory_config: dict[str, Any] | None = None,
    ) -> ProjectRecord:
        current = self.get_project(project_id)
        next_name = current.name if name is None else name.strip()
        if not next_name:
            raise StorageError("Project name cannot be empty")
        next_description = current.description if description is None else description.strip()
        next_config = (
            current.memory_config
            if memory_config is None
            else normalize_memory_config(memory_config)
        )
        with self._lock, self.connection() as connection:
            connection.execute(
                """
                UPDATE projects
                SET name = ?, description = ?, memory_config_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    next_name,
                    next_description,
                    json.dumps(next_config, ensure_ascii=False),
                    utc_now_iso(),
                    project_id,
                ),
            )
        return self.get_project(project_id)

    def add_snapshot(
        self,
        project_id: int,
        *,
        version_name: str,
        elf_source: str | Path,
        map_source: str | Path | None,
        analysis: FirmwareAnalysis,
        notes: str = "",
    ) -> SnapshotRecord:
        self.get_project(project_id)
        clean_version = version_name.strip()
        if not clean_version:
            raise StorageError("Version name cannot be empty")
        elf_source_path = Path(elf_source).resolve()
        map_source_path = Path(map_source).resolve() if map_source else None
        if not elf_source_path.is_file():
            raise StorageError(f"ELF source does not exist: {elf_source_path}")
        if map_source_path is not None and not map_source_path.is_file():
            raise StorageError(f"MAP source does not exist: {map_source_path}")
        now = utc_now_iso()
        blob = self._pack_analysis(analysis)
        with self._lock, self.connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO snapshots(
                    project_id, version_name, notes, elf_path, map_path,
                    analysis_blob, sha256, created_at
                ) VALUES (?, ?, ?, '', '', ?, ?, ?)
                """,
                (
                    project_id,
                    clean_version,
                    notes.strip(),
                    blob,
                    analysis.identity.sha256,
                    now,
                ),
            )
            snapshot_id = int(cursor.lastrowid)
            snapshot_dir = self.artifact_root / str(project_id) / str(snapshot_id)
            snapshot_dir.mkdir(parents=True, exist_ok=False)
            elf_target = snapshot_dir / "firmware.elf"
            map_target = snapshot_dir / "firmware.map"
            try:
                shutil.copy2(elf_source_path, elf_target)
                stored_map = ""
                if map_source_path:
                    shutil.copy2(map_source_path, map_target)
                    stored_map = str(map_target)
                connection.execute(
                    "UPDATE snapshots SET elf_path = ?, map_path = ? WHERE id = ?",
                    (str(elf_target), stored_map, snapshot_id),
                )
                connection.execute(
                    "UPDATE projects SET updated_at = ? WHERE id = ?",
                    (now, project_id),
                )
            except Exception:
                shutil.rmtree(snapshot_dir, ignore_errors=True)
                raise
        return self.get_snapshot(snapshot_id, include_analysis=True)

    def list_snapshots(
        self, project_id: int, *, include_analysis: bool = False
    ) -> list[SnapshotRecord]:
        self.get_project(project_id)
        columns = "*" if include_analysis else (
            "id, project_id, version_name, notes, elf_path, map_path, created_at"
        )
        with self.connection() as connection:
            rows = connection.execute(
                f"SELECT {columns} FROM snapshots WHERE project_id = ? "
                "ORDER BY created_at DESC, id DESC",
                (project_id,),
            ).fetchall()
        return [self._snapshot_from_row(row, include_analysis) for row in rows]

    def get_snapshot(
        self, snapshot_id: int, *, include_analysis: bool = True
    ) -> SnapshotRecord:
        columns = "*" if include_analysis else (
            "id, project_id, version_name, notes, elf_path, map_path, created_at"
        )
        with self.connection() as connection:
            row = connection.execute(
                f"SELECT {columns} FROM snapshots WHERE id = ?", (snapshot_id,)
            ).fetchone()
        if row is None:
            raise SnapshotNotFoundError(f"Snapshot {snapshot_id} does not exist")
        return self._snapshot_from_row(row, include_analysis)

    def get_analysis_dict(self, snapshot_id: int) -> dict[str, Any]:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT analysis_blob FROM snapshots WHERE id = ?", (snapshot_id,)
            ).fetchone()
        if row is None:
            raise SnapshotNotFoundError(f"Snapshot {snapshot_id} does not exist")
        return self._unpack_analysis(row["analysis_blob"])

    def save_report(self, file_name: str, content: bytes) -> Path:
        safe_name = Path(file_name).name
        if not safe_name:
            raise StorageError("Report file name cannot be empty")
        target = self.report_root / safe_name
        target.write_bytes(content)
        return target

    @staticmethod
    def _project_from_row(row: sqlite3.Row) -> ProjectRecord:
        return ProjectRecord(
            id=int(row["id"]),
            name=row["name"],
            description=row["description"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            memory_config=json.loads(row["memory_config_json"]),
            snapshot_count=int(row["snapshot_count"]),
        )

    def _snapshot_from_row(
        self, row: sqlite3.Row, include_analysis: bool
    ) -> SnapshotRecord:
        analysis = None
        if include_analysis and "analysis_blob" in row.keys():
            analysis = self._unpack_analysis(row["analysis_blob"])
        return SnapshotRecord(
            id=int(row["id"]),
            project_id=int(row["project_id"]),
            version_name=row["version_name"],
            notes=row["notes"],
            created_at=row["created_at"],
            elf_path=row["elf_path"],
            map_path=row["map_path"],
            analysis=analysis,  # type: ignore[arg-type]
        )
