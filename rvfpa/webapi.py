"""本地Web服务和HTTP路由入口。

该文件处理项目、快照、固件分析、版本比较、准入策略和报告下载请求，同时
提供前端静态文件。JSON响应转换和上传文件解码已经拆到独立模块，这里只保留
路由、请求校验和业务服务调用。
"""

from __future__ import annotations

import json
import mimetypes
import shutil
import tempfile
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .constants import MAX_UPLOAD_BYTES, SOFTWARE_NAME, SOFTWARE_SHORT_NAME, SOFTWARE_VERSION
from .errors import InputValidationError, RVFPAError
from .services.analysis import FirmwareAnalysisService
from .services.diff import compare_firmware
from .analyzers.policy import evaluate_policy
from .services.reports import (
    analysis_csv_report,
    analysis_html_report,
    analysis_json_report,
    diff_json_report,
)
from .services.storage import WorkspaceStore
from .web_payloads import (
    json_bytes as _json_bytes,
    project_payload as _project_payload,
    snapshot_payload as _snapshot_payload,
)
from .web_uploads import decode_uploaded_file

class RVFPAApplication:
    def __init__(self, workspace: Path):
        """初始化本地工作区及Web静态资源目录。"""

        self.workspace = workspace
        self.store = WorkspaceStore(workspace)
        self.analysis_service = FirmwareAnalysisService()
        self.web_root = Path(__file__).with_name("web")

    def create_handler(self) -> type[BaseHTTPRequestHandler]:
        """创建绑定当前应用实例的线程化请求处理器类型。"""

        application = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "RVFPA/1.0"

            def log_message(self, fmt: str, *args: Any) -> None:
                print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

            def do_GET(self) -> None:
                self._dispatch("GET")

            def do_POST(self) -> None:
                self._dispatch("POST")

            def do_PUT(self) -> None:
                self._dispatch("PUT")

            def do_OPTIONS(self) -> None:
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("Allow", "GET, POST, PUT, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
                self.end_headers()

            def _dispatch(self, method: str) -> None:
                try:
                    parsed = urlparse(self.path)
                    if parsed.path.startswith("/api/"):
                        self._handle_api(method, parsed.path, parse_qs(parsed.query))
                    elif method == "GET":
                        self._serve_static(parsed.path)
                    else:
                        self._send_error(HTTPStatus.NOT_FOUND, "Route not found")
                except RVFPAError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": exc.as_dict()})
                except (ValueError, KeyError, TypeError) as exc:
                    self._send_json(
                        HTTPStatus.BAD_REQUEST,
                        {"error": {"code": "invalid_request", "message": str(exc)}},
                    )
                except Exception as exc:
                    traceback.print_exc()
                    self._send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {
                            "error": {
                                "code": "internal_error",
                                "message": f"Internal server error: {exc}",
                            }
                        },
                    )

            def _handle_api(
                self, method: str, path: str, query: dict[str, list[str]]
            ) -> None:
                parts = [unquote(item) for item in path.strip("/").split("/")]
                if path == "/api/health" and method == "GET":
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "software_name": SOFTWARE_NAME,
                            "short_name": SOFTWARE_SHORT_NAME,
                            "version": SOFTWARE_VERSION,
                            "workspace": str(application.workspace),
                            "toolchain": application.analysis_service.toolchain.describe(),
                        },
                    )
                    return
                if path == "/api/projects" and method == "GET":
                    self._send_json(
                        HTTPStatus.OK,
                        {"projects": [_project_payload(item) for item in application.store.list_projects()]},
                    )
                    return
                if path == "/api/projects" and method == "POST":
                    payload = self._read_json()
                    project = application.store.create_project(
                        name=str(payload.get("name", "")),
                        description=str(payload.get("description", "")),
                        memory_config=payload.get("memory_config"),
                    )
                    self._send_json(HTTPStatus.CREATED, {"project": _project_payload(project)})
                    return
                if len(parts) >= 3 and parts[:2] == ["api", "projects"]:
                    project_id = int(parts[2])
                    if len(parts) == 3 and method == "GET":
                        project = application.store.get_project(project_id)
                        snapshots = application.store.list_snapshots(
                            project_id, include_analysis=True
                        )
                        self._send_json(
                            HTTPStatus.OK,
                            {
                                "project": _project_payload(project),
                                "snapshots": [_snapshot_payload(item) for item in snapshots],
                            },
                        )
                        return
                    if len(parts) == 3 and method == "PUT":
                        payload = self._read_json()
                        project = application.store.update_project(
                            project_id,
                            name=payload.get("name"),
                            description=payload.get("description"),
                            memory_config=payload.get("memory_config"),
                        )
                        self._send_json(HTTPStatus.OK, {"project": _project_payload(project)})
                        return
                    if len(parts) == 4 and parts[3] == "snapshots" and method == "GET":
                        snapshots = application.store.list_snapshots(
                            project_id, include_analysis=True
                        )
                        self._send_json(
                            HTTPStatus.OK,
                            {"snapshots": [_snapshot_payload(item) for item in snapshots]},
                        )
                        return
                    if len(parts) == 4 and parts[3] == "snapshots" and method == "POST":
                        self._create_snapshot(project_id)
                        return
                    if len(parts) == 4 and parts[3] == "demo" and method == "POST":
                        self._import_demo(project_id)
                        return
                if len(parts) >= 3 and parts[:2] == ["api", "snapshots"]:
                    snapshot_id = int(parts[2])
                    if len(parts) == 3 and method == "GET":
                        snapshot = application.store.get_snapshot(snapshot_id, include_analysis=True)
                        self._send_json(
                            HTTPStatus.OK,
                            {"snapshot": _snapshot_payload(snapshot, include_paths=True)},
                        )
                        return
                    if len(parts) == 4 and parts[3] == "analysis" and method == "GET":
                        self._send_json(
                            HTTPStatus.OK,
                            {"analysis": application.store.get_analysis_dict(snapshot_id)},
                        )
                        return
                    if len(parts) == 4 and parts[3] == "report" and method == "GET":
                        self._download_snapshot_report(snapshot_id, query)
                        return
                    if len(parts) == 4 and parts[3] == "policy" and method == "POST":
                        policy = self._read_json()
                        evaluation = evaluate_policy(
                            self._load_analysis_for_snapshot(snapshot_id), policy
                        )
                        self._send_json(
                            HTTPStatus.OK, {"evaluation": evaluation.to_dict()}
                        )
                        return
                if path == "/api/diff" and method == "GET":
                    self._compare_snapshots(query)
                    return
                self._send_error(HTTPStatus.NOT_FOUND, "API route not found")

            def _read_json(self) -> dict[str, Any]:
                content_length = int(self.headers.get("Content-Length", "0") or 0)
                if content_length <= 0:
                    return {}
                if content_length > MAX_UPLOAD_BYTES * 3:
                    raise InputValidationError("Request body is too large")
                raw = self.rfile.read(content_length)
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise InputValidationError("Request body must be valid UTF-8 JSON") from exc
                if not isinstance(payload, dict):
                    raise InputValidationError("JSON request root must be an object")
                return payload

            def _create_snapshot(self, project_id: int) -> None:
                payload = self._read_json()
                elf_file = decode_uploaded_file(payload, "elf")
                if elf_file is None:
                    raise InputValidationError("An ELF file is required")
                map_file = decode_uploaded_file(payload, "map")
                project = application.store.get_project(project_id)
                temporary = Path(tempfile.mkdtemp(prefix="upload-", dir=application.workspace))
                try:
                    elf_path = temporary / elf_file[0]
                    elf_path.write_bytes(elf_file[1])
                    map_path = None
                    if map_file:
                        map_path = temporary / map_file[0]
                        map_path.write_bytes(map_file[1])
                    analysis = application.analysis_service.analyze(
                        elf_path,
                        map_path=map_path,
                        memory_config=project.memory_config,
                        prefer_map_regions=bool(payload.get("prefer_map_regions", True)),
                    )
                    snapshot = application.store.add_snapshot(
                        project_id,
                        version_name=str(payload.get("version_name", "V1")),
                        notes=str(payload.get("notes", "")),
                        elf_source=elf_path,
                        map_source=map_path,
                        analysis=analysis,
                    )
                    self._send_json(
                        HTTPStatus.CREATED,
                        {"snapshot": _snapshot_payload(snapshot, include_paths=False)},
                    )
                finally:
                    shutil.rmtree(temporary, ignore_errors=True)

            def _import_demo(self, project_id: int) -> None:
                project = application.store.get_project(project_id)
                example_root = Path(__file__).resolve().parent.parent / "examples" / "build"
                imported = []
                for version in ("v1", "v2"):
                    elf_path = example_root / f"firmware_{version}.elf"
                    map_path = example_root / f"firmware_{version}.map"
                    if not elf_path.exists():
                        raise InputValidationError(
                            "Demo firmware is not built. Run: python3 examples/build_examples.py"
                        )
                    analysis = application.analysis_service.analyze(
                        elf_path,
                        map_path=map_path if map_path.exists() else None,
                        memory_config=project.memory_config,
                        prefer_map_regions=True,
                    )
                    snapshot = application.store.add_snapshot(
                        project_id,
                        version_name=version.upper(),
                        notes="Built-in RISC-V demonstration firmware",
                        elf_source=elf_path,
                        map_source=map_path if map_path.exists() else None,
                        analysis=analysis,
                    )
                    imported.append(_snapshot_payload(snapshot))
                self._send_json(HTTPStatus.CREATED, {"snapshots": imported})

            def _load_analysis_for_snapshot(self, snapshot_id: int):
                snapshot = application.store.get_snapshot(snapshot_id, include_analysis=False)
                project = application.store.get_project(snapshot.project_id)
                return application.analysis_service.analyze(
                    snapshot.elf_path,
                    map_path=snapshot.map_path or None,
                    memory_config=project.memory_config,
                    prefer_map_regions=True,
                )

            def _compare_snapshots(self, query: dict[str, list[str]]) -> None:
                baseline_id = int(query.get("baseline", ["0"])[0])
                target_id = int(query.get("target", ["0"])[0])
                if baseline_id <= 0 or target_id <= 0:
                    raise InputValidationError("baseline and target snapshot IDs are required")
                baseline_snapshot = application.store.get_snapshot(
                    baseline_id, include_analysis=False
                )
                target_snapshot = application.store.get_snapshot(
                    target_id, include_analysis=False
                )
                if baseline_snapshot.project_id != target_snapshot.project_id:
                    raise InputValidationError("Snapshots must belong to the same project")
                baseline = self._load_analysis_for_snapshot(baseline_id)
                target = self._load_analysis_for_snapshot(target_id)
                diff = compare_firmware(
                    baseline,
                    target,
                    baseline_id=baseline_id,
                    target_id=target_id,
                )
                self._send_json(HTTPStatus.OK, {"diff": diff.to_dict()})

            def _download_snapshot_report(
                self, snapshot_id: int, query: dict[str, list[str]]
            ) -> None:
                report_format = query.get("format", ["html"])[0]
                analysis = self._load_analysis_for_snapshot(snapshot_id)
                if report_format == "html":
                    artifact = analysis_html_report(analysis)
                elif report_format == "json":
                    artifact = analysis_json_report(analysis)
                elif report_format in {"sections", "symbols", "instructions", "functions", "strings"}:
                    artifact = analysis_csv_report(analysis, report_format)
                else:
                    raise InputValidationError(f"Unsupported report format: {report_format}")
                self._send_bytes(
                    HTTPStatus.OK,
                    artifact.content,
                    artifact.media_type,
                    download_name=artifact.file_name,
                )

            def _serve_static(self, request_path: str) -> None:
                relative = request_path.strip("/") or "index.html"
                candidate = (application.web_root / relative).resolve()
                try:
                    candidate.relative_to(application.web_root.resolve())
                except ValueError:
                    self._send_error(HTTPStatus.FORBIDDEN, "Invalid static path")
                    return
                if not candidate.is_file():
                    candidate = application.web_root / "index.html"
                media_type, _ = mimetypes.guess_type(candidate.name)
                self._send_bytes(
                    HTTPStatus.OK,
                    candidate.read_bytes(),
                    media_type or "application/octet-stream",
                )

            def _send_json(self, status: HTTPStatus, payload: Any) -> None:
                self._send_bytes(status, _json_bytes(payload), "application/json; charset=utf-8")

            def _send_error(self, status: HTTPStatus, message: str) -> None:
                self._send_json(
                    status,
                    {"error": {"code": status.phrase.lower().replace(" ", "_"), "message": message}},
                )

            def _send_bytes(
                self,
                status: HTTPStatus,
                content: bytes,
                media_type: str,
                *,
                download_name: str | None = None,
            ) -> None:
                self.send_response(status)
                self.send_header("Content-Type", media_type)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                if download_name:
                    self.send_header(
                        "Content-Disposition", f'attachment; filename="{Path(download_name).name}"'
                    )
                self.end_headers()
                self.wfile.write(content)

        return Handler


def serve(host: str, port: int, workspace: Path) -> None:
    """启动本地线程化HTTP服务，并在Ctrl+C后释放监听端口。"""

    application = RVFPAApplication(workspace)
    server = ThreadingHTTPServer((host, port), application.create_handler())
    print(f"{SOFTWARE_NAME} {SOFTWARE_VERSION}")
    print(f"Workspace: {workspace}")
    print(f"Open: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")
    finally:
        server.server_close()
