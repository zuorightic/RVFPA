"""目录固件发现、ELF/MAP配对和并行批量分析。"""

from __future__ import annotations

import re
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

from ..errors import RVFPAError
from ..models import (
    BatchAnalysisResult,
    BatchItemResult,
    FirmwareCandidate,
    utc_now_iso,
)
from .analysis import FirmwareAnalysisService
from .diff import compare_firmware
from .trends import build_version_trends

ELF_SUFFIXES = {".elf", ".out", ".axf", ".riscv"}
MAP_SUFFIXES = {".map", ".ldmap"}
_VERSION_RE = re.compile(
    r"(?:^|[_\-.])(?:v|ver|version|release|rel)?(?P<major>\d+)"
    r"(?:[._-](?P<minor>\d+))?(?:[._-](?P<patch>\d+))?(?:$|[_\-.])",
    re.IGNORECASE,
)


def infer_version_name(path: Path) -> str:
    stem = path.stem
    matches = list(_VERSION_RE.finditer(stem))
    if matches:
        match = matches[-1]
        values = [match.group("major"), match.group("minor"), match.group("patch")]
        version = ".".join(value for value in values if value is not None)
        return f"V{version}"
    return stem


def _map_candidates(elf_path: Path) -> list[Path]:
    stem = elf_path.stem
    candidates = [
        elf_path.with_suffix(".map"),
        elf_path.parent / f"{elf_path.name}.map",
        elf_path.parent / f"{stem}.ldmap",
    ]
    if stem.endswith("_firmware"):
        candidates.append(elf_path.parent / f"{stem[:-9]}.map")
    return candidates


def find_matching_map(elf_path: Path, known_maps: dict[str, Path]) -> Path | None:
    for candidate in _map_candidates(elf_path):
        if candidate.is_file():
            return candidate
    keys = [elf_path.stem.casefold(), elf_path.name.casefold()]
    for key in keys:
        if key in known_maps:
            return known_maps[key]
    return None


def discover_firmware_candidates(
    root: str | Path,
    *,
    recursive: bool = True,
    maximum_files: int = 500,
) -> list[FirmwareCandidate]:
    root_path = Path(root).expanduser().resolve()
    if not root_path.is_dir():
        raise ValueError(f"Batch root is not a directory: {root_path}")
    iterator = root_path.rglob("*") if recursive else root_path.glob("*")
    files = [item for item in iterator if item.is_file()]
    known_maps: dict[str, Path] = {}
    for path in files:
        if path.suffix.casefold() in MAP_SUFFIXES:
            known_maps[path.stem.casefold()] = path
            known_maps[path.name.casefold()] = path
    candidates: list[FirmwareCandidate] = []
    for path in files:
        if path.suffix.casefold() not in ELF_SUFFIXES:
            continue
        stat = path.stat()
        map_path = find_matching_map(path, known_maps)
        candidates.append(
            FirmwareCandidate(
                version_name=infer_version_name(path),
                elf_path=str(path),
                map_path=str(map_path) if map_path else "",
                relative_path=str(path.relative_to(root_path)),
                file_size=stat.st_size,
                modified_time=stat.st_mtime,
            )
        )
        if len(candidates) >= maximum_files:
            break
    return sorted(
        candidates,
        key=lambda item: (item.modified_time, item.relative_path.casefold()),
    )


def _analyze_candidate(
    candidate: FirmwareCandidate,
    memory_config: dict[str, Any] | None,
) -> BatchItemResult:
    started = time.monotonic()
    service = FirmwareAnalysisService()
    try:
        analysis = service.analyze(
            candidate.elf_path,
            map_path=candidate.map_path or None,
            memory_config=memory_config,
            prefer_map_regions=True,
        )
        return BatchItemResult(
            candidate=candidate,
            status="success",
            analysis=analysis,
            elapsed_seconds=round(time.monotonic() - started, 4),
        )
    except RVFPAError as exc:
        return BatchItemResult(
            candidate=candidate,
            status="failed",
            error_code=exc.code,
            error_message=str(exc),
            elapsed_seconds=round(time.monotonic() - started, 4),
        )
    except Exception as exc:
        return BatchItemResult(
            candidate=candidate,
            status="failed",
            error_code="unexpected_error",
            error_message=str(exc),
            elapsed_seconds=round(time.monotonic() - started, 4),
        )


def _comparison_sequence(items: list[BatchItemResult]):
    successful = [item for item in items if item.status == "success" and item.analysis]
    comparisons = []
    for index in range(1, len(successful)):
        baseline = successful[index - 1]
        target = successful[index]
        comparisons.append(
            compare_firmware(
                baseline.analysis,
                target.analysis,
                baseline_id=index,
                target_id=index + 1,
            )
        )
    return comparisons


def _batch_summary(
    candidates: list[FirmwareCandidate],
    items: list[BatchItemResult],
    comparisons,
) -> dict[str, Any]:
    successful = [item for item in items if item.analysis is not None]
    code_sizes = [item.analysis.size_summary.code_bytes for item in successful]
    runtime_sizes = [item.analysis.size_summary.runtime_bytes for item in successful]
    return {
        "candidate_count": len(candidates),
        "success_count": len(successful),
        "failure_count": len(items) - len(successful),
        "map_pair_count": sum(bool(item.map_path) for item in candidates),
        "comparison_count": len(comparisons),
        "minimum_code_bytes": min(code_sizes, default=0),
        "maximum_code_bytes": max(code_sizes, default=0),
        "minimum_runtime_bytes": min(runtime_sizes, default=0),
        "maximum_runtime_bytes": max(runtime_sizes, default=0),
        "total_input_bytes": sum(item.file_size for item in candidates),
        "architectures": sorted(
            {item.analysis.identity.architecture for item in successful}
        ),
        "trends": build_version_trends(successful),
    }


def analyze_directory(
    root: str | Path,
    *,
    memory_config: dict[str, Any] | None = None,
    recursive: bool = True,
    workers: int = 2,
    maximum_files: int = 500,
) -> BatchAnalysisResult:
    started = time.monotonic()
    root_path = Path(root).expanduser().resolve()
    candidates = discover_firmware_candidates(
        root_path,
        recursive=recursive,
        maximum_files=maximum_files,
    )
    if not candidates:
        return BatchAnalysisResult(
            root_path=str(root_path),
            created_at=utc_now_iso(),
            elapsed_seconds=round(time.monotonic() - started, 4),
            items=[],
            comparisons=[],
            summary=_batch_summary([], [], []),
        )
    worker_count = max(1, min(int(workers), 16, len(candidates)))
    results_by_path: dict[str, BatchItemResult] = {}
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="rvfpa-batch") as executor:
        futures: dict[Future[BatchItemResult], FirmwareCandidate] = {
            executor.submit(_analyze_candidate, candidate, memory_config): candidate
            for candidate in candidates
        }
        for future in as_completed(futures):
            candidate = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = BatchItemResult(
                    candidate=candidate,
                    status="failed",
                    error_code="worker_error",
                    error_message=str(exc),
                )
            results_by_path[candidate.elf_path] = result
    items = [results_by_path[item.elf_path] for item in candidates]
    comparisons = _comparison_sequence(items)
    return BatchAnalysisResult(
        root_path=str(root_path),
        created_at=utc_now_iso(),
        elapsed_seconds=round(time.monotonic() - started, 4),
        items=items,
        comparisons=comparisons,
        summary=_batch_summary(candidates, items, comparisons),
    )
