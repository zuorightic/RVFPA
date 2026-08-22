"""RVFPA命令行入口与子命令调度。

统一提供本地Web服务、单固件分析、版本比较、批处理、链接脚本、准入策略、
追溯清单和GCC栈使用分析命令。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import default_workspace, load_json_file
from .constants import DEFAULT_HOST, DEFAULT_PORT, SOFTWARE_NAME, SOFTWARE_VERSION
from .errors import RVFPAError
from .services.analysis import FirmwareAnalysisService
from .services.batch import analyze_directory
from .services.diff import compare_firmware
from .services.reports import analysis_html_report, analysis_json_report, diff_json_report
from .services.manifest import build_firmware_manifest
from .services.stack_analysis import analyze_stack_usage
from .analyzers.policy import evaluate_policy
from .parsers.linker_script import parse_linker_script
from .webapi import serve


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rvfpa",
        description=f"{SOFTWARE_NAME} {SOFTWARE_VERSION}",
    )
    parser.add_argument("--version", action="version", version=SOFTWARE_VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="Start the local web application")
    serve_parser.add_argument("--host", default=DEFAULT_HOST)
    serve_parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve_parser.add_argument("--workspace", type=Path, default=default_workspace())

    analyze_parser = subparsers.add_parser("analyze", help="Analyze one RISC-V ELF file")
    analyze_parser.add_argument("elf", type=Path)
    analyze_parser.add_argument("--map", dest="map_path", type=Path)
    analyze_parser.add_argument("--memory", type=Path, help="Memory configuration JSON")
    analyze_parser.add_argument(
        "--format", choices=["summary", "json", "html"], default="summary"
    )
    analyze_parser.add_argument("--output", type=Path)

    compare_parser = subparsers.add_parser("compare", help="Compare two RISC-V ELF files")
    compare_parser.add_argument("baseline", type=Path)
    compare_parser.add_argument("target", type=Path)
    compare_parser.add_argument("--baseline-map", type=Path)
    compare_parser.add_argument("--target-map", type=Path)
    compare_parser.add_argument("--memory", type=Path)
    compare_parser.add_argument("--output", type=Path)

    batch_parser = subparsers.add_parser("batch", help="Analyze a directory of firmware versions")
    batch_parser.add_argument("directory", type=Path)
    batch_parser.add_argument("--memory", type=Path)
    batch_parser.add_argument("--workers", type=int, default=2)
    batch_parser.add_argument("--no-recursive", action="store_true")
    batch_parser.add_argument("--maximum-files", type=int, default=500)
    batch_parser.add_argument("--output", type=Path)

    linker_parser = subparsers.add_parser("linker", help="Extract MEMORY regions from a linker script")
    linker_parser.add_argument("script", type=Path)
    linker_parser.add_argument("--output", type=Path)

    policy_parser = subparsers.add_parser("policy", help="Evaluate a firmware release policy")
    policy_parser.add_argument("elf", type=Path)
    policy_parser.add_argument("--policy", required=True, type=Path)
    policy_parser.add_argument("--map", dest="map_path", type=Path)
    policy_parser.add_argument("--memory", type=Path)
    policy_parser.add_argument("--output", type=Path)

    manifest_parser = subparsers.add_parser("manifest", help="Generate a traceable firmware manifest")
    manifest_parser.add_argument("elf", type=Path)
    manifest_parser.add_argument("--map", dest="map_path", type=Path)
    manifest_parser.add_argument("--memory", type=Path)
    manifest_parser.add_argument("--output", type=Path)

    stack_parser = subparsers.add_parser("stack", help="Analyze GCC .su stack usage files")
    stack_parser.add_argument("path", type=Path)
    stack_parser.add_argument("--limit", help="Maximum stack bytes per function")
    stack_parser.add_argument("--maximum-files", type=int, default=5000)
    stack_parser.add_argument("--no-recursive", action="store_true")
    stack_parser.add_argument("--output", type=Path)
    return parser


def _print_summary(analysis) -> None:
    summary = analysis.size_summary
    print(f"File:         {analysis.identity.file_name}")
    print(f"Architecture: {analysis.identity.architecture}")
    print(f"ABI:          {analysis.identity.abi}")
    print(f"Entry:        0x{analysis.identity.entry_point:x}")
    print(f"Code bytes:   {summary.code_bytes}")
    print(f"RO bytes:     {summary.readonly_bytes}")
    print(f"Data bytes:   {summary.initialized_data_bytes}")
    print(f"BSS bytes:    {summary.zero_fill_bytes}")
    print(f"Instructions: {analysis.instruction_profile.total}")
    print(f"Symbols:      {len(analysis.symbols)}")
    print(f"Diagnostics:  {len(analysis.diagnostics)}")
    for usage in analysis.region_usage:
        print(
            f"Region {usage.region.name}: {usage.used_bytes}/{usage.region.length} "
            f"bytes ({usage.usage_percent:.2f}%)"
        )


def _write_or_stdout(content: bytes, output: Path | None) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(content)
        print(output.resolve())
    else:
        sys.stdout.buffer.write(content)
        if not content.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")


def _run_analyze(args: argparse.Namespace) -> int:
    memory = load_json_file(args.memory) if args.memory else None
    service = FirmwareAnalysisService()
    analysis = service.analyze(
        args.elf,
        map_path=args.map_path,
        memory_config=memory,
        prefer_map_regions=True,
    )
    if args.format == "summary":
        _print_summary(analysis)
    elif args.format == "json":
        _write_or_stdout(analysis_json_report(analysis).content, args.output)
    else:
        _write_or_stdout(analysis_html_report(analysis).content, args.output)
    return 0


def _run_compare(args: argparse.Namespace) -> int:
    memory = load_json_file(args.memory) if args.memory else None
    service = FirmwareAnalysisService()
    baseline = service.analyze(
        args.baseline,
        map_path=args.baseline_map,
        memory_config=memory,
        prefer_map_regions=True,
    )
    target = service.analyze(
        args.target,
        map_path=args.target_map,
        memory_config=memory,
        prefer_map_regions=True,
    )
    artifact = diff_json_report(compare_firmware(baseline, target))
    _write_or_stdout(artifact.content, args.output)
    return 0


def _run_batch(args: argparse.Namespace) -> int:
    memory = load_json_file(args.memory) if args.memory else None
    result = analyze_directory(
        args.directory,
        memory_config=memory,
        recursive=not args.no_recursive,
        workers=args.workers,
        maximum_files=args.maximum_files,
    )
    content = json.dumps(result.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")
    _write_or_stdout(content, args.output)
    return 0 if result.summary["failure_count"] == 0 else 1


def _run_linker(args: argparse.Namespace) -> int:
    document = parse_linker_script(args.script)
    payload = {
        "path": str(document.path),
        "entry_symbol": document.entry_symbol,
        "output_architecture": document.output_architecture,
        "aliases": document.aliases,
        "provided_symbols": document.provided_symbols,
        "warnings": document.warnings,
        "memory_config": document.to_memory_config(),
    }
    _write_or_stdout(
        json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
        args.output,
    )
    return 0


def _run_policy(args: argparse.Namespace) -> int:
    memory = load_json_file(args.memory) if args.memory else None
    policy = load_json_file(args.policy)
    analysis = FirmwareAnalysisService().analyze(
        args.elf,
        map_path=args.map_path,
        memory_config=memory,
        prefer_map_regions=True,
    )
    evaluation = evaluate_policy(analysis, policy)
    content = json.dumps(
        evaluation.to_dict(), ensure_ascii=False, indent=2
    ).encode("utf-8")
    _write_or_stdout(content, args.output)
    return 0 if evaluation.status == "pass" else 1


def _run_manifest(args: argparse.Namespace) -> int:
    memory = load_json_file(args.memory) if args.memory else None
    analysis = FirmwareAnalysisService().analyze(
        args.elf,
        map_path=args.map_path,
        memory_config=memory,
        prefer_map_regions=True,
    )
    manifest = build_firmware_manifest(
        analysis,
        elf_path=args.elf,
        map_path=args.map_path,
    )
    content = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    _write_or_stdout(content, args.output)
    return 0


def _run_stack(args: argparse.Namespace) -> int:
    result = analyze_stack_usage(
        args.path,
        recursive=not args.no_recursive,
        maximum_files=args.maximum_files,
        maximum_stack_bytes=args.limit,
    )
    content = json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8")
    _write_or_stdout(content, args.output)
    return 1 if result["budget"]["status"] == "fail" else 0


def main(argv: list[str] | None = None) -> int:
    """解析命令行参数并分派到分析、比较、批处理等子命令。"""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            serve(args.host, args.port, args.workspace.resolve())
            return 0
        if args.command == "analyze":
            return _run_analyze(args)
        if args.command == "compare":
            return _run_compare(args)
        if args.command == "batch":
            return _run_batch(args)
        if args.command == "linker":
            return _run_linker(args)
        if args.command == "policy":
            return _run_policy(args)
        if args.command == "manifest":
            return _run_manifest(args)
        if args.command == "stack":
            return _run_stack(args)
        parser.error(f"Unknown command: {args.command}")
    except RVFPAError as exc:
        print(f"error[{exc.code}]: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
