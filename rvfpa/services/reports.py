"""HTML、JSON和各类CSV分析报告生成。"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime
from typing import Any, Iterable

from ..constants import SOFTWARE_NAME, SOFTWARE_VERSION
from ..models import FirmwareAnalysis, FirmwareDiff, ReportArtifact


def format_bytes(value: int | float) -> str:
    number = float(value)
    units = ["B", "KiB", "MiB", "GiB"]
    unit = units[0]
    for candidate in units:
        unit = candidate
        if abs(number) < 1024 or candidate == units[-1]:
            break
        number /= 1024
    if unit == "B":
        return f"{int(number)} {unit}"
    return f"{number:.2f} {unit}"


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def analysis_json_report(analysis: FirmwareAnalysis) -> ReportArtifact:
    content = json.dumps(
        {
            "software": SOFTWARE_NAME,
            "version": SOFTWARE_VERSION,
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "analysis": analysis.to_dict(),
        },
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")
    return ReportArtifact(
        file_name="firmware-analysis.json",
        media_type="application/json; charset=utf-8",
        content=content,
    )


def analysis_csv_report(analysis: FirmwareAnalysis, kind: str) -> ReportArtifact:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    if kind == "sections":
        writer.writerow(
            [
                "index",
                "name",
                "type",
                "address",
                "end_address",
                "size",
                "permissions",
                "alignment",
            ]
        )
        for item in analysis.sections:
            writer.writerow(
                [
                    item.index,
                    item.name,
                    item.section_type,
                    f"0x{item.address:x}",
                    f"0x{item.end_address:x}",
                    item.size,
                    item.permissions,
                    item.alignment,
                ]
            )
    elif kind == "symbols":
        writer.writerow(
            [
                "name",
                "type",
                "binding",
                "address",
                "size",
                "section",
                "source",
            ]
        )
        for item in sorted(analysis.symbols, key=lambda value: value.size, reverse=True):
            writer.writerow(
                [
                    item.name,
                    item.symbol_type,
                    item.binding,
                    f"0x{item.value:x}",
                    item.size,
                    item.section_name,
                    item.source,
                ]
            )
    elif kind == "instructions":
        writer.writerow(
            [
                "address",
                "raw",
                "width",
                "mnemonic",
                "operands",
                "category",
                "extension",
                "function",
            ]
        )
        for item in analysis.instruction_profile.records:
            writer.writerow(
                [
                    f"0x{item.address:x}",
                    item.raw.hex(),
                    item.width,
                    item.mnemonic,
                    item.operands,
                    item.category,
                    item.extension,
                    item.function_name,
                ]
            )
    elif kind == "functions":
        writer.writerow(
            [
                "name",
                "address",
                "size",
                "instruction_count",
                "complexity",
                "calls",
                "callers",
                "callees",
                "compressed_percent",
            ]
        )
        for item in analysis.function_profiles:
            writer.writerow(
                [
                    item.name,
                    f"0x{item.address:x}",
                    item.size,
                    item.instruction_count,
                    item.estimated_complexity,
                    item.call_count,
                    ";".join(item.callers),
                    ";".join(item.callees),
                    item.compressed_percent,
                ]
            )
    elif kind == "strings":
        writer.writerow(
            ["section", "address", "offset", "encoding", "category", "length", "text"]
        )
        for item in analysis.firmware_strings:
            writer.writerow(
                [
                    item.section_name,
                    f"0x{item.address:x}",
                    item.offset,
                    item.encoding,
                    item.category,
                    item.length,
                    item.text,
                ]
            )
    else:
        raise ValueError(f"Unknown CSV report kind: {kind}")
    return ReportArtifact(
        file_name=f"firmware-{kind}.csv",
        media_type="text/csv; charset=utf-8",
        content=("\ufeff" + stream.getvalue()).encode("utf-8"),
    )


def _summary_cards(analysis: FirmwareAnalysis) -> str:
    values = [
        ("Firmware file", analysis.identity.file_name),
        ("Architecture", analysis.identity.architecture),
        ("Code", format_bytes(analysis.size_summary.code_bytes)),
        (
            "Static RAM",
            format_bytes(
                analysis.size_summary.initialized_data_bytes
                + analysis.size_summary.zero_fill_bytes
            ),
        ),
        ("Instructions", f"{analysis.instruction_profile.total:,}"),
        ("Symbols", f"{len(analysis.symbols):,}"),
    ]
    return "".join(
        f'<div class="metric"><span>{_escape(label)}</span><strong>{_escape(value)}</strong></div>'
        for label, value in values
    )


def _table(headers: list[str], rows: Iterable[Iterable[Any]]) -> str:
    head = "".join(f"<th>{_escape(item)}</th>" for item in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_escape(cell)}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def analysis_html_report(analysis: FirmwareAnalysis) -> ReportArtifact:
    region_rows = [
        (
            item.region.name,
            f"0x{item.region.origin:x}",
            format_bytes(item.region.length),
            format_bytes(item.used_bytes),
            f"{item.usage_percent:.2f}%",
            item.region.permissions,
        )
        for item in analysis.region_usage
    ]
    section_rows = [
        (
            item.name,
            item.section_type,
            f"0x{item.address:x}",
            format_bytes(item.size),
            item.permissions,
        )
        for item in sorted(analysis.sections, key=lambda value: value.size, reverse=True)[:30]
    ]
    symbol_rows = [
        (
            item.name,
            item.symbol_type,
            item.section_name,
            f"0x{item.value:x}",
            format_bytes(item.size),
        )
        for item in sorted(analysis.symbols, key=lambda value: value.size, reverse=True)[:40]
    ]
    instruction_rows = [
        (name, count, f"{count * 100.0 / max(1, analysis.instruction_profile.total):.2f}%")
        for name, count in analysis.instruction_profile.categories.items()
    ]
    diagnostic_rows = [
        (item.severity.upper(), item.title, item.detail, item.suggestion)
        for item in analysis.diagnostics
    ]
    function_rows = [
        (
            item.name,
            f"0x{item.address:x}",
            format_bytes(item.size),
            item.instruction_count,
            item.estimated_complexity,
            "是" if item.is_leaf else "否",
        )
        for item in analysis.function_profiles[:30]
    ]
    release_rows = [
        (item.status.upper(), item.title, item.summary, item.detail, item.recommendation)
        for item in analysis.release_checks
    ]
    content = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_escape(SOFTWARE_NAME)} - 固件分析报告</title>
<style>
body{{font-family:Arial,"Microsoft YaHei",sans-serif;color:#18212b;margin:0;background:#f5f7f8}}
main{{max-width:1180px;margin:0 auto;padding:32px}}
header{{border-bottom:3px solid #146c5b;padding-bottom:20px;margin-bottom:24px}}
h1{{font-size:26px;margin:0 0 8px}} h2{{font-size:18px;margin:32px 0 12px}}
.muted{{color:#607080}} .metrics{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}}
.metric{{background:white;border:1px solid #d8e0e4;padding:14px;border-radius:6px}}
.metric span{{display:block;color:#607080;font-size:12px;margin-bottom:8px}}
.metric strong{{font-size:18px}} table{{width:100%;border-collapse:collapse;background:white}}
th,td{{text-align:left;padding:9px 10px;border-bottom:1px solid #e3e8eb;font-size:12px}}
th{{background:#edf2f3;color:#3c4b54}} footer{{margin-top:40px;color:#607080;font-size:12px}}
@media(max-width:700px){{main{{padding:16px}}.metrics{{grid-template-columns:1fr}}}}
</style>
</head>
<body><main>
<header><h1>{_escape(SOFTWARE_NAME)}</h1>
<div class="muted">固件资源画像报告 · {_escape(SOFTWARE_VERSION)} · {_escape(datetime.now().astimezone().isoformat(timespec='seconds'))}</div></header>
<section class="metrics">{_summary_cards(analysis)}</section>
<h2>内存区域</h2>{_table(['区域','起始地址','容量','已用','占用率','权限'], region_rows)}
<h2>主要段</h2>{_table(['名称','类型','地址','大小','权限'], section_rows)}
<h2>主要符号</h2>{_table(['符号','类型','所在段','地址','大小'], symbol_rows)}
<h2>指令类别</h2>{_table(['类别','数量','占比'], instruction_rows)}
<h2>主要函数</h2>{_table(['函数','地址','大小','指令数','复杂度','叶函数'], function_rows)}
<h2>发布检查</h2>{_table(['状态','检查项','摘要','详情','建议'], release_rows)}
<h2>诊断结果</h2>{_table(['级别','标题','详情','建议'], diagnostic_rows)}
<footer>SHA-256: {_escape(analysis.identity.sha256)}</footer>
</main></body></html>"""
    return ReportArtifact(
        file_name="firmware-analysis.html",
        media_type="text/html; charset=utf-8",
        content=content.encode("utf-8"),
    )


def diff_json_report(diff: FirmwareDiff) -> ReportArtifact:
    return ReportArtifact(
        file_name="firmware-diff.json",
        media_type="application/json; charset=utf-8",
        content=json.dumps(diff.to_dict(), ensure_ascii=False, indent=2).encode("utf-8"),
    )
