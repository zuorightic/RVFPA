from __future__ import annotations

from collections import Counter

from ..models import FirmwareAnalysis, ReleaseCheck


def _check_layout_errors(analysis: FirmwareAnalysis) -> ReleaseCheck:
    errors = [item for item in analysis.diagnostics if item.severity == "error"]
    return ReleaseCheck(
        check_id="layout-errors",
        title="地址布局完整性",
        status="fail" if errors else "pass",
        summary="存在布局错误" if errors else "未发现布局错误",
        detail=(
            f"分析结果包含{len(errors)}项错误级诊断。"
            if errors
            else "入口地址、段归属和区域边界检查均未产生错误级诊断。"
        ),
        evidence=[item.title for item in errors[:10]],
        recommendation="修复错误级诊断后再生成发布版本。" if errors else "",
    )


def _check_memory_headroom(analysis: FirmwareAnalysis) -> ReleaseCheck:
    crowded = [item for item in analysis.region_usage if item.usage_percent >= 90]
    tight = [item for item in analysis.region_usage if 75 <= item.usage_percent < 90]
    if crowded:
        status = "fail"
        summary = "内存余量不足"
        detail = "至少一个区域占用率达到90%。"
        recommendation = "缩减静态占用或扩大目标区域。"
    elif tight:
        status = "warn"
        summary = "内存余量偏低"
        detail = "至少一个区域占用率达到75%。"
        recommendation = "评估后续功能增长和运行时栈空间。"
    else:
        status = "pass"
        summary = "内存余量充足"
        detail = "所有已配置区域占用率均低于75%。"
        recommendation = ""
    evidence = [f"{item.region.name}: {item.usage_percent}%" for item in crowded + tight]
    return ReleaseCheck(
        check_id="memory-headroom",
        title="内存区域余量",
        status=status,
        summary=summary,
        detail=detail,
        evidence=evidence,
        recommendation=recommendation,
    )


def _check_writable_executable(analysis: FirmwareAnalysis) -> ReleaseCheck:
    sections = [
        f"节区 {item.name}"
        for item in analysis.sections
        if item.allocated and item.writable and item.executable and item.size
    ]
    segments = [
        (
            f"程序段 #{item.index} {item.segment_type}: "
            f"0x{item.virtual_address:x}-0x{item.end_address:x}"
        )
        for item in analysis.segments
        if item.memory_size and "w" in item.flags and "x" in item.flags
    ]
    evidence = sections + segments
    return ReleaseCheck(
        check_id="writable-executable",
        title="可写可执行区域",
        status="warn" if evidence else "pass",
        summary="发现可写可执行区域" if evidence else "未发现可写可执行区域",
        detail=(
            "部分节区或程序段同时具备写入和执行权限。"
            if evidence
            else "节区与程序段均未同时启用写入和执行权限。"
        ),
        evidence=evidence,
        recommendation="调整链接脚本以拆分可执行代码和可写数据。" if evidence else "",
    )


def _check_debug_payload(analysis: FirmwareAnalysis) -> ReleaseCheck:
    debug = analysis.size_summary.debug_bytes
    file_size = max(1, analysis.size_summary.file_bytes)
    percent = round(debug * 100.0 / file_size, 2)
    if percent >= 40:
        status = "warn"
        summary = "调试信息占比较高"
        recommendation = "发布镜像可使用strip副本，但应保留带符号版本用于定位。"
    else:
        status = "pass"
        summary = "调试信息占比正常"
        recommendation = ""
    return ReleaseCheck(
        check_id="debug-payload",
        title="调试信息占用",
        status=status,
        summary=summary,
        detail=f"调试段共{debug}字节，占ELF文件{percent}%。",
        evidence=[item.name for item in analysis.sections if item.name.startswith(".debug")][:20],
        recommendation=recommendation,
    )


def _check_instruction_decode(analysis: FirmwareAnalysis) -> ReleaseCheck:
    profile = analysis.instruction_profile
    if profile.total == 0:
        return ReleaseCheck(
            check_id="instruction-decode",
            title="指令反汇编覆盖",
            status="fail",
            summary="没有获得指令记录",
            detail="反汇编工具未产生可解析的指令。",
            recommendation="检查RISC-V objdump工具和ELF可执行段。",
        )
    failure_percent = profile.decode_failures * 100.0 / profile.total
    status = "warn" if failure_percent > 1 else "pass"
    return ReleaseCheck(
        check_id="instruction-decode",
        title="指令反汇编覆盖",
        status=status,
        summary="指令画像已生成" if status == "pass" else "部分指令未分类",
        detail=(
            f"共解析{profile.total}条指令，分类失败{profile.decode_failures}条。"
        ),
        evidence=[f"扩展{key}: {value}" for key, value in profile.extensions.items()],
        recommendation="检查自定义扩展助记符并补充分类规则。" if status == "warn" else "",
    )


def _check_sensitive_strings(analysis: FirmwareAnalysis) -> ReleaseCheck:
    suspects = [
        item for item in analysis.firmware_strings if item.category == "sensitive-keyword"
    ]
    return ReleaseCheck(
        check_id="sensitive-strings",
        title="敏感关键词线索",
        status="warn" if suspects else "pass",
        summary="发现需要复核的字符串" if suspects else "未发现敏感关键词线索",
        detail=(
            "字符串中出现密码、令牌或密钥相关关键词；这只是线索，不代表存在泄露。"
            if suspects
            else "可提取字符串中未出现预设的敏感关键词。"
        ),
        evidence=[f"{item.section_name}: {item.text[:80]}" for item in suspects[:20]],
        recommendation="人工确认字符串是否包含真实凭据或仅为提示文本。" if suspects else "",
    )


def _check_high_entropy_sections(analysis: FirmwareAnalysis) -> ReleaseCheck:
    values = [
        item
        for item in analysis.section_entropy
        if item.classification == "high-entropy" and item.size >= 256
    ]
    return ReleaseCheck(
        check_id="high-entropy-sections",
        title="高熵数据段",
        status="warn" if values else "pass",
        summary="发现高熵数据段" if values else "未发现异常高熵数据段",
        detail=(
            "高熵可能来自压缩表、加密数据或已打包资源，需要结合项目用途判断。"
            if values
            else "较大的固件段未表现出异常高熵特征。"
        ),
        evidence=[f"{item.section_name}: {item.entropy:.3f}" for item in values],
        recommendation="确认高熵段是否为预期资源，并保留生成来源。" if values else "",
    )


def build_release_checks(analysis: FirmwareAnalysis) -> list[ReleaseCheck]:
    checks = [
        _check_layout_errors(analysis),
        _check_memory_headroom(analysis),
        _check_writable_executable(analysis),
        _check_debug_payload(analysis),
        _check_instruction_decode(analysis),
        _check_sensitive_strings(analysis),
        _check_high_entropy_sections(analysis),
    ]
    return checks


def release_check_summary(checks: list[ReleaseCheck]) -> dict[str, int | str]:
    counts = Counter(item.status for item in checks)
    if counts.get("fail"):
        overall = "fail"
    elif counts.get("warn"):
        overall = "warn"
    else:
        overall = "pass"
    return {
        "overall": overall,
        "pass": counts.get("pass", 0),
        "warn": counts.get("warn", 0),
        "fail": counts.get("fail", 0),
        "total": len(checks),
    }
