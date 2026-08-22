"""校验并执行JSON格式的发布准入策略。

策略可以限制体积、内存区域、ABI、扩展、节区、诊断、函数复杂度和字符串。
每条规则单独返回结果；配置写错时，调用方会收到可直接显示的输入错误。
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter
from typing import Any

from ..config import parse_integer
from ..errors import InputValidationError
from ..models import FirmwareAnalysis, PolicyEvaluation, PolicyRuleResult


_SIZE_FIELDS: dict[str, tuple[str, str]] = {
    "file_bytes": ("ELF文件体积", "file_bytes"),
    "load_bytes": ("加载镜像体积", "load_bytes"),
    "runtime_bytes": ("运行时内存", "runtime_bytes"),
    "code_bytes": ("代码体积", "code_bytes"),
    "readonly_bytes": ("只读数据体积", "readonly_bytes"),
    "initialized_data_bytes": ("已初始化数据体积", "initialized_data_bytes"),
    "zero_fill_bytes": ("零初始化数据体积", "zero_fill_bytes"),
    "debug_bytes": ("调试信息体积", "debug_bytes"),
    "metadata_bytes": ("元数据体积", "metadata_bytes"),
}


def _require_object(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise InputValidationError(f"Policy field {field_name} must be an object")
    return value


def _string_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise InputValidationError(f"Policy field {field_name} must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        text = str(item).strip()
        if not text:
            raise InputValidationError(
                f"Policy field {field_name}[{index}] cannot be empty"
            )
        result.append(text)
    return result


def _non_negative_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool):
        raise InputValidationError(f"Policy field {field_name} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise InputValidationError(
            f"Policy field {field_name} must be numeric"
        ) from exc
    if number < 0:
        raise InputValidationError(f"Policy field {field_name} cannot be negative")
    return number


def _result(
    rule_id: str,
    title: str,
    passed: bool,
    expected: Any,
    actual: Any,
    summary: str,
    evidence: list[str] | None = None,
) -> PolicyRuleResult:
    return PolicyRuleResult(
        rule_id=rule_id,
        title=title,
        status="pass" if passed else "fail",
        expected=expected,
        actual=actual,
        summary=summary,
        evidence=evidence or [],
    )


def _evaluate_size_limits(
    analysis: FirmwareAnalysis, raw_limits: Any
) -> list[PolicyRuleResult]:
    """逐项检查文件、代码、数据和运行时空间上限。"""
    limits = _require_object(raw_limits, "limits")
    unknown = sorted(set(limits) - set(_SIZE_FIELDS))
    if unknown:
        raise InputValidationError(f"Unknown size limit: {unknown[0]}")
    results: list[PolicyRuleResult] = []
    for key, raw_limit in limits.items():
        title, attribute = _SIZE_FIELDS[key]
        limit = parse_integer(raw_limit, field_name=f"policy.limits.{key}")
        if limit < 0:
            raise InputValidationError(f"Policy limit {key} cannot be negative")
        actual = getattr(analysis.size_summary, attribute)
        passed = actual <= limit
        results.append(
            _result(
                f"limit.{key}",
                title,
                passed,
                {"maximum": limit},
                actual,
                f"{actual}字节，策略上限{limit}字节。",
            )
        )
    return results


def _evaluate_region_limits(
    analysis: FirmwareAnalysis, raw_limits: Any
) -> list[PolicyRuleResult]:
    """按内存区域名称检查占用率是否超过策略阈值。"""
    limits = _require_object(raw_limits, "region_usage_percent")
    usage_by_name = {item.region.name.casefold(): item for item in analysis.region_usage}
    results: list[PolicyRuleResult] = []
    for configured_name, raw_limit in limits.items():
        region_name = str(configured_name).strip()
        if not region_name:
            raise InputValidationError("Policy region name cannot be empty")
        limit = _non_negative_number(
            raw_limit, f"policy.region_usage_percent.{region_name}"
        )
        if limit > 100:
            raise InputValidationError(
                f"Policy region limit cannot exceed 100: {region_name}"
            )
        usage = usage_by_name.get(region_name.casefold())
        if usage is None:
            results.append(
                _result(
                    f"region.{region_name}",
                    f"{region_name}区域占用",
                    False,
                    {"maximum_percent": limit},
                    None,
                    "分析结果中没有该内存区域。",
                )
            )
            continue
        passed = usage.usage_percent <= limit
        results.append(
            _result(
                f"region.{usage.region.name}",
                f"{usage.region.name}区域占用",
                passed,
                {"maximum_percent": limit},
                usage.usage_percent,
                (
                    f"已使用{usage.used_bytes}/{usage.region.length}字节，"
                    f"占用率{usage.usage_percent:.3f}%。"
                ),
                usage.section_names[:20],
            )
        )
    return results


def _evaluate_membership(
    *,
    rule_id: str,
    title: str,
    expected: list[str],
    actual: set[str],
    require_present: bool,
) -> PolicyRuleResult | None:
    if not expected:
        return None
    normalized_actual = {item.casefold() for item in actual}
    matched = [item for item in expected if item.casefold() in normalized_actual]
    violations = [item for item in expected if item.casefold() not in normalized_actual]
    if not require_present:
        matched, violations = violations, matched
    passed = not violations
    if require_present:
        summary = "所有必需项均存在。" if passed else "缺少必需项。"
    else:
        summary = "未发现禁用项。" if passed else "发现策略禁用项。"
    return _result(
        rule_id,
        title,
        passed,
        expected,
        sorted(actual),
        summary,
        violations,
    )


def _evaluate_extension_rules(
    analysis: FirmwareAnalysis, policy: dict[str, Any]
) -> list[PolicyRuleResult]:
    """检查RISC-V必需扩展和禁用扩展规则。"""
    extensions = set(analysis.instruction_profile.extensions)
    results: list[PolicyRuleResult] = []
    required = _string_list(policy.get("required_extensions"), "required_extensions")
    forbidden = _string_list(policy.get("forbidden_extensions"), "forbidden_extensions")
    for item in (
        _evaluate_membership(
            rule_id="extensions.required",
            title="必需指令扩展",
            expected=required,
            actual=extensions,
            require_present=True,
        ),
        _evaluate_membership(
            rule_id="extensions.forbidden",
            title="禁用指令扩展",
            expected=forbidden,
            actual=extensions,
            require_present=False,
        ),
    ):
        if item is not None:
            results.append(item)
    return results


def _evaluate_abi(analysis: FirmwareAnalysis, raw_allowed: Any) -> PolicyRuleResult | None:
    allowed = _string_list(raw_allowed, "allowed_abis")
    if not allowed:
        return None
    actual = analysis.identity.abi
    actual_values = {actual.casefold(), actual.split(maxsplit=1)[0].casefold()}
    passed = bool(actual_values & {item.casefold() for item in allowed})
    return _result(
        "abi.allowed",
        "允许的RISC-V ABI",
        passed,
        allowed,
        actual,
        "ABI符合策略。" if passed else "ABI不在允许列表中。",
    )


def _matching_sections(patterns: list[str], section_names: set[str]) -> list[str]:
    matches: list[str] = []
    for pattern in patterns:
        matches.extend(
            name for name in section_names if fnmatch.fnmatchcase(name, pattern)
        )
    return sorted(set(matches))


def _evaluate_section_rules(
    analysis: FirmwareAnalysis, policy: dict[str, Any]
) -> list[PolicyRuleResult]:
    """使用节区名或通配模式检查必需、禁用节区。"""
    names = {item.name for item in analysis.sections if item.size > 0}
    required = _string_list(policy.get("required_sections"), "required_sections")
    forbidden = _string_list(policy.get("forbidden_sections"), "forbidden_sections")
    results: list[PolicyRuleResult] = []
    if required:
        missing = [pattern for pattern in required if not _matching_sections([pattern], names)]
        results.append(
            _result(
                "sections.required",
                "必需固件段",
                not missing,
                required,
                sorted(names),
                "所有必需段均存在。" if not missing else "缺少必需固件段。",
                missing,
            )
        )
    if forbidden:
        present = _matching_sections(forbidden, names)
        results.append(
            _result(
                "sections.forbidden",
                "禁用固件段",
                not present,
                forbidden,
                present,
                "未发现禁用段。" if not present else "发现策略禁用段。",
                present,
            )
        )
    return results


def _evaluate_diagnostic_limits(
    analysis: FirmwareAnalysis, raw_limits: Any
) -> list[PolicyRuleResult]:
    """限制不同严重级别诊断的允许数量。"""
    limits = _require_object(raw_limits, "max_diagnostics")
    allowed_severities = {"error", "warning", "info"}
    unknown = sorted(set(limits) - allowed_severities)
    if unknown:
        raise InputValidationError(f"Unknown diagnostic severity: {unknown[0]}")
    counts = Counter(item.severity for item in analysis.diagnostics)
    results: list[PolicyRuleResult] = []
    titles = {"error": "错误级诊断", "warning": "警告级诊断", "info": "信息级诊断"}
    for severity, raw_limit in limits.items():
        limit = parse_integer(
            raw_limit, field_name=f"policy.max_diagnostics.{severity}"
        )
        if limit < 0:
            raise InputValidationError(
                f"Diagnostic limit cannot be negative: {severity}"
            )
        actual = counts.get(severity, 0)
        evidence = [
            f"{item.code}: {item.title}"
            for item in analysis.diagnostics
            if item.severity == severity
        ][:20]
        results.append(
            _result(
                f"diagnostics.{severity}",
                titles[severity],
                actual <= limit,
                {"maximum": limit},
                actual,
                f"当前{actual}项，策略上限{limit}项。",
                evidence,
            )
        )
    return results


def _evaluate_decode_failure(
    analysis: FirmwareAnalysis, raw_limit: Any
) -> PolicyRuleResult | None:
    """检查内置指令解码失败比例是否在允许范围内。"""
    if raw_limit is None:
        return None
    limit = _non_negative_number(raw_limit, "policy.max_decode_failure_percent")
    if limit > 100:
        raise InputValidationError("Decode failure percentage cannot exceed 100")
    profile = analysis.instruction_profile
    actual = 0.0 if not profile.total else round(
        profile.decode_failures * 100.0 / profile.total, 3
    )
    return _result(
        "instructions.decode_failure",
        "指令解码失败率",
        actual <= limit,
        {"maximum_percent": limit},
        actual,
        f"{profile.decode_failures}/{profile.total}条指令未能分类。",
    )


def _evaluate_function_complexity(
    analysis: FirmwareAnalysis, raw_limit: Any
) -> PolicyRuleResult | None:
    """检查单函数估算复杂度，并列出超过阈值的函数。"""
    if raw_limit is None:
        return None
    limit = parse_integer(raw_limit, field_name="policy.max_function_complexity")
    if limit < 1:
        raise InputValidationError("Function complexity limit must be at least 1")
    offenders = sorted(
        (
            item
            for item in analysis.function_profiles
            if item.estimated_complexity > limit
        ),
        key=lambda item: (item.estimated_complexity, item.name),
        reverse=True,
    )
    actual = max(
        (item.estimated_complexity for item in analysis.function_profiles), default=0
    )
    return _result(
        "functions.complexity",
        "函数估算复杂度",
        not offenders,
        {"maximum": limit},
        actual,
        "所有函数均在复杂度上限内。" if not offenders else "存在复杂度超限函数。",
        [f"{item.name}: {item.estimated_complexity}" for item in offenders[:20]],
    )


def _compile_patterns(raw_patterns: Any) -> list[tuple[str, re.Pattern[str]]]:
    patterns = _string_list(raw_patterns, "forbidden_string_patterns")
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for pattern in patterns:
        try:
            compiled.append((pattern, re.compile(pattern, re.IGNORECASE)))
        except re.error as exc:
            raise InputValidationError(
                f"Invalid forbidden string pattern {pattern!r}: {exc}"
            ) from exc
    return compiled


def _evaluate_string_patterns(
    analysis: FirmwareAnalysis, raw_patterns: Any
) -> PolicyRuleResult | None:
    """在已提取固件字符串中匹配用户配置的禁用正则表达式。"""
    patterns = _compile_patterns(raw_patterns)
    if not patterns:
        return None
    evidence: list[str] = []
    matched_patterns: set[str] = set()
    for item in analysis.firmware_strings:
        for source, compiled in patterns:
            if compiled.search(item.text):
                matched_patterns.add(source)
                evidence.append(f"{item.section_name}@0x{item.address:x}: {item.text[:100]}")
                break
    return _result(
        "strings.forbidden_patterns",
        "禁用字符串模式",
        not evidence,
        [source for source, _ in patterns],
        sorted(matched_patterns),
        "未命中禁用模式。" if not evidence else "固件字符串命中禁用模式。",
        evidence[:20],
    )


def evaluate_policy(
    analysis: FirmwareAnalysis, policy: dict[str, Any]
) -> PolicyEvaluation:
    """执行一份发布准入策略并汇总所有规则的通过状态。"""
    if not isinstance(policy, dict):
        raise InputValidationError("Policy root must be an object")
    name = str(policy.get("name", "未命名发布策略")).strip()
    if not name:
        raise InputValidationError("Policy name cannot be empty")
    known_fields = {
        "name",
        "limits",
        "region_usage_percent",
        "required_extensions",
        "forbidden_extensions",
        "allowed_abis",
        "required_sections",
        "forbidden_sections",
        "max_diagnostics",
        "max_decode_failure_percent",
        "max_function_complexity",
        "forbidden_string_patterns",
    }
    unknown = sorted(set(policy) - known_fields)
    if unknown:
        raise InputValidationError(f"Unknown policy field: {unknown[0]}")

    results = [
        *_evaluate_size_limits(analysis, policy.get("limits")),
        *_evaluate_region_limits(analysis, policy.get("region_usage_percent")),
        *_evaluate_extension_rules(analysis, policy),
        *_evaluate_section_rules(analysis, policy),
        *_evaluate_diagnostic_limits(analysis, policy.get("max_diagnostics")),
    ]
    optional_checks: list[PolicyRuleResult | None] = [
        _evaluate_abi(analysis, policy.get("allowed_abis")),
        _evaluate_decode_failure(
            analysis, policy.get("max_decode_failure_percent")
        ),
        _evaluate_function_complexity(
            analysis, policy.get("max_function_complexity")
        ),
        _evaluate_string_patterns(
            analysis, policy.get("forbidden_string_patterns")
        ),
    ]
    results.extend(item for item in optional_checks if item is not None)
    passed = sum(item.status == "pass" for item in results)
    failed = len(results) - passed
    return PolicyEvaluation(
        policy_name=name,
        status="pass" if failed == 0 else "fail",
        passed=passed,
        failed=failed,
        total=len(results),
        results=results,
    )
