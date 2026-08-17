from __future__ import annotations

import math
from statistics import mean, median
from typing import Any, Iterable

from ..models import BatchItemResult


METRICS: dict[str, tuple[str, str]] = {
    "file_bytes": ("ELF文件体积", "file_bytes"),
    "code_bytes": ("代码体积", "code_bytes"),
    "runtime_bytes": ("运行时内存", "runtime_bytes"),
    "readonly_bytes": ("只读数据", "readonly_bytes"),
    "initialized_data_bytes": ("初始化数据", "initialized_data_bytes"),
    "zero_fill_bytes": ("BSS", "zero_fill_bytes"),
    "instruction_count": ("指令数量", "instruction_count"),
    "symbol_count": ("符号数量", "symbol_count"),
    "function_count": ("函数数量", "function_count"),
}


def _metric_value(item: BatchItemResult, attribute: str) -> int:
    analysis = item.analysis
    if analysis is None:
        return 0
    if attribute == "instruction_count":
        return analysis.instruction_profile.total
    if attribute == "symbol_count":
        return len(analysis.symbols)
    if attribute == "function_count":
        return len(analysis.function_profiles)
    return int(getattr(analysis.size_summary, attribute))


def _linear_slope(values: list[int]) -> float:
    count = len(values)
    if count < 2:
        return 0.0
    x_mean = (count - 1) / 2
    y_mean = mean(values)
    numerator = sum((index - x_mean) * (value - y_mean) for index, value in enumerate(values))
    denominator = sum((index - x_mean) ** 2 for index in range(count))
    return 0.0 if denominator == 0 else round(numerator / denominator, 3)


def _direction(values: list[int], slope: float) -> str:
    if len(values) < 2 or all(value == values[0] for value in values):
        return "stable"
    baseline = max(1.0, abs(mean(values)))
    relative = slope / baseline
    if relative >= 0.01:
        return "increasing"
    if relative <= -0.01:
        return "decreasing"
    return "stable"


def _change_percent(before: int, after: int) -> float | None:
    if before == 0:
        return None if after == 0 else 100.0
    return round((after - before) * 100.0 / before, 3)


def _outliers(values: list[int]) -> list[int]:
    if len(values) < 4:
        return []
    ordered = sorted(values)
    lower = median(ordered[: len(ordered) // 2])
    upper_start = (len(ordered) + 1) // 2
    upper = median(ordered[upper_start:])
    spread = upper - lower
    if spread <= 0:
        return []
    minimum = lower - 1.5 * spread
    maximum = upper + 1.5 * spread
    return [index for index, value in enumerate(values) if value < minimum or value > maximum]


def _volatility(values: list[int]) -> float:
    if len(values) < 2:
        return 0.0
    average = mean(values)
    if average == 0:
        return 0.0
    variance = sum((value - average) ** 2 for value in values) / len(values)
    return round(math.sqrt(variance) * 100.0 / abs(average), 3)


def build_version_trends(items: Iterable[BatchItemResult]) -> dict[str, Any]:
    successful = [item for item in items if item.analysis is not None]
    versions = [item.candidate.version_name for item in successful]
    metrics: dict[str, Any] = {}
    alerts: list[dict[str, Any]] = []
    for metric_id, (title, attribute) in METRICS.items():
        values = [_metric_value(item, attribute) for item in successful]
        slope = _linear_slope(values)
        outlier_indexes = _outliers(values)
        metric = {
            "metric_id": metric_id,
            "title": title,
            "values": values,
            "minimum": min(values, default=0),
            "maximum": max(values, default=0),
            "average": round(mean(values), 3) if values else 0.0,
            "slope_per_version": slope,
            "direction": _direction(values, slope),
            "volatility_percent": _volatility(values),
            "first_to_last_percent": (
                _change_percent(values[0], values[-1]) if values else None
            ),
            "outlier_versions": [versions[index] for index in outlier_indexes],
        }
        metrics[metric_id] = metric
        for index in outlier_indexes:
            alerts.append(
                {
                    "severity": "warning",
                    "metric_id": metric_id,
                    "version": versions[index],
                    "value": values[index],
                    "message": f"{versions[index]}的{title}偏离版本序列常规范围。",
                }
            )
        if len(values) >= 2:
            change = _change_percent(values[-2], values[-1])
            if change is not None and abs(change) >= 25:
                alerts.append(
                    {
                        "severity": "info",
                        "metric_id": metric_id,
                        "version": versions[-1],
                        "value": values[-1],
                        "message": f"最新版本{title}较上一版本变化{change:+.3f}%。",
                    }
                )
    return {
        "version_count": len(successful),
        "versions": versions,
        "metrics": metrics,
        "alerts": alerts,
        "growing_metrics": [
            metric_id
            for metric_id, item in metrics.items()
            if item["direction"] == "increasing"
        ],
        "shrinking_metrics": [
            metric_id
            for metric_id, item in metrics.items()
            if item["direction"] == "decreasing"
        ],
    }

