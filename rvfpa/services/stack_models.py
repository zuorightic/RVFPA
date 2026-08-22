"""GCC栈使用分析的领域模型。

本模块保存单个函数的栈记录和单个 ``.su`` 文件的解析结果。模型不负责读取文件
或计算统计指标，因此解析器和汇总器都可以依赖稳定的数据结构。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class StackUsageRecord:
    """一条GCC ``-fstack-usage`` 函数栈占用记录。"""

    source_path: str
    line: int
    column: int
    function_name: str
    stack_bytes: int
    allocation: str
    bounded: bool
    usage_file: str
    qualifiers: list[str] = field(default_factory=list)

    @property
    def source_name(self) -> str:
        """返回不含目录的源文件名称。"""

        return Path(self.source_path).name

    @property
    def location(self) -> str:
        """返回适合报告展示的源文件位置。"""

        return f"{self.source_path}:{self.line}:{self.column}"

    @property
    def identity(self) -> tuple[str, str, int, int]:
        """返回去重使用的函数与源位置联合标识。"""

        return self.function_name, self.source_path, self.line, self.column

    def to_dict(self) -> dict[str, Any]:
        """转换为可写入JSON报告的字典。"""

        return {
            "source_path": self.source_path,
            "source_name": self.source_name,
            "line": self.line,
            "column": self.column,
            "function_name": self.function_name,
            "stack_bytes": self.stack_bytes,
            "allocation": self.allocation,
            "bounded": self.bounded,
            "usage_file": self.usage_file,
            "qualifiers": self.qualifiers,
            "location": self.location,
        }


@dataclass(slots=True)
class StackUsageDocument:
    """一个 ``.su`` 文件的有效记录及逐行解析警告。"""

    path: Path
    records: list[StackUsageRecord]
    warnings: list[str] = field(default_factory=list)

    @property
    def maximum_stack_bytes(self) -> int:
        """返回当前文件中最大的单函数栈占用。"""

        return max((item.stack_bytes for item in self.records), default=0)

    def to_dict(self) -> dict[str, Any]:
        """生成包含记录、最大值和警告的文件级摘要。"""

        return {
            "path": str(self.path),
            "record_count": len(self.records),
            "maximum_stack_bytes": self.maximum_stack_bytes,
            "records": [item.to_dict() for item in self.records],
            "warnings": self.warnings,
        }
