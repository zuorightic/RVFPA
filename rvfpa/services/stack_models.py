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
        return Path(self.source_path).name

    @property
    def location(self) -> str:
        return f"{self.source_path}:{self.line}:{self.column}"

    @property
    def identity(self) -> tuple[str, str, int, int]:


        return self.function_name, self.source_path, self.line, self.column

    def to_dict(self) -> dict[str, Any]:

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

    path: Path
    records: list[StackUsageRecord]
    warnings: list[str] = field(default_factory=list)

    @property
    def maximum_stack_bytes(self) -> int:

        return max((item.stack_bytes for item in self.records), default=0)

    def to_dict(self) -> dict[str, Any]:

        return {
            "path": str(self.path),
            "record_count": len(self.records),
            "maximum_stack_bytes": self.maximum_stack_bytes,
            "records": [item.to_dict() for item in self.records],
            "warnings": self.warnings,
        }
