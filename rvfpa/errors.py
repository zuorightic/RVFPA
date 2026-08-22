"""面向命令行和Web界面的统一业务异常类型。"""

from __future__ import annotations


class RVFPAError(Exception):
    """Base exception for user-facing application errors."""

    code = "rvfpa_error"

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": str(self)}


class InputValidationError(RVFPAError):
    code = "input_validation_error"


class UnsupportedFormatError(RVFPAError):
    code = "unsupported_format"


class ELFParseError(RVFPAError):
    code = "elf_parse_error"


class MapParseError(RVFPAError):
    code = "map_parse_error"


class ToolExecutionError(RVFPAError):
    code = "tool_execution_error"


class ProjectNotFoundError(RVFPAError):
    code = "project_not_found"


class SnapshotNotFoundError(RVFPAError):
    code = "snapshot_not_found"


class StorageError(RVFPAError):
    code = "storage_error"
