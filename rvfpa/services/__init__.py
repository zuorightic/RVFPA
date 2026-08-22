"""应用服务包，集中导出命令行与Web接口共用的编排、差异和存储服务。"""

from .analysis import FirmwareAnalysisService
from .diff import compare_firmware
from .storage import WorkspaceStore

__all__ = ["FirmwareAnalysisService", "WorkspaceStore", "compare_firmware"]
