"""固件分析器包，对外汇总资源、指令、函数、内容和发布检查入口。"""

from .content import analyze_section_entropy, extract_firmware_strings
from .functions import build_function_profiles
from .memory import analyze_memory_layout
from .policy import evaluate_policy
from .release import build_release_checks
from .raw_decode import decode_executable_sections
from .riscv import build_instruction_profile
from .size import summarize_sizes
from .symbols import enrich_symbols_from_map
from .system_usage import analyze_system_usage

__all__ = [
    "analyze_memory_layout",
    "analyze_section_entropy",
    "analyze_system_usage",
    "build_instruction_profile",
    "build_function_profiles",
    "build_release_checks",
    "decode_executable_sections",
    "extract_firmware_strings",
    "evaluate_policy",
    "summarize_sizes",
    "enrich_symbols_from_map",
]
