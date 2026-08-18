from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def to_primitive(value: Any) -> Any:
    if is_dataclass(value):
        return {key: to_primitive(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): to_primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_primitive(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


@dataclass(slots=True)
class FirmwareIdentity:
    file_name: str
    file_size: int
    sha256: str
    elf_class: int
    byte_order: str
    machine: int
    architecture: str
    entry_point: int
    flags: int
    abi: str
    build_id: str = ""
    comment: str = ""


@dataclass(slots=True)
class ProgramSegment:
    index: int
    segment_type: str
    offset: int
    virtual_address: int
    physical_address: int
    file_size: int
    memory_size: int
    flags: str
    alignment: int

    @property
    def end_address(self) -> int:
        return self.virtual_address + self.memory_size


@dataclass(slots=True)
class SectionRecord:
    index: int
    name: str
    section_type: str
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int
    allocated: bool
    writable: bool
    executable: bool
    nobits: bool

    @property
    def end_address(self) -> int:
        return self.address + self.size

    @property
    def permissions(self) -> str:
        result = "r" if self.allocated else "-"
        result += "w" if self.writable else "-"
        result += "x" if self.executable else "-"
        return result


@dataclass(slots=True)
class SymbolRecord:
    name: str
    value: int
    size: int
    symbol_type: str
    binding: str
    visibility: str
    section_index: int
    section_name: str
    source: str = "elf"

    @property
    def end_address(self) -> int:
        return self.value + self.size


@dataclass(slots=True)
class MapContribution:
    section_name: str
    object_path: str
    address: int
    size: int
    archive_path: str = ""
    symbol_name: str = ""


@dataclass(slots=True)
class MemoryRegion:
    name: str
    origin: int
    length: int
    permissions: str = "rwx"
    description: str = ""

    @property
    def end(self) -> int:
        return self.origin + self.length

    def contains(self, address: int, size: int = 1) -> bool:
        if size < 0:
            return False
        end = address + size
        return address >= self.origin and end <= self.end


@dataclass(slots=True)
class RegionUsage:
    region: MemoryRegion
    used_bytes: int
    file_bytes: int
    section_names: list[str] = field(default_factory=list)
    uncovered_sections: list[str] = field(default_factory=list)

    @property
    def free_bytes(self) -> int:
        return max(0, self.region.length - self.used_bytes)

    @property
    def usage_percent(self) -> float:
        if self.region.length <= 0:
            return 0.0
        return round(self.used_bytes * 100.0 / self.region.length, 3)


@dataclass(slots=True)
class Diagnostic:
    severity: str
    code: str
    title: str
    detail: str
    subject: str = ""
    address: int | None = None
    suggestion: str = ""


@dataclass(slots=True)
class InstructionRecord:
    address: int
    raw: bytes
    width: int
    mnemonic: str
    operands: str
    category: str
    extension: str
    function_name: str = ""
    source_line: str = ""


@dataclass(slots=True)
class InstructionProfile:
    total: int = 0
    compressed: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    extensions: dict[str, int] = field(default_factory=dict)
    mnemonics: dict[str, int] = field(default_factory=dict)
    records: list[InstructionRecord] = field(default_factory=list)
    decode_failures: int = 0

    @property
    def compressed_percent(self) -> float:
        if not self.total:
            return 0.0
        return round(self.compressed * 100.0 / self.total, 3)


@dataclass(slots=True)
class FunctionProfile:
    name: str
    address: int
    size: int
    instruction_count: int
    byte_count: int
    compressed_count: int
    branch_count: int
    call_count: int
    load_count: int
    store_count: int
    estimated_complexity: int
    is_leaf: bool
    categories: dict[str, int] = field(default_factory=dict)
    extensions: dict[str, int] = field(default_factory=dict)
    callees: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    source_lines: list[str] = field(default_factory=list)

    @property
    def compressed_percent(self) -> float:
        if not self.instruction_count:
            return 0.0
        return round(self.compressed_count * 100.0 / self.instruction_count, 3)


@dataclass(slots=True)
class FirmwareString:
    section_name: str
    address: int
    offset: int
    text: str
    encoding: str
    category: str
    length: int


@dataclass(slots=True)
class SectionEntropy:
    section_name: str
    address: int
    size: int
    entropy: float
    zero_percent: float
    printable_percent: float
    classification: str


@dataclass(slots=True)
class ReleaseCheck:
    check_id: str
    title: str
    status: str
    summary: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass(slots=True)
class PolicyRuleResult:
    rule_id: str
    title: str
    status: str
    expected: Any
    actual: Any
    summary: str
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PolicyEvaluation:
    policy_name: str
    status: str
    passed: int
    failed: int
    total: int
    results: list[PolicyRuleResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_primitive(self)


@dataclass(slots=True)
class SizeSummary:
    file_bytes: int = 0
    load_bytes: int = 0
    runtime_bytes: int = 0
    code_bytes: int = 0
    readonly_bytes: int = 0
    initialized_data_bytes: int = 0
    zero_fill_bytes: int = 0
    debug_bytes: int = 0
    metadata_bytes: int = 0


@dataclass(slots=True)
class FirmwareAnalysis:
    identity: FirmwareIdentity
    segments: list[ProgramSegment]
    sections: list[SectionRecord]
    symbols: list[SymbolRecord]
    map_contributions: list[MapContribution]
    memory_regions: list[MemoryRegion]
    region_usage: list[RegionUsage]
    diagnostics: list[Diagnostic]
    instruction_profile: InstructionProfile
    size_summary: SizeSummary
    function_profiles: list[FunctionProfile] = field(default_factory=list)
    firmware_strings: list[FirmwareString] = field(default_factory=list)
    section_entropy: list[SectionEntropy] = field(default_factory=list)
    release_checks: list[ReleaseCheck] = field(default_factory=list)
    toolchain: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return to_primitive(self)

    def top_symbols(self, limit: int = 20, symbol_type: str | None = None) -> list[SymbolRecord]:
        values: Iterable[SymbolRecord] = self.symbols
        if symbol_type:
            values = (item for item in values if item.symbol_type == symbol_type)
        return sorted(values, key=lambda item: (item.size, item.name), reverse=True)[:limit]


@dataclass(slots=True)
class ValueDelta:
    before: int | float
    after: int | float

    @property
    def absolute(self) -> int | float:
        return self.after - self.before

    @property
    def percent(self) -> float | None:
        if self.before == 0:
            return None if self.after == 0 else 100.0
        return round((self.after - self.before) * 100.0 / self.before, 3)


@dataclass(slots=True)
class NamedDelta:
    name: str
    status: str
    before_size: int
    after_size: int
    before_address: int | None = None
    after_address: int | None = None
    kind: str = ""

    @property
    def delta(self) -> int:
        return self.after_size - self.before_size


@dataclass(slots=True)
class FirmwareDiff:
    baseline_id: int
    target_id: int
    created_at: str
    identity_changes: dict[str, dict[str, Any]]
    size_deltas: dict[str, ValueDelta]
    section_deltas: list[NamedDelta]
    symbol_deltas: list[NamedDelta]
    region_deltas: list[NamedDelta]
    instruction_deltas: dict[str, ValueDelta]
    extension_changes: dict[str, str]
    diagnostics: list[Diagnostic]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        payload = to_primitive(self)
        for field_name in ("size_deltas", "instruction_deltas"):
            serialized = payload[field_name]
            for name, delta in getattr(self, field_name).items():
                serialized[name]["absolute"] = delta.absolute
                serialized[name]["percent"] = delta.percent
        for field_name in ("section_deltas", "symbol_deltas", "region_deltas"):
            serialized = payload[field_name]
            for item, delta in zip(serialized, getattr(self, field_name), strict=True):
                item["delta"] = delta.delta
        return payload


@dataclass(slots=True)
class ProjectRecord:
    id: int
    name: str
    description: str
    created_at: str
    updated_at: str
    memory_config: dict[str, Any]
    snapshot_count: int = 0


@dataclass(slots=True)
class SnapshotRecord:
    id: int
    project_id: int
    version_name: str
    notes: str
    created_at: str
    elf_path: str
    map_path: str
    analysis: FirmwareAnalysis | None = None


@dataclass(slots=True)
class ReportArtifact:
    file_name: str
    media_type: str
    content: bytes


@dataclass(slots=True)
class FirmwareCandidate:
    version_name: str
    elf_path: str
    map_path: str = ""
    relative_path: str = ""
    file_size: int = 0
    modified_time: float = 0.0


@dataclass(slots=True)
class BatchItemResult:
    candidate: FirmwareCandidate
    status: str
    analysis: FirmwareAnalysis | None = None
    error_code: str = ""
    error_message: str = ""
    elapsed_seconds: float = 0.0


@dataclass(slots=True)
class BatchAnalysisResult:
    root_path: str
    created_at: str
    elapsed_seconds: float
    items: list[BatchItemResult]
    comparisons: list[FirmwareDiff]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return to_primitive(self)
