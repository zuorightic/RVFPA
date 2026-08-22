"""GNU链接脚本中的内存、入口和区域别名解析。"""

from __future__ import annotations

import ast
import operator
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..config import parse_integer
from ..errors import InputValidationError
from ..models import MemoryRegion

_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)
_MEMORY_BLOCK_RE = re.compile(r"\bMEMORY\s*\{(?P<body>.*?)\}", re.DOTALL | re.IGNORECASE)
_REGION_RE = re.compile(
    r"(?P<name>[A-Za-z_][\w.$-]*)\s*"
    r"(?:\((?P<attributes>[^)]*)\))?\s*:\s*"
    r"ORIGIN\s*=\s*(?P<origin>[^,\r\n]+)\s*,\s*"
    r"LENGTH\s*=\s*(?P<length>[^,;\r\n}]+)",
    re.IGNORECASE,
)
_REGION_ALIAS_RE = re.compile(
    r"REGION_ALIAS\s*\(\s*\"(?P<alias>[^\"]+)\"\s*,\s*(?P<target>[A-Za-z_][\w.$-]*)\s*\)",
    re.IGNORECASE,
)
_PROVIDE_RE = re.compile(
    r"(?:PROVIDE|PROVIDE_HIDDEN)\s*\(\s*(?P<name>[A-Za-z_][\w.$]*)\s*=\s*(?P<value>.*?)\s*\)\s*;",
    re.DOTALL,
)
_ENTRY_RE = re.compile(r"\bENTRY\s*\(\s*([^\s)]+)\s*\)", re.IGNORECASE)
_OUTPUT_ARCH_RE = re.compile(r"\bOUTPUT_ARCH\s*\(\s*([^\s)]+)\s*\)", re.IGNORECASE)


@dataclass(slots=True)
class LinkerScriptDocument:
    path: Path
    regions: list[MemoryRegion] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    provided_symbols: dict[str, str] = field(default_factory=dict)
    entry_symbol: str = ""
    output_architecture: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_memory_config(self) -> dict:
        return {
            "architecture": self.output_architecture or "auto",
            "regions": [
                {
                    "name": item.name,
                    "origin": f"0x{item.origin:x}",
                    "length": item.length,
                    "permissions": item.permissions,
                    "description": item.description,
                }
                for item in self.regions
            ],
        }


def remove_comments(text: str) -> str:
    without_blocks = _BLOCK_COMMENT_RE.sub("", text)
    return _LINE_COMMENT_RE.sub("", without_blocks)


def _normalize_permissions(attributes: str) -> str:
    values = set(attributes.lower().replace("!", "").replace(" ", ""))
    return "".join(character for character in "rwx" if character in values) or "rwx"


def _parse_expression(value: str, constants: dict[str, int]) -> int:
    text = value.strip()
    for name, number in sorted(constants.items(), key=lambda item: len(item[0]), reverse=True):
        text = re.sub(rf"\b{re.escape(name)}\b", str(number), text)
    if re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|\d+)\s*[kKmMgG](?:[iI]?[bB])?", text):
        return parse_integer(text)
    text = re.sub(
        r"(?P<number>(?:0[xX][0-9a-fA-F]+|\d+))\s*(?P<suffix>[kKmMgG](?:[iI]?[bB])?)",
        lambda match: str(parse_integer(match.group("number") + match.group("suffix"))),
        text,
    )
    try:
        tree = ast.parse(text, mode="eval")
        return int(_evaluate_ast(tree.body))
    except (SyntaxError, ValueError, ZeroDivisionError) as exc:
        raise InputValidationError(f"Cannot evaluate linker expression: {value}") from exc


_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.floordiv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.BitOr: operator.or_,
    ast.BitAnd: operator.and_,
    ast.BitXor: operator.xor,
}
_UNARY_OPERATORS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
    ast.Invert: operator.invert,
}


def _evaluate_ast(node: ast.AST) -> int:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY_OPERATORS:
        left = _evaluate_ast(node.left)
        right = _evaluate_ast(node.right)
        return int(_BINARY_OPERATORS[type(node.op)](left, right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPERATORS:
        return int(_UNARY_OPERATORS[type(node.op)](_evaluate_ast(node.operand)))
    raise ValueError(f"Unsupported expression node: {type(node).__name__}")


def parse_linker_script_text(text: str, *, path: Path | None = None) -> LinkerScriptDocument:
    clean = remove_comments(text)
    document = LinkerScriptDocument(path=path or Path("<memory>"))
    entry_match = _ENTRY_RE.search(clean)
    if entry_match:
        document.entry_symbol = entry_match.group(1)
    arch_match = _OUTPUT_ARCH_RE.search(clean)
    if arch_match:
        document.output_architecture = arch_match.group(1)
    for match in _REGION_ALIAS_RE.finditer(clean):
        document.aliases[match.group("alias")] = match.group("target")
    for match in _PROVIDE_RE.finditer(clean):
        document.provided_symbols[match.group("name")] = " ".join(match.group("value").split())
    memory_match = _MEMORY_BLOCK_RE.search(clean)
    if not memory_match:
        document.warnings.append("No MEMORY block was found")
        return document
    constants: dict[str, int] = {}
    for match in _REGION_RE.finditer(memory_match.group("body")):
        name = match.group("name")
        try:
            origin = _parse_expression(match.group("origin"), constants)
            length = _parse_expression(match.group("length"), constants)
        except InputValidationError as exc:
            document.warnings.append(f"{name}: {exc}")
            continue
        if length <= 0:
            document.warnings.append(f"{name}: region length must be positive")
            continue
        permissions = _normalize_permissions(match.group("attributes") or "rwx")
        document.regions.append(
            MemoryRegion(
                name=name,
                origin=origin,
                length=length,
                permissions=permissions,
                description="Imported from GNU linker script",
            )
        )
        constants[f"ORIGIN_{name}"] = origin
        constants[f"LENGTH_{name}"] = length
    document.regions.sort(key=lambda item: item.origin)
    for current, following in zip(document.regions, document.regions[1:]):
        if current.end > following.origin:
            document.warnings.append(
                f"Regions overlap: {current.name} and {following.name}"
            )
    return document


def parse_linker_script(path: str | Path) -> LinkerScriptDocument:
    file_path = Path(path).expanduser().resolve()
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise InputValidationError(f"Cannot read linker script: {file_path}") from exc
    return parse_linker_script_text(text, path=file_path)
