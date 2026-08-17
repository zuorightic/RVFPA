from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..errors import ToolExecutionError
from ..parsers.objdump import ObjdumpDocument, parse_objdump_text

_ATTRIBUTE_ARCH_RE = re.compile(r"Tag_RISCV_arch:\s+\"?([^\"\r\n]+)")
_ATTRIBUTE_STACK_ALIGN_RE = re.compile(r"Tag_RISCV_stack_align:\s+(\d+)-bytes")
_ATTRIBUTE_UNALIGNED_RE = re.compile(r"Tag_RISCV_unaligned_access:\s+(.+)")


@dataclass(slots=True)
class ToolResult:
    command: list[str]
    return_code: int
    stdout: str
    stderr: str


def find_tool(candidates: list[str]) -> str | None:
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def run_tool(
    command: list[str], *, timeout: int = 60, accepted_codes: tuple[int, ...] = (0,)
) -> ToolResult:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except OSError as exc:
        raise ToolExecutionError(f"Cannot execute tool: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolExecutionError(
            f"Tool timed out after {timeout} seconds: {' '.join(command)}"
        ) from exc
    result = ToolResult(
        command=command,
        return_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
    if result.return_code not in accepted_codes:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise ToolExecutionError(
            f"Tool failed with exit code {result.return_code}: {detail[:800]}"
        )
    return result


class RiscVToolchain:
    def __init__(self, objdump_path: str | None = None, readelf_path: str | None = None):
        self.objdump_path = objdump_path or find_tool(
            [
                "riscv64-unknown-elf-objdump",
                "riscv64-linux-gnu-objdump",
                "llvm-objdump",
                "objdump",
            ]
        )
        self.readelf_path = readelf_path or find_tool(
            [
                "riscv64-unknown-elf-readelf",
                "riscv64-linux-gnu-readelf",
                "readelf",
            ]
        )

    @property
    def available(self) -> bool:
        return bool(self.objdump_path)

    def describe(self) -> dict[str, str]:
        result: dict[str, str] = {}
        if self.objdump_path:
            result["objdump"] = self.objdump_path
            try:
                output = run_tool([self.objdump_path, "--version"], timeout=10).stdout
                result["objdump_version"] = output.splitlines()[0] if output else ""
            except ToolExecutionError:
                result["objdump_version"] = "unavailable"
        if self.readelf_path:
            result["readelf"] = self.readelf_path
        return result

    def disassemble(self, elf_path: str | Path) -> ObjdumpDocument:
        if not self.objdump_path:
            raise ToolExecutionError("No compatible objdump executable was found")
        path = Path(elf_path).resolve()
        options = ["-d", "-l", "-w", "-M", "no-aliases,numeric"]
        result = run_tool([self.objdump_path, *options, str(path)], timeout=120)
        return parse_objdump_text(result.stdout, path=path)

    def attributes(self, elf_path: str | Path) -> dict[str, str]:
        if not self.readelf_path:
            return {}
        path = Path(elf_path).resolve()
        try:
            result = run_tool(
                [self.readelf_path, "--arch-specific", "--wide", str(path)],
                timeout=30,
            )
        except ToolExecutionError:
            return {}
        attributes: dict[str, str] = {}
        arch_match = _ATTRIBUTE_ARCH_RE.search(result.stdout)
        if arch_match:
            attributes["riscv_arch"] = arch_match.group(1).strip()
        stack_match = _ATTRIBUTE_STACK_ALIGN_RE.search(result.stdout)
        if stack_match:
            attributes["stack_alignment"] = stack_match.group(1)
        unaligned_match = _ATTRIBUTE_UNALIGNED_RE.search(result.stdout)
        if unaligned_match:
            attributes["unaligned_access"] = unaligned_match.group(1).strip()
        return attributes

