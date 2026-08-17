#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"


def find_compiler() -> str:
    candidates = ["riscv64-unknown-elf-gcc", "riscv64-linux-gnu-gcc"]
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path
    raise SystemExit("No RISC-V GCC cross compiler was found")


def build(version: str, compiler: str) -> None:
    source = ROOT / f"firmware_{version}.c"
    target = BUILD / f"firmware_{version}.elf"
    map_file = BUILD / f"firmware_{version}.map"
    common = [
        compiler,
        "-march=rv64imac_zicsr_zifencei",
        "-mabi=lp64",
        "-mcmodel=medany",
        "-Os",
        "-g",
        "-ffreestanding",
        "-fno-builtin",
        "-fno-pic",
        "-fno-pie",
        "-nostdlib",
        "-nostartfiles",
        "-no-pie",
    ]
    objects = [
        BUILD / "startup.o",
        BUILD / "runtime.o",
        BUILD / f"firmware_{version}.o",
    ]
    sources = [ROOT / "startup.S", ROOT / "runtime.c", source]
    for object_path, source_path in zip(objects, sources):
        subprocess.run([*common, "-c", str(source_path), "-o", str(object_path)], check=True)
    command = [
        *common,
        *(str(item) for item in objects),
        f"-Wl,-T,{ROOT / 'linker.ld'}",
        f"-Wl,-Map,{map_file}",
        "-Wl,--gc-sections",
        "-Wl,--build-id=none",
        "-o",
        str(target),
    ]
    subprocess.run(command, check=True)
    print(f"built {target.name} ({target.stat().st_size} bytes)")


def main() -> int:
    compiler = find_compiler()
    BUILD.mkdir(parents=True, exist_ok=True)
    build("v1", compiler)
    build("v2", compiler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
