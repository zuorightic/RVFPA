from __future__ import annotations

import unittest

from rvfpa.analyzers.riscv import build_instruction_profile, classify_instruction
from rvfpa.models import InstructionRecord


def record(mnemonic: str, width: int = 4) -> InstructionRecord:
    return InstructionRecord(
        address=0,
        raw=b"\0" * width,
        width=width,
        mnemonic=mnemonic,
        operands="",
        category="",
        extension="",
    )


class InstructionClassificationTests(unittest.TestCase):
    def test_base_integer_categories(self) -> None:
        self.assertEqual(classify_instruction("addi", 4), ("integer-arithmetic", "I"))
        self.assertEqual(classify_instruction("and", 4), ("integer-logic", "I"))
        self.assertEqual(classify_instruction("lw", 4), ("load", "I"))
        self.assertEqual(classify_instruction("sd", 4), ("store", "I"))
        self.assertEqual(classify_instruction("jal", 4), ("control-flow", "I"))

    def test_standard_extensions(self) -> None:
        self.assertEqual(classify_instruction("mul", 4)[1], "M")
        self.assertEqual(classify_instruction("amoadd.w", 4)[1], "A")
        self.assertEqual(classify_instruction("fadd.s", 4)[1], "F")
        self.assertEqual(classify_instruction("fadd.d", 4)[1], "D")
        self.assertEqual(classify_instruction("vadd.vv", 4)[1], "V")
        self.assertEqual(classify_instruction("c.addi", 2)[1], "C")

    def test_profile_counts_categories_and_compression(self) -> None:
        profile = build_instruction_profile(
            [record("addi"), record("mul"), record("c.addi", 2), record("jal")]
        )
        self.assertEqual(profile.total, 4)
        self.assertEqual(profile.compressed, 1)
        self.assertEqual(profile.extensions["I"], 2)
        self.assertEqual(profile.extensions["M"], 1)
        self.assertEqual(profile.extensions["C"], 1)


if __name__ == "__main__":
    unittest.main()

