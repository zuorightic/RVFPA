from __future__ import annotations

import copy
import unittest

from rvfpa.analyzers.policy import evaluate_policy
from rvfpa.errors import InputValidationError
from rvfpa.models import Diagnostic
from rvfpa.services.analysis import FirmwareAnalysisService

from .common import example_elf, example_map


class PolicyEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.analysis = FirmwareAnalysisService().analyze(
            example_elf("v1"), map_path=example_map("v1")
        )

    def passing_policy(self) -> dict:
        return {
            "name": "示例准入策略",
            "limits": {
                "file_bytes": "64K",
                "code_bytes": "8K",
                "runtime_bytes": "16K",
                "debug_bytes": "32K",
            },
            "region_usage_percent": {"FLASH": 80, "RAM": 80},
            "allowed_abis": ["lp64"],
            "required_extensions": ["I", "M"],
            "forbidden_extensions": ["V"],
            "required_sections": [".text", ".rodata"],
            "forbidden_sections": [".note*"],
            "max_diagnostics": {"error": 0, "warning": 0},
            "max_decode_failure_percent": 1,
            "max_function_complexity": 20,
            "forbidden_string_patterns": [r"password\s*=", r"private[_ -]?key"],
        }

    def test_complete_policy_passes_example(self) -> None:
        evaluation = evaluate_policy(self.analysis, self.passing_policy())
        self.assertEqual(evaluation.status, "pass")
        self.assertEqual(evaluation.failed, 0)
        self.assertEqual(evaluation.passed, evaluation.total)
        self.assertGreaterEqual(evaluation.total, 10)

    def test_size_limit_failure_reports_actual_value(self) -> None:
        policy = self.passing_policy()
        policy["limits"]["code_bytes"] = 16
        evaluation = evaluate_policy(self.analysis, policy)
        result = next(item for item in evaluation.results if item.rule_id == "limit.code_bytes")
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.actual, self.analysis.size_summary.code_bytes)
        self.assertEqual(evaluation.status, "fail")

    def test_missing_region_is_a_policy_failure(self) -> None:
        policy = {"name": "区域", "region_usage_percent": {"TCM": 50}}
        evaluation = evaluate_policy(self.analysis, policy)
        self.assertEqual(evaluation.failed, 1)
        self.assertIsNone(evaluation.results[0].actual)

    def test_region_limit_can_fail(self) -> None:
        policy = {"name": "区域", "region_usage_percent": {"FLASH": 0}}
        evaluation = evaluate_policy(self.analysis, policy)
        self.assertEqual(evaluation.results[0].status, "fail")
        self.assertGreater(evaluation.results[0].actual, 0)

    def test_required_extension_is_case_insensitive(self) -> None:
        evaluation = evaluate_policy(
            self.analysis, {"name": "扩展", "required_extensions": ["i", "m"]}
        )
        self.assertEqual(evaluation.status, "pass")

    def test_missing_required_extension_is_reported(self) -> None:
        evaluation = evaluate_policy(
            self.analysis, {"name": "扩展", "required_extensions": ["V"]}
        )
        result = evaluation.results[0]
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.evidence, ["V"])

    def test_present_forbidden_extension_is_reported(self) -> None:
        evaluation = evaluate_policy(
            self.analysis, {"name": "扩展", "forbidden_extensions": ["M"]}
        )
        result = evaluation.results[0]
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.evidence, ["M"])

    def test_abi_rule_accepts_multiple_values(self) -> None:
        evaluation = evaluate_policy(
            self.analysis, {"name": "ABI", "allowed_abis": ["ilp32", "LP64"]}
        )
        self.assertEqual(evaluation.status, "pass")

    def test_section_patterns_use_shell_style_wildcards(self) -> None:
        policy = {
            "name": "段规则",
            "required_sections": [".text*"],
            "forbidden_sections": [".note*"],
        }
        evaluation = evaluate_policy(self.analysis, policy)
        self.assertEqual(evaluation.status, "pass")
        self.assertEqual(evaluation.total, 2)

    def test_forbidden_existing_section_fails(self) -> None:
        evaluation = evaluate_policy(
            self.analysis, {"name": "段规则", "forbidden_sections": [".text"]}
        )
        self.assertEqual(evaluation.results[0].evidence, [".text"])
        self.assertEqual(evaluation.status, "fail")

    def test_diagnostic_limit_detects_excess(self) -> None:
        mutated = copy.deepcopy(self.analysis)
        mutated.diagnostics.append(
            Diagnostic(
                severity="warning",
                code="test_warning",
                title="Test warning",
                detail="Synthetic test diagnostic",
            )
        )
        evaluation = evaluate_policy(
            mutated, {"name": "诊断", "max_diagnostics": {"warning": 0}}
        )
        self.assertEqual(evaluation.status, "fail")
        self.assertEqual(evaluation.results[0].actual, 1)

    def test_decode_failure_percent_is_calculated(self) -> None:
        mutated = copy.deepcopy(self.analysis)
        mutated.instruction_profile.decode_failures = 10
        evaluation = evaluate_policy(
            mutated, {"name": "解码", "max_decode_failure_percent": 1}
        )
        self.assertEqual(evaluation.status, "fail")
        self.assertGreater(evaluation.results[0].actual, 1)

    def test_complex_function_is_named_in_evidence(self) -> None:
        mutated = copy.deepcopy(self.analysis)
        function = max(
            mutated.function_profiles, key=lambda item: item.estimated_complexity
        )
        function.estimated_complexity = 99
        evaluation = evaluate_policy(
            mutated, {"name": "复杂度", "max_function_complexity": 20}
        )
        self.assertEqual(evaluation.status, "fail")
        self.assertIn(function.name, evaluation.results[0].evidence[0])

    def test_forbidden_string_regex_is_case_insensitive(self) -> None:
        mutated = copy.deepcopy(self.analysis)
        mutated.firmware_strings[0].text = "PASSWORD = demo"
        evaluation = evaluate_policy(
            mutated, {"name": "字符串", "forbidden_string_patterns": [r"password\s*="]}
        )
        self.assertEqual(evaluation.status, "fail")
        self.assertIn("PASSWORD", evaluation.results[0].evidence[0])

    def test_to_dict_contains_serializable_results(self) -> None:
        evaluation = evaluate_policy(self.analysis, self.passing_policy())
        payload = evaluation.to_dict()
        self.assertEqual(payload["policy_name"], "示例准入策略")
        self.assertIsInstance(payload["results"], list)
        self.assertIn("expected", payload["results"][0])


class PolicyValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.analysis = FirmwareAnalysisService().analyze(
            example_elf("v1"), map_path=example_map("v1")
        )

    def assert_invalid(self, policy: object) -> None:
        with self.assertRaises(InputValidationError):
            evaluate_policy(self.analysis, policy)  # type: ignore[arg-type]

    def test_policy_root_must_be_object(self) -> None:
        self.assert_invalid([])

    def test_policy_name_cannot_be_empty(self) -> None:
        self.assert_invalid({"name": "  "})

    def test_unknown_top_level_field_is_rejected(self) -> None:
        self.assert_invalid({"name": "x", "unknown": True})

    def test_unknown_size_field_is_rejected(self) -> None:
        self.assert_invalid({"name": "x", "limits": {"heap_bytes": 12}})

    def test_negative_size_limit_is_rejected(self) -> None:
        self.assert_invalid({"name": "x", "limits": {"code_bytes": -1}})

    def test_region_percent_cannot_exceed_one_hundred(self) -> None:
        self.assert_invalid({"name": "x", "region_usage_percent": {"RAM": 101}})

    def test_string_list_fields_must_be_arrays(self) -> None:
        self.assert_invalid({"name": "x", "required_extensions": "I"})

    def test_empty_string_list_item_is_rejected(self) -> None:
        self.assert_invalid({"name": "x", "required_sections": [""]})

    def test_unknown_diagnostic_severity_is_rejected(self) -> None:
        self.assert_invalid({"name": "x", "max_diagnostics": {"fatal": 0}})

    def test_invalid_regex_is_rejected(self) -> None:
        self.assert_invalid({"name": "x", "forbidden_string_patterns": ["["]})

    def test_empty_policy_is_valid_and_has_no_rules(self) -> None:
        evaluation = evaluate_policy(self.analysis, {})
        self.assertEqual(evaluation.status, "pass")
        self.assertEqual(evaluation.total, 0)
