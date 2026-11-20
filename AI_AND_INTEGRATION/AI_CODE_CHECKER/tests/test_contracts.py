import json
import unittest

from contracts import CONTRACT_VERSION, MAX_BATCH_BYTES, MAX_FINDINGS_PER_CALL
from contracts.adapters import AdapterError, ScannerAdapter
from contracts.finding import ContractError, validate_findings


def valid(**over):
    base = {"rule_id": "R", "file": "f", "severity": "HIGH", "message": "m"}
    base.update(over)
    return base


class VersionTests(unittest.TestCase):
    def test_version(self):
        self.assertEqual(CONTRACT_VERSION, "1.0.0")


class ValidateTests(unittest.TestCase):
    def test_minimal(self):
        out = validate_findings([valid()])
        self.assertEqual(len(out), 1)

    def test_line_null_and_missing(self):
        self.assertEqual(len(validate_findings([valid(line=None)])), 1)
        self.assertEqual(len(validate_findings([valid()])), 1)

    def test_evidence_null(self):
        self.assertEqual(len(validate_findings([valid(evidence=None)])), 1)

    def test_empty_list_ok(self):
        self.assertEqual(validate_findings([]), [])

    def test_not_a_list(self):
        for bad in (None, {}, "x", 42):
            with self.assertRaises(ContractError):
                validate_findings(bad)

    def test_too_many(self):
        items = [valid() for _ in range(MAX_FINDINGS_PER_CALL + 1)]
        with self.assertRaises(ContractError):
            validate_findings(items)

    def test_missing_required(self):
        for key in ("rule_id", "file", "severity", "message"):
            d = valid()
            del d[key]
            with self.assertRaises(ContractError):
                validate_findings([d])

    def test_blank_required(self):
        for key in ("rule_id", "file", "severity", "message"):
            with self.assertRaises(ContractError):
                validate_findings([valid(**{key: "   "})])

    def test_line_invalid(self):
        for bad in (0, -1, True, "42", 1.5):
            with self.assertRaises(ContractError):
                validate_findings([valid(line=bad)])

    def test_evidence_invalid(self):
        for bad in (123, [], True):
            with self.assertRaises(ContractError):
                validate_findings([valid(evidence=bad)])

    def test_extra_field_rejected(self):
        with self.assertRaises(ContractError):
            validate_findings([valid(extra="x")])

    def test_oversize(self):
        big = "x" * 30000
        items = [valid(evidence=big) for _ in range(3)]
        with self.assertRaises(ContractError):
            validate_findings(items)

    def test_does_not_mutate_input(self):
        d = valid()
        snapshot = dict(d)
        validate_findings([d])
        self.assertEqual(d, snapshot)


class AdapterContractTests(unittest.TestCase):
    def test_protocol_is_runtime_checkable(self):
        class Dummy:
            name = "d"

            def normalize(self, raw):
                return []

        self.assertIsInstance(Dummy(), ScannerAdapter)

    def test_adapter_error_is_exception(self):
        self.assertTrue(issubclass(AdapterError, Exception))