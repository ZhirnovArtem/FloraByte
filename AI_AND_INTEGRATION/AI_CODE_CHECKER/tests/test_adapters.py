import unittest

from adapters.scanner1_fixture import (
    Scanner1FixtureAdapter,
    load_fixture as load1,
)
from adapters.scanner2_fixture import (
    Scanner2FixtureAdapter,
    load_fixture as load2,
)
from contracts.adapters import AdapterError
from contracts.finding import validate_findings


class Scanner1Tests(unittest.TestCase):
    def test_normalizes_sample(self):
        raw = load1("fixtures/scanner1/sample.json")
        out = Scanner1FixtureAdapter().normalize(raw)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["rule_id"], "HARDCODED_PASSWORD")
        self.assertEqual(out[0]["line"], 42)
        self.assertEqual(out[0]["severity"], "HIGH")
        self.assertIsNone(out[1]["line"])
        # результат — валидный canonical v1.0
        self.assertEqual(len(validate_findings(out)), 2)

    def test_rejects_missing_fixture_marker(self):
        with self.assertRaises(AdapterError):
            Scanner1FixtureAdapter().normalize({"issues": []})

    def test_rejects_missing_issues(self):
        with self.assertRaises(AdapterError):
            Scanner1FixtureAdapter().normalize({"_fixture": True})

    def test_rejects_bad_line(self):
        raw = {
            "_fixture": True,
            "issues": [
                {
                    "id": "R",
                    "path": "f",
                    "line": 0,
                    "level": "HIGH",
                    "title": "m",
                }
            ],
        }
        with self.assertRaises(AdapterError):
            Scanner1FixtureAdapter().normalize(raw)

    def test_rejects_blank_required(self):
        raw = {
            "_fixture": True,
            "issues": [
                {"id": "", "path": "f", "level": "HIGH", "title": "m"}
            ],
        }
        with self.assertRaises(AdapterError):
            Scanner1FixtureAdapter().normalize(raw)

    def test_rejects_non_dict(self):
        for bad in (None, [], "x", 42):
            with self.assertRaises(AdapterError):
                Scanner1FixtureAdapter().normalize(bad)


class Scanner2Tests(unittest.TestCase):
    def test_normalizes_sample(self):
        raw = load2("fixtures/scanner2/sample.json")
        out = Scanner2FixtureAdapter().normalize(raw)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["severity"], "MEDIUM")
        self.assertEqual(out[1]["severity"], "HIGH")
        self.assertEqual(len(validate_findings(out)), 2)

    def test_rejects_missing_fixture_marker(self):
        with self.assertRaises(AdapterError):
            Scanner2FixtureAdapter().normalize({"results": []})

    def test_rejects_missing_location(self):
        raw = {
            "_fixture": True,
            "results": [
                {
                    "check_id": "R",
                    "severity": "high",
                    "description": "m",
                }
            ],
        }
        with self.assertRaises(AdapterError):
            Scanner2FixtureAdapter().normalize(raw)

    def test_rejects_non_dict(self):
        for bad in (None, [], "x", 42):
            with self.assertRaises(AdapterError):
                Scanner2FixtureAdapter().normalize(bad)