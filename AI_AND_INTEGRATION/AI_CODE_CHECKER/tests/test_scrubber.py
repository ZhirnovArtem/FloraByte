import json
import re
import unittest

from security.scrubber import (
    DEFAULT_RULES,
    REDACTED,
    ScrubRule,
    scrub_findings,
    scrub_text,
    scrub_value,
)


class ScrubTextTests(unittest.TestCase):
    def test_bearer(self):
        out = scrub_text("Authorization: Bearer abcdefgh1234567890")
        self.assertIn(REDACTED, out)
        self.assertNotIn("abcdefgh1234567890", out)

    def test_aws_access_key(self):
        out = scrub_text("key AKIAIOSFODNN7EXAMPLE end")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertIn(REDACTED, out)

    def test_github_pat(self):
        secret = "ghp_" + "a" * 30
        self.assertNotIn(secret, scrub_text(secret))

    def test_openai_sk(self):
        secret = "sk-" + "a" * 25
        self.assertNotIn(secret, scrub_text(secret))

    def test_jwt(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        self.assertNotIn("eyJ", scrub_text(jwt))

    def test_pem_private_key(self):
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIB...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        out = scrub_text(pem)
        self.assertNotIn("MIIB", out)
        self.assertIn(REDACTED, out)

    def test_password_assignment(self):
        for s in (
            "password=hunter2",
            'password = "hunter2"',
            "PASSWORD: 'hunter2'",
        ):
            out = scrub_text(s)
            self.assertNotIn("hunter2", out)
            self.assertIn(REDACTED, out)

    def test_token_assignment(self):
        for s in (
            "api_key=abcdef123456",
            'token: "abcdef123456"',
            "secret = abcdef123456",
        ):
            self.assertNotIn("abcdef123456", scrub_text(s))

    def test_plain_text_untouched(self):
        self.assertEqual(scrub_text("hello world"), "hello world")

    def test_rule_id_untouched(self):
        # Идентификаторы правил не должны попадать под регэкспы.
        self.assertEqual(scrub_text("HARDCODED_PASSWORD"), "HARDCODED_PASSWORD")

    def test_empty_string(self):
        self.assertEqual(scrub_text(""), "")


class ScrubValueTests(unittest.TestCase):
    def test_recursive_dict(self):
        v = {"a": "password=x1234", "b": {"c": "Bearer " + "a" * 20}}
        out = scrub_value(v)
        dumped = json.dumps(out)
        self.assertNotIn("x1234", dumped)
        self.assertNotIn("a" * 20, dumped)

    def test_original_not_mutated(self):
        v = {"a": "password=x1234"}
        out = scrub_value(v)
        self.assertEqual(v["a"], "password=x1234")
        self.assertIsNot(out, v)
        self.assertIsNot(out["a"], v["a"])

    def test_non_string_untouched(self):
        for value in (42, None, True, 3.14):
            self.assertEqual(scrub_value(value), value)

    def test_list(self):
        v = ["password=x1", "plain"]
        out = scrub_value(v)
        self.assertNotIn("x1", out[0])
        self.assertEqual(out[1], "plain")


class ScrubFindingsTests(unittest.TestCase):
    def test_original_untouched(self):
        f = [
            {
                "rule_id": "R",
                "file": "f",
                "severity": "HIGH",
                "message": "m",
                "evidence": "password=hunter2",
            }
        ]
        out = scrub_findings(f)
        self.assertIn(REDACTED, out[0]["evidence"])
        self.assertEqual(f[0]["evidence"], "password=hunter2")
        self.assertIsNot(f, out)
        self.assertIsNot(f[0], out[0])


class ExtensibilityTests(unittest.TestCase):
    def test_custom_rule(self):
        rule = ScrubRule("demo", re.compile(r"DEMOSECRET-\w+"), "[X]")
        self.assertEqual(scrub_text("DEMOSECRET-abc", rules=[rule]), "[X]")

    def test_rules_are_extensible_by_substitution(self):
        # Заменяем весь набор правил — scrub_text подчиняется аргументу.
        self.assertEqual(
            scrub_text("hello", rules=()), "hello"
        )
        rule = ScrubRule("h", re.compile("hello"), "bye")
        self.assertEqual(scrub_text("hello", rules=[rule]), "bye")


class DefaultRulesShapeTests(unittest.TestCase):
    def test_rules_have_required_shape(self):
        self.assertGreaterEqual(len(DEFAULT_RULES), 5)
        for rule in DEFAULT_RULES:
            self.assertIsInstance(rule, ScrubRule)
            self.assertTrue(rule.name)
            self.assertTrue(hasattr(rule.pattern, "sub"))