"""Task 12 (todolist.md) named PII-masking as "a good first real test
target" for owl24-js; this is the same suite ported to owl24-py, using the
stdlib unittest module - pytest isn't a dependency yet (see Task 12's own
audit), and adding it is that task's job, not Task 8's. Run directly:
`python tests/test_masking.py`, or `python -m unittest discover -s tests`
once a real test runner is wired up (Task 12).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from owl24_py.masking import (  # noqa: E402
    mask_sensitive_data, is_sensitive_field_name, configure_masking,
    luhn_valid, iban_valid, routing_valid, is_private_ipv4,
)


class TestMasking(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(luhn_valid("4111111111111111"), "real Visa test number")
        self.assertFalse(luhn_valid("1234567890123456"), "random non-Luhn digit run")

    def test_card_masking(self):
        self.assertEqual(mask_sensitive_data("card: 4111111111111111"), "card: 411111******1111")
        self.assertEqual(mask_sensitive_data("5500005555555559"), "550000******5559")
        self.assertEqual(mask_sensitive_data("378282246310005"), "378282*****0005")
        self.assertEqual(
            mask_sensitive_data("id: 1234567890123456"), "id: 1234567890123456",
            "a 16-digit run that fails Luhn is left untouched - fixes the old bare-regex over-matching bug",
        )

    def test_secrets(self):
        self.assertEqual(mask_sensitive_data("key=AKIAIOSFODNN7EXAMPLE"), "key=[SECRET_MASKED]")
        self.assertEqual(mask_sensitive_data("token ghp_" + "a" * 36), "token [SECRET_MASKED]")
        self.assertEqual(mask_sensitive_data("xoxb-1234567890-abcdefg"), "[SECRET_MASKED]")
        self.assertEqual(mask_sensitive_data("sk_live_" + "a" * 24), "[SECRET_MASKED]")
        self.assertEqual(
            mask_sensitive_data("-----BEGIN RSA PRIVATE KEY-----\nABC123\n-----END RSA PRIVATE KEY-----"),
            "[SECRET_MASKED]",
        )

    def test_jwt_bearer(self):
        real_jwt = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123XYZ_-"
        self.assertEqual(mask_sensitive_data(real_jwt), "[TOKEN_MASKED]", "ends in '-', the boundary bug this replaced")
        self.assertEqual(
            mask_sensitive_data("Authorization: Bearer sometoken123"), "Authorization: Bearer sometoken123",
            "old loose regex over-matched this",
        )

    def test_field_name_catch_all(self):
        self.assertTrue(is_sensitive_field_name("user_password"))
        self.assertTrue(is_sensitive_field_name("stripe_api_key"))
        self.assertFalse(is_sensitive_field_name("service_name"))

    def test_iban(self):
        real_iban = "DE89370400440532013000"
        self.assertTrue(iban_valid(real_iban))
        self.assertFalse(iban_valid("DE00000000000000000000"))
        masked = mask_sensitive_data(real_iban)
        self.assertTrue(masked.startswith("DE"))
        self.assertTrue(iban_valid(masked), "masked IBAN still round-trips as structurally valid")
        self.assertEqual(mask_sensitive_data("ZZ00000000000000000000"), "ZZ00000000000000000000")

    def test_routing_number(self):
        self.assertTrue(routing_valid("011401533"), "real Bank of America routing number")
        self.assertFalse(routing_valid("123456789"))
        self.assertEqual(mask_sensitive_data("routing 011401533"), "routing [ROUTING_MASKED]")
        self.assertEqual(mask_sensitive_data("id 123456789"), "id 123456789")

    def test_ip_truncation(self):
        self.assertEqual(mask_sensitive_data("client 203.0.113.42 connected"), "client 203.0.113.0 connected")
        self.assertEqual(
            mask_sensitive_data("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "2001:0db8:85a3:0:0:0:0:0"
        )

    def test_rfc1918_detection(self):
        self.assertTrue(is_private_ipv4("10.1.2.3"))
        self.assertTrue(is_private_ipv4("172.20.5.5"), "inside 172.16.0.0/12")
        self.assertFalse(is_private_ipv4("172.32.5.5"), "outside 172.16.0.0/12")
        self.assertTrue(is_private_ipv4("192.168.1.1"))
        self.assertTrue(is_private_ipv4("127.0.0.1"))
        self.assertFalse(is_private_ipv4("8.8.8.8"))

    def test_hostname_suffixes(self):
        self.assertEqual(mask_sensitive_data("connecting to db-primary.internal now"), "connecting to [HOSTNAME_MASKED] now")
        self.assertEqual(mask_sensitive_data("redis.default.svc.cluster.local"), "[HOSTNAME_MASKED]")
        self.assertEqual(mask_sensitive_data("example.com"), "example.com")

    def test_configure_masking(self):
        configure_masking(mask_fields=["*internal_customer_id*", "pricing.*"], internal_hostname_suffixes=[".mycorp.io"])
        try:
            self.assertTrue(is_sensitive_field_name("internal_customer_id"))
            self.assertTrue(is_sensitive_field_name("pricing.tier"))
            self.assertFalse(is_sensitive_field_name("unrelated_field"))
            self.assertTrue(is_sensitive_field_name("password"), "defaults still apply alongside custom patterns")
            self.assertEqual(mask_sensitive_data("worker-3.mycorp.io"), "[HOSTNAME_MASKED]")
            self.assertEqual(mask_sensitive_data("db.internal"), "[HOSTNAME_MASKED]", "default suffix still applies too")
        finally:
            configure_masking()  # reset so this test's config doesn't leak into others
        self.assertFalse(is_sensitive_field_name("internal_customer_id"))

    def test_email(self):
        self.assertEqual(mask_sensitive_data("contact me at a@b.com"), "contact me at [EMAIL_MASKED]")


if __name__ == "__main__":
    unittest.main()
