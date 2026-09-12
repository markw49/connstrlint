import unittest

from connstrlint.parser import ConnectionString
from connstrlint import rules


def make_conn(**overrides):
    fields = dict(raw="", style="url", scheme="postgres")
    fields.update(overrides)
    return ConnectionString(**fields)


class PlaintextPasswordTests(unittest.TestCase):
    def test_flags_a_literal_password(self):
        conn = make_conn(password="changeme123")
        findings = rules.rule_plaintext_password(conn)
        self.assertEqual([f.rule_id for f in findings], ["CS001"])

    def test_no_password_is_not_flagged(self):
        self.assertEqual(rules.rule_plaintext_password(make_conn()), [])

    def test_empty_password_is_not_flagged_here(self):
        # empty string is falsy, so this is CS002's job, not CS001's
        self.assertEqual(rules.rule_plaintext_password(make_conn(password="")), [])

    def test_placeholder_forms_are_not_flagged(self):
        for value in ("${DB_PASSWORD}", "%DB_PASSWORD%", "$DB_PASSWORD", "<password>", "...", "DB_PASSWORD"):
            with self.subTest(value=value):
                conn = make_conn(password=value)
                self.assertEqual(rules.rule_plaintext_password(conn), [])


class EmptyPasswordTests(unittest.TestCase):
    def test_flags_user_with_empty_password(self):
        conn = make_conn(user="app", password="")
        findings = rules.rule_empty_password(conn)
        self.assertEqual([f.rule_id for f in findings], ["CS002"])

    def test_no_finding_without_a_user(self):
        self.assertEqual(rules.rule_empty_password(make_conn(password="")), [])

    def test_no_finding_when_password_is_set(self):
        conn = make_conn(user="app", password="changeme123")
        self.assertEqual(rules.rule_empty_password(conn), [])


class MissingSslTests(unittest.TestCase):
    def test_url_style_known_scheme_without_ssl_option(self):
        conn = make_conn(style="url", scheme="postgres")
        findings = rules.rule_missing_ssl(conn)
        self.assertEqual([f.rule_id for f in findings], ["CS003"])

    def test_url_style_with_ssl_option_present(self):
        conn = make_conn(style="url", scheme="postgres", options={"sslmode": "require"})
        self.assertEqual(rules.rule_missing_ssl(conn), [])

    def test_url_style_unknown_scheme_is_ignored(self):
        conn = make_conn(style="url", scheme="http")
        self.assertEqual(rules.rule_missing_ssl(conn), [])

    def test_jdbc_prefix_is_stripped_before_checking_scheme(self):
        conn = make_conn(style="url", scheme="jdbc:mysql")
        findings = rules.rule_missing_ssl(conn)
        self.assertEqual([f.rule_id for f in findings], ["CS003"])

    def test_kv_style_without_host_is_ignored(self):
        conn = make_conn(style="kv", scheme=None, host=None)
        self.assertEqual(rules.rule_missing_ssl(conn), [])

    def test_kv_style_with_host_and_no_encrypt_option(self):
        conn = make_conn(style="kv", scheme=None, host="sqlsrv01")
        findings = rules.rule_missing_ssl(conn)
        self.assertEqual([f.rule_id for f in findings], ["CS003"])

    def test_kv_style_with_encrypt_option(self):
        conn = make_conn(
            style="kv", scheme=None, host="sqlsrv01", options={"encrypt": "yes"}
        )
        self.assertEqual(rules.rule_missing_ssl(conn), [])


class TrustServerCertificateTests(unittest.TestCase):
    def test_flags_true_value(self):
        conn = make_conn(options={"trustservercertificate": "true"})
        findings = rules.rule_trust_server_certificate(conn)
        self.assertEqual([f.rule_id for f in findings], ["CS004"])

    def test_flags_yes_and_1(self):
        for value in ("yes", "1", "TRUE"):
            with self.subTest(value=value):
                conn = make_conn(options={"trustservercertificate": value})
                findings = rules.rule_trust_server_certificate(conn)
                self.assertEqual([f.rule_id for f in findings], ["CS004"])

    def test_false_value_is_not_flagged(self):
        conn = make_conn(options={"trustservercertificate": "false"})
        self.assertEqual(rules.rule_trust_server_certificate(conn), [])

    def test_spaced_key_variant_is_recognized(self):
        conn = make_conn(options={"trust server certificate": "true"})
        findings = rules.rule_trust_server_certificate(conn)
        self.assertEqual([f.rule_id for f in findings], ["CS004"])

    def test_absent_option_is_not_flagged(self):
        self.assertEqual(rules.rule_trust_server_certificate(make_conn()), [])


class DefaultAccountTests(unittest.TestCase):
    def test_flags_known_default_accounts(self):
        for name in ("sa", "root", "admin", "administrator", "postgres"):
            with self.subTest(name=name):
                findings = rules.rule_default_account(make_conn(user=name))
                self.assertEqual([f.rule_id for f in findings], ["CS005"])

    def test_is_case_insensitive(self):
        findings = rules.rule_default_account(make_conn(user="ROOT"))
        self.assertEqual([f.rule_id for f in findings], ["CS005"])

    def test_regular_user_is_not_flagged(self):
        self.assertEqual(rules.rule_default_account(make_conn(user="app_user")), [])

    def test_no_user_is_not_flagged(self):
        self.assertEqual(rules.rule_default_account(make_conn()), [])


class RunRulesTests(unittest.TestCase):
    def test_aggregates_findings_from_every_rule(self):
        conn = make_conn(
            style="kv",
            scheme=None,
            host="sqlsrv01",
            user="sa",
            password="changeme123",
            options={"trustservercertificate": "true"},
        )
        rule_ids = {f.rule_id for f in rules.run_rules(conn)}
        self.assertEqual(rule_ids, {"CS001", "CS003", "CS004", "CS005"})

    def test_clean_connection_produces_no_findings(self):
        conn = make_conn(
            style="url",
            scheme="postgres",
            user="app_user",
            password="${DB_PASSWORD}",
            options={"sslmode": "require"},
        )
        self.assertEqual(rules.run_rules(conn), [])


if __name__ == "__main__":
    unittest.main()
