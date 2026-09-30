import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from connstrlint import cli


class MergeEnvContinuationsTests(unittest.TestCase):
    def test_single_line_assignment_passes_through_unchanged(self):
        lines = ["DATABASE_URL=postgres://user:pass@host/db\n"]
        blocks = list(cli.merge_env_continuations(lines))
        self.assertEqual(blocks, [(1, "DATABASE_URL=postgres://user:pass@host/db")])

    def test_quoted_value_closed_on_same_line_is_not_merged(self):
        lines = ['DATABASE_URL="postgres://user:pass@host/db"\n', "OTHER=1\n"]
        blocks = list(cli.merge_env_continuations(lines))
        self.assertEqual(
            blocks,
            [
                (1, 'DATABASE_URL="postgres://user:pass@host/db"'),
                (2, "OTHER=1"),
            ],
        )

    def test_multiline_quoted_kv_string_is_joined(self):
        lines = [
            'CONN_STR="Server=sqlsrv01;\n',
            "Database=orders;\n",
            'Password=changeme123;"\n',
            "OTHER=1\n",
        ]
        blocks = list(cli.merge_env_continuations(lines))
        self.assertEqual(len(blocks), 2)
        start_no, text = blocks[0]
        self.assertEqual(start_no, 1)
        self.assertEqual(
            text,
            'CONN_STR="Server=sqlsrv01;\nDatabase=orders;\nPassword=changeme123;"',
        )
        self.assertEqual(blocks[1], (4, "OTHER=1"))

    def test_unterminated_quote_absorbs_rest_of_file(self):
        lines = ['CONN_STR="Server=sqlsrv01;\n', "Database=orders;\n"]
        blocks = list(cli.merge_env_continuations(lines))
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0][0], 1)

    def test_export_prefix_is_recognized(self):
        lines = ['export CONN_STR="Server=sqlsrv01;\n', 'Password=x;"\n']
        blocks = list(cli.merge_env_continuations(lines))
        self.assertEqual(len(blocks), 1)


class LocateTests(unittest.TestCase):
    def test_offset_on_first_line(self):
        self.assertEqual(cli._locate(3, "hello world", 6), (3, 7))

    def test_offset_on_a_later_line(self):
        text = "first\nsecond\nthird"
        # 'second' starts right after "first\n" (6 chars)
        self.assertEqual(cli._locate(1, text, 6), (2, 1))
        self.assertEqual(cli._locate(1, text, 6 + 7), (3, 1))


class ScanFileEnvTests(unittest.TestCase):
    def _write(self, suffix, content):
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        )
        try:
            handle.write(content)
        finally:
            handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_finds_password_in_multiline_quoted_env_value(self):
        path = self._write(
            ".env",
            'CONN_STR="Server=sqlsrv01;\nDatabase=orders;\nPassword=changeme123;"\n',
        )
        findings = list(cli.scan_file(path))
        rule_ids = {finding.rule_id for _, _, finding in findings}
        self.assertIn("CS001", rule_ids)
        # every finding should be anchored to the line the value started on
        self.assertTrue(all(line_no == 1 for line_no, _, _ in findings))

    def test_non_env_file_is_not_merged_across_lines(self):
        path = self._write(
            ".ini",
            'conn = "Server=sqlsrv01;\nDatabase=orders;\nPassword=changeme123;"\n',
        )
        findings = list(cli.scan_file(path))
        self.assertEqual(findings, [])


class MainJsonFormatTests(unittest.TestCase):
    def _write(self, suffix, content):
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        )
        try:
            handle.write(content)
        finally:
            handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_json_output_is_a_list_of_findings(self):
        path = self._write(
            ".ini",
            "conn = Server=sqlsrv01;Database=orders;User Id=sa;Password=changeme123;"
            "TrustServerCertificate=true;\n",
        )
        out = io.StringIO()
        with redirect_stdout(out):
            exit_code = cli.main(["--format", "json", path])

        payload = json.loads(out.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertTrue(len(payload) >= 4)
        rule_ids = {item["rule_id"] for item in payload}
        self.assertIn("CS004", rule_ids)
        first = payload[0]
        self.assertEqual(first["path"], path)
        self.assertEqual(set(first), {"path", "line", "column", "rule_id", "severity", "message"})

    def test_json_output_is_empty_list_when_nothing_found(self):
        path = self._write(".ini", "just some plain text with no connection strings\n")
        out = io.StringIO()
        with redirect_stdout(out):
            exit_code = cli.main(["--format", "json", path])

        self.assertEqual(json.loads(out.getvalue()), [])
        self.assertEqual(exit_code, 0)

    def test_text_format_is_still_the_default(self):
        path = self._write(".ini", "just some plain text with no connection strings\n")
        out = io.StringIO()
        with redirect_stdout(out):
            exit_code = cli.main([path])

        self.assertEqual(out.getvalue().strip(), "no findings")
        self.assertEqual(exit_code, 0)


class MainFailOnTests(unittest.TestCase):
    def _run(self, content, *flags):
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".ini", delete=False, encoding="utf-8"
        )
        try:
            handle.write(content)
        finally:
            handle.close()
        self.addCleanup(os.unlink, handle.name)
        with redirect_stdout(io.StringIO()):
            return cli.main([*flags, handle.name])

    # warnings only: plaintext password and no ssl option, nothing at error level
    WARNING_ONLY = "conn = Server=db1;Database=orders;User Id=app;Password=changeme123;\n"

    def test_default_ignores_warnings(self):
        self.assertEqual(self._run(self.WARNING_ONLY), 0)

    def test_fail_on_warning_trips_on_warnings(self):
        self.assertEqual(self._run(self.WARNING_ONLY, "--fail-on", "warning"), 1)

    def test_fail_on_error_does_not_trip_on_warnings(self):
        self.assertEqual(self._run(self.WARNING_ONLY, "--fail-on", "error"), 0)

    def test_fail_on_info_trips_on_any_finding(self):
        content = "conn = postgres://app@db:5432/x?sslmode=require\n"
        self.assertEqual(self._run(content, "--fail-on", "info"), 1)

    def test_fail_on_none_never_fails(self):
        content = self.WARNING_ONLY.rstrip("\n") + "TrustServerCertificate=true;\n"
        self.assertEqual(self._run(content, "--fail-on", "none"), 0)

    def test_no_findings_exits_zero_even_at_info(self):
        self.assertEqual(self._run("nothing here\n", "--fail-on", "info"), 0)


if __name__ == "__main__":
    unittest.main()
