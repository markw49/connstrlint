import os
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
