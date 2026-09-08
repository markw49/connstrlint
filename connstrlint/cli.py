"""Walk files, pull out anything that looks like a connection string,
parse it, run the rules, print findings as path:line:col."""

import argparse
import os
import re
import sys

from .parser import parse
from .rules import run_rules

SCAN_EXTENSIONS = {
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".yaml",
    ".yml",
    ".json",
    ".txt",
    ".properties",
    ".xml",
}

SKIP_DIRS = {".git", "__pycache__", "node_modules", "venv", ".venv"}

KNOWN_URL_SCHEMES = {
    "postgres",
    "postgresql",
    "mysql",
    "mongodb",
    "mongodb+srv",
    "redis",
    "amqp",
    "sqlserver",
    "mssql",
    "oracle",
    "ldap",
    "ldaps",
}

URL_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.:-]*://[^\s'\"]+")

KV_KEYS = (
    r"server|data source|host|address|uid|user id|password|pwd|"
    r"database|initial catalog|port|encrypt|trustservercertificate|sslmode|ssl"
)
CANDIDATE_KV_RE = re.compile(
    rf"(?i)\b(?:{KV_KEYS})\s*=\s*[^;]+(?:;\s*(?:{KV_KEYS})\s*=\s*[^;]*)+;?"
)


def iter_candidates(line: str):
    """Yield (column, text) for each connection-string-shaped chunk in a line."""
    for match in URL_TOKEN_RE.finditer(line):
        token = match.group(0).rstrip(".,;\"')")
        scheme = token.split("://", 1)[0].lower()
        base_scheme = scheme[5:] if scheme.startswith("jdbc:") else scheme
        if base_scheme in KNOWN_URL_SCHEMES:
            yield match.start() + 1, token

    for match in CANDIDATE_KV_RE.finditer(line):
        yield match.start() + 1, match.group(0)


def scan_file(path: str):
    """Yield (line_no, column, finding) for a single file."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except OSError as exc:
        print(f"{path}: could not read file ({exc})", file=sys.stderr)
        return

    for line_no, line in enumerate(lines, start=1):
        for column, candidate in iter_candidates(line):
            conn = parse(candidate)
            if conn is None:
                continue
            for finding in run_rules(conn):
                yield line_no, column, finding


def collect_files(paths):
    for path in paths:
        if os.path.isfile(path):
            yield path
            continue
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                if os.path.splitext(name)[1].lower() in SCAN_EXTENSIONS:
                    yield os.path.join(root, name)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="connstrlint",
        description="Find connection strings in files and flag risky settings.",
    )
    parser.add_argument(
        "paths", nargs="+", help="files or directories to scan"
    )
    args = parser.parse_args(argv)

    highest_severity = None
    severity_rank = {"info": 0, "warning": 1, "error": 2}
    total_findings = 0

    for path in collect_files(args.paths):
        for line_no, column, finding in scan_file(path):
            total_findings += 1
            if (
                highest_severity is None
                or severity_rank[finding.severity] > severity_rank[highest_severity]
            ):
                highest_severity = finding.severity
            print(
                f"{path}:{line_no}:{column}: [{finding.severity.upper()}] "
                f"{finding.rule_id} {finding.message}"
            )

    if total_findings == 0:
        print("no findings")
        return 0

    print(f"\n{total_findings} finding(s)")
    return 1 if highest_severity == "error" else 0


if __name__ == "__main__":
    sys.exit(main())
