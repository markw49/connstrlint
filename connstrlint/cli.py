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

# Matches the start of a .env-style assignment whose value opens with a
# quote, e.g. `DATABASE_URL="` or `export CONN='`.
ENV_ASSIGNMENT_RE = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=\s*(['\"])")


def iter_candidates(text: str):
    """Yield (offset, text) for each connection-string-shaped chunk in text."""
    for match in URL_TOKEN_RE.finditer(text):
        token = match.group(0).rstrip(".,;\"')")
        scheme = token.split("://", 1)[0].lower()
        base_scheme = scheme[5:] if scheme.startswith("jdbc:") else scheme
        if base_scheme in KNOWN_URL_SCHEMES:
            yield match.start(), token

    for match in CANDIDATE_KV_RE.finditer(text):
        yield match.start(), match.group(0)


def _quote_closes(text: str, quote: str) -> bool:
    """True if an unescaped `quote` appears somewhere in text."""
    escaped = False
    for char in text:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return True
    return False


def merge_env_continuations(lines):
    """Join KEY="...\\n...\\n..." style .env values that span physical
    lines into a single logical block, so a connection string that was
    wrapped across lines for readability is still seen as one candidate.

    Yields (start_line_no, text) pairs. Lines that aren't part of an
    unterminated quoted assignment pass through unchanged, one at a time.
    """
    count = len(lines)
    i = 0
    while i < count:
        line = lines[i].rstrip("\n")
        start_no = i + 1
        match = ENV_ASSIGNMENT_RE.match(line)
        if match and not _quote_closes(line[match.end():], match.group(1)):
            quote = match.group(1)
            buffer = [line]
            i += 1
            while i < count:
                cont = lines[i].rstrip("\n")
                buffer.append(cont)
                i += 1
                if _quote_closes(cont, quote):
                    break
            yield start_no, "\n".join(buffer)
        else:
            yield start_no, line
            i += 1


def _locate(start_no: int, text: str, offset: int):
    """Map a character offset within a (possibly multi-line) block back
    to the actual (line_no, column) it came from."""
    line_no = start_no
    line_start = 0
    for part in text.split("\n"):
        line_end = line_start + len(part)
        if offset <= line_end:
            return line_no, offset - line_start + 1
        line_start = line_end + 1  # +1 for the '\n' that joined the lines
        line_no += 1
    return line_no, offset - line_start + 1


def scan_file(path: str):
    """Yield (line_no, column, finding) for a single file."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except OSError as exc:
        print(f"{path}: could not read file ({exc})", file=sys.stderr)
        return

    if os.path.splitext(path)[1].lower() == ".env":
        blocks = merge_env_continuations(lines)
    else:
        blocks = ((i + 1, line.rstrip("\n")) for i, line in enumerate(lines))

    for start_no, text in blocks:
        for offset, candidate in iter_candidates(text):
            conn = parse(candidate)
            if conn is None:
                continue
            line_no, column = _locate(start_no, text, offset)
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
