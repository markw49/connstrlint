"""Checks run against a parsed ConnectionString.

Each rule takes a ConnectionString and returns a list of Findings.
Keep new rules cheap and independent of each other - the CLI just
runs the whole list and reports whatever comes back.
"""

import re
from dataclasses import dataclass

from .parser import ConnectionString

PLACEHOLDER_RE = re.compile(
    r"^\$\{.*\}$|^%.*%$|^\$\w+$|^<.*>$|^\.\.\.$", re.IGNORECASE
)

DEFAULT_ACCOUNTS = {"sa", "root", "admin", "administrator", "postgres"}

SSL_SCHEMES = {
    "postgres",
    "postgresql",
    "mysql",
    "mongodb",
    "mongodb+srv",
    "redis",
    "amqp",
    "sqlserver",
}

SSL_OPTION_KEYS = {"sslmode", "ssl", "tls", "ssl_mode", "require_ssl"}


@dataclass
class Finding:
    rule_id: str
    severity: str  # "error", "warning", or "info"
    message: str


def _looks_like_placeholder(value: str) -> bool:
    if not value:
        return False
    if PLACEHOLDER_RE.match(value.strip()):
        return True
    # ALL_CAPS_WITH_UNDERSCORES reads as an env var name someone forgot
    # to substitute, not a literal secret.
    return bool(re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", value.strip()))


def rule_plaintext_password(conn: ConnectionString):
    if conn.password and not _looks_like_placeholder(conn.password):
        return [
            Finding(
                "CS001",
                "warning",
                "password is stored in plain text in the connection string",
            )
        ]
    return []


def rule_empty_password(conn: ConnectionString):
    if conn.user and conn.password == "":
        return [
            Finding(
                "CS002",
                "info",
                f"user '{conn.user}' is set with an empty password",
            )
        ]
    return []


def rule_missing_ssl(conn: ConnectionString):
    if conn.style == "url":
        base_scheme = (conn.scheme or "").replace("jdbc:", "")
        if base_scheme not in SSL_SCHEMES:
            return []
        if any(k in conn.options for k in SSL_OPTION_KEYS):
            return []
    else:
        if conn.host is None:
            return []
        if any(k in conn.options for k in SSL_OPTION_KEYS | {"encrypt"}):
            return []

    return [
        Finding(
            "CS003",
            "warning",
            "no SSL/TLS option set - traffic may be sent unencrypted",
        )
    ]


def rule_trust_server_certificate(conn: ConnectionString):
    value = conn.options.get("trustservercertificate") or conn.options.get(
        "trust server certificate"
    )
    if value and value.strip().lower() in {"true", "yes", "1"}:
        return [
            Finding(
                "CS004",
                "error",
                "TrustServerCertificate is enabled, which skips certificate "
                "validation and allows man-in-the-middle attacks",
            )
        ]
    return []


def rule_default_account(conn: ConnectionString):
    if conn.user and conn.user.strip().lower() in DEFAULT_ACCOUNTS:
        return [
            Finding(
                "CS005",
                "info",
                f"'{conn.user}' is a default/administrative account name",
            )
        ]
    return []


ALL_RULES = (
    rule_plaintext_password,
    rule_empty_password,
    rule_missing_ssl,
    rule_trust_server_certificate,
    rule_default_account,
)


def run_rules(conn: ConnectionString):
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(conn))
    return findings
