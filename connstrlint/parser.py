"""Parsing for the two connection string shapes we see in the wild:

- URL style: postgres://user:pass@host:5432/dbname?sslmode=require
- key/value style: Server=host;Database=db;User Id=u;Password=p;Encrypt=yes

Both get normalized into a single ConnectionString so the rules only
have to know about one shape.
"""

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit, parse_qsl, unquote

USER_KEYS = {"user id", "uid", "user", "username", "user name"}
PASSWORD_KEYS = {"password", "pwd"}
HOST_KEYS = {"server", "data source", "host", "address", "addr", "network address"}
PORT_KEYS = {"port"}
DATABASE_KEYS = {"database", "initial catalog", "db"}


@dataclass
class ConnectionString:
    raw: str
    style: str  # "url" or "kv"
    scheme: Optional[str] = None
    user: Optional[str] = None
    password: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    database: Optional[str] = None
    options: dict = field(default_factory=dict)


def parse_url(raw: str) -> Optional[ConnectionString]:
    marker = raw.split("://", 1)[0].lower()
    is_jdbc = marker.startswith("jdbc:")
    target = raw[5:] if is_jdbc else raw

    try:
        parts = urlsplit(target)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None

    try:
        port = parts.port
    except ValueError:
        port = None

    options = {k.lower(): v for k, v in parse_qsl(parts.query)}
    scheme = ("jdbc:" + parts.scheme) if is_jdbc else parts.scheme

    return ConnectionString(
        raw=raw,
        style="url",
        scheme=scheme,
        user=unquote(parts.username) if parts.username else None,
        password=unquote(parts.password) if parts.password else None,
        host=parts.hostname,
        port=port,
        database=(parts.path.lstrip("/") or None),
        options=options,
    )


def parse_keyvalue(raw: str) -> Optional[ConnectionString]:
    pairs = [p for p in raw.strip().rstrip(";").split(";") if p.strip()]
    if len(pairs) < 2:
        return None

    options = {}
    for pair in pairs:
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        options[key.strip().lower()] = value.strip().strip('"').strip("'")

    if not options:
        return None

    user = password = host = database = None
    port = None
    for key in list(options):
        if key in USER_KEYS:
            user = options.pop(key)
        elif key in PASSWORD_KEYS:
            password = options.pop(key)
        elif key in HOST_KEYS:
            host = options.pop(key)
        elif key in PORT_KEYS:
            try:
                port = int(options.pop(key))
            except ValueError:
                options.pop(key)
        elif key in DATABASE_KEYS:
            database = options.pop(key)

    if user is None and host is None and database is None:
        return None

    return ConnectionString(
        raw=raw,
        style="kv",
        user=user,
        password=password,
        host=host,
        port=port,
        database=database,
        options=options,
    )


def parse(raw: str) -> Optional[ConnectionString]:
    raw = raw.strip()
    if "://" in raw.split(" ", 1)[0]:
        return parse_url(raw)
    return parse_keyvalue(raw)
