# connstrlint

Connection strings end up committed to `.env` files, dropped into `appsettings.json`,
pasted into a Kubernetes ConfigMap, or left in a shell script "just for now." They carry
a password, a hostname, and often a setting that quietly turns off certificate checking.
Nobody reviews them line by line, because they don't look like code.

connstrlint scans plain files for anything shaped like a connection string - a URL like
`postgres://user:pass@host/db` or a key/value string like `Server=...;Password=...;` -
and reports what it finds, with a file, line, and column, so you can point at the exact
spot in a review.

## Install

No install step needed yet - it's a single package with no dependencies. Either run it
from a checkout:

```
python -m connstrlint path/to/config
```

or install it locally:

```
pip install -e .
connstrlint path/to/config
```

## Usage

Given a file `settings.ini`:

```ini
[database]
primary = postgres://app_user:changeme123@db.internal:5432/orders
legacy = Server=sqlsrv01;Database=orders;User Id=sa;Password=changeme123;TrustServerCertificate=true;
```

Running:

```
$ connstrlint settings.ini
settings.ini:2:11: [WARNING] CS001 password is stored in plain text in the connection string
settings.ini:2:11: [WARNING] CS003 no SSL/TLS option set - traffic may be sent unencrypted
settings.ini:2:11: [INFO] CS006 host is exposed on the default postgres port (5432) - it's the first port an automated scanner probes
settings.ini:3:10: [WARNING] CS001 password is stored in plain text in the connection string
settings.ini:3:10: [WARNING] CS003 no SSL/TLS option set - traffic may be sent unencrypted
settings.ini:3:10: [ERROR] CS004 TrustServerCertificate is enabled, which skips certificate validation and allows man-in-the-middle attacks
settings.ini:3:10: [INFO] CS005 'sa' is a default/administrative account name

7 finding(s)
```

Point it at a directory and it walks it, scanning files with common config extensions
(`.env`, `.ini`, `.cfg`, `.conf`, `.config`, `.yaml`, `.yml`, `.json`, `.txt`,
`.properties`, `.xml`). Pass a specific file directly and it's scanned regardless of
extension.

By default the process exits `1` if any finding is severity `error`, `0` otherwise, so
it can be wired into CI as a gate on the errors while leaving warnings and info as
visible noise. `--fail-on info|warning|error` moves that threshold (a finding at or
above it fails the run), and `--fail-on none` always exits `0`.

Pass `--format json` to get findings as a JSON array instead, one object per finding
with `path`, `line`, `column`, `rule_id`, `severity`, and `message` keys - useful for
feeding into another tool rather than reading in a terminal:

```
$ connstrlint --format json settings.ini
[
  {
    "path": "settings.ini",
    "line": 2,
    "column": 11,
    "rule_id": "CS001",
    "severity": "warning",
    "message": "password is stored in plain text in the connection string"
  },
  ...
]
```

## Rules

| ID    | Severity | Checks for |
|-------|----------|------------|
| CS001 | warning  | password written in plain text rather than an env var or placeholder |
| CS002 | info     | a user name set with an empty password |
| CS003 | warning  | no SSL/TLS related option set on a connection string that supports one |
| CS004 | error    | `TrustServerCertificate=true` (or equivalent), which disables certificate validation |
| CS005 | info     | a default/administrative account name (`sa`, `root`, `admin`, ...) |
| CS006 | info     | a URL-style connection left on the scheme's default port (5432 for postgres, 3306 for mysql, 27017 for mongodb, ...) |

A value is treated as a placeholder rather than a real secret if it looks like
`${DB_PASSWORD}`, `%DB_PASSWORD%`, `$DB_PASSWORD`, `<password>`, or an
`ALL_CAPS_ENV_VAR_NAME`.

## Supported formats

- URL style connection strings for postgres, mysql, mongodb (including `mongodb+srv`),
  redis, amqp, sqlserver, oracle, ldap, and `jdbc:` prefixed variants of those.
- Key/value style strings (ODBC, ADO.NET, and similar), matched on keys like `Server`,
  `Database`, `User Id`, `Password`, `Encrypt`, `TrustServerCertificate`.

## Limitations

This is a line-scanning heuristic, not a real parser for every config file format - it
does not understand YAML/JSON structure, so a connection string split across multiple
keys won't be reassembled. It also only looks at what a regex can find on a single
line, with one exception: in `.env` files, a quoted value that opens on one line and
closes on a later one (`CONN="Server=...;\nPassword=...;"`) is joined before scanning,
since that's a common way long ADO.NET/ODBC strings end up formatted in `.env` files.
Good enough to catch what's actually in the file; not a guarantee nothing was missed.

## Tests

```
python -m unittest discover
```

## License

MIT, see [LICENSE](LICENSE).
