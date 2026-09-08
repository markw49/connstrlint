"""connstrlint - find and lint database connection strings in plain files."""

__version__ = "0.1.0"

from .parser import ConnectionString, parse  # noqa: F401
