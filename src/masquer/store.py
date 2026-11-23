"""Per-case mapping store: original value <-> token, in SQLite (mode 600).

Tokens look like «KIND_0001». The same original (case-insensitive) always
gets the same token within a case; nothing is shared across cases.
"""
from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

TOKEN_RE = re.compile(r"«([A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*)_(\d{4,})»")

SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
  kind     TEXT NOT NULL,
  norm     TEXT NOT NULL,
  original TEXT NOT NULL,
  token    TEXT NOT NULL UNIQUE,
  PRIMARY KEY (kind, norm)
);
CREATE TABLE IF NOT EXISTS counters (kind TEXT PRIMARY KEY, n INTEGER NOT NULL);
"""


class Store:
    def __init__(self, path: Path | None):
        if path is None:  # in-memory scratch copy
            self.db = sqlite3.connect(":memory:")
        else:
            if not path.exists():
                fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
                os.close(fd)
            os.chmod(path, 0o600)
            self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)
        self._cache: dict[tuple[str, str], str] = {
            (k, n): t for k, n, t in self.db.execute("SELECT kind, norm, token FROM tokens")
        }
        self._by_norm: dict[str, str] = {n: t for (_, n), t in self._cache.items()}

    @staticmethod
    def norm(value: str) -> str:
        return value.strip().casefold()

    def token(self, kind: str, value: str) -> str:
        """Token for value; created on first sight. A value already known under
        another kind keeps its first token, so one original has one token."""
        n = self.norm(value)
        hit = self._by_norm.get(n)
        if hit:
            return hit
        row = self.db.execute("SELECT n FROM counters WHERE kind = ?", (kind,)).fetchone()
        num = (row[0] if row else 0) + 1
        self.db.execute("INSERT OR REPLACE INTO counters (kind, n) VALUES (?, ?)", (kind, num))
        tok = f"«{kind}_{num:04d}»"
        self.db.execute("INSERT INTO tokens (kind, norm, original, token) VALUES (?, ?, ?, ?)",
                        (kind, n, value.strip(), tok))
        self._cache[(kind, n)] = tok
        self._by_norm[n] = tok
        return tok

    def scratch(self) -> "Store":
        """In-memory copy for checks that must not add tokens to the case."""
        s = Store(None)
        s.db.executemany("INSERT INTO tokens VALUES (?, ?, ?, ?)",
                         self.db.execute("SELECT kind, norm, original, token FROM tokens"))
        s.db.executemany("INSERT INTO counters VALUES (?, ?)", self.db.execute("SELECT kind, n FROM counters"))
        s._cache = dict(self._cache)
        s._by_norm = dict(self._by_norm)
        return s

    def originals(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT original FROM tokens")]

    def lookup(self) -> dict[str, str]:
        """token -> original"""
        return dict(self.db.execute("SELECT token, original FROM tokens"))

    def commit(self) -> None:
        self.db.commit()

    def close(self) -> None:
        self.db.commit()
        self.db.close()
