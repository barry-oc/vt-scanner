"""SQLite-based hash cache — avoids re-checking unchanged files on VT."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    hash       TEXT NOT NULL,
    algorithm  TEXT NOT NULL DEFAULT 'sha256',
    mtime      REAL NOT NULL,
    path       TEXT NOT NULL,
    result     TEXT,
    checked_at REAL NOT NULL,
    PRIMARY KEY (hash, algorithm)
);

CREATE INDEX IF NOT EXISTS idx_cache_path ON cache(path);
CREATE INDEX IF NOT EXISTS idx_cache_hash ON cache(hash);
"""


class HashCache:
    """Persistent cache mapping (hash, algorithm) → VT result.

    Also tracks file mtime so we know when a file changed without
    re-hashing unless necessary.
    """

    def __init__(self, db_path: Path | str = "~/.vt_cache.db"):
        self.db_path = Path(db_path).expanduser()
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(CACHE_SCHEMA)
            self._conn.commit()
        return self._conn

    def get(self, file_hash: str, algorithm: str = "sha256") -> dict[str, Any] | None:
        """Look up a cached VT result by hash. Returns None if not found."""
        row = self.conn.execute(
            "SELECT result, checked_at FROM cache WHERE hash=? AND algorithm=?",
            (file_hash, algorithm),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def set(self, file_hash: str, result: dict[str, Any], path: str = "", mtime: float = 0.0, algorithm: str = "sha256") -> None:
        """Store a VT result in the cache."""
        self.conn.execute(
            "INSERT OR REPLACE INTO cache (hash, algorithm, mtime, path, result, checked_at) VALUES (?,?,?,?,?,?)",
            (file_hash, algorithm, mtime, path, json.dumps(result), time.time()),
        )
        self.conn.commit()

    def lookup_by_path(self, path: str, current_mtime: float, algorithm: str = "sha256") -> tuple[str, dict[str, Any] | None] | None:
        """Check if a file at path with the given mtime has a cached hash.

        Returns (hash, VT_result) if cached and mtime matches, or None if stale.
        """
        row = self.conn.execute(
            "SELECT hash, result FROM cache WHERE path=? AND mtime=? AND algorithm=?",
            (path, current_mtime, algorithm),
        ).fetchone()
        if row is None:
            return None
        return (row[0], json.loads(row[1]))

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None