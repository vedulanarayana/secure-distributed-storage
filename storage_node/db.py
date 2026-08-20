import sqlite3
from pathlib import Path


class ChunkStore:
    """Content-addressed blob store backed by SQLite. Never sees plaintext or keys."""

    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS chunks ("
            "hash TEXT PRIMARY KEY, data BLOB NOT NULL, size INTEGER NOT NULL)"
        )
        self._conn.commit()

    def put(self, chunk_hash: str, data: bytes) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO chunks (hash, data, size) VALUES (?, ?, ?)",
            (chunk_hash, data, len(data)),
        )
        self._conn.commit()

    def get(self, chunk_hash: str) -> bytes | None:
        row = self._conn.execute(
            "SELECT data FROM chunks WHERE hash = ?", (chunk_hash,)
        ).fetchone()
        return row[0] if row else None

    def exists(self, chunk_hash: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM chunks WHERE hash = ?", (chunk_hash,)
        ).fetchone()
        return row is not None
