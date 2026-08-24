import hmac
import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class MetadataStore:
    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                key_hash TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                manifest TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS wrapped_keys (
                file_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                wrapped_key TEXT NOT NULL,
                PRIMARY KEY (file_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS acl (
                user_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                permission TEXT NOT NULL,
                PRIMARY KEY (user_id, file_id)
            );
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                file_id TEXT,
                action TEXT NOT NULL,
                timestamp REAL NOT NULL,
                source_ip TEXT NOT NULL,
                bytes_transferred INTEGER NOT NULL DEFAULT 0,
                success INTEGER NOT NULL DEFAULT 1,
                anomaly_score REAL,
                flagged INTEGER NOT NULL DEFAULT 0
            );
            """)
        self._conn.commit()

    # --- users ---

    def create_user(self, user_id: str, key_hash: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO users (user_id, key_hash, created_at) VALUES (?, ?, ?)",
            (user_id, key_hash, time.time()),
        )
        self._conn.commit()

    def verify_user(self, user_id: str, api_key: str) -> bool:
        from metadata_service.auth import hash_key

        row = self._conn.execute(
            "SELECT key_hash FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        return row is not None and hmac.compare_digest(
            row["key_hash"], hash_key(api_key)
        )

    # --- files ---

    def create_file(
        self, file_id: str, owner_id: str, manifest: dict[str, Any], signature: str
    ) -> None:
        self._conn.execute(
            "INSERT INTO files (file_id, owner_id, manifest, signature, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (file_id, owner_id, json.dumps(manifest), signature, time.time()),
        )
        self._conn.commit()

    def get_file(self, file_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM files WHERE file_id = ?", (file_id,)
        ).fetchone()
        if row is None:
            return None
        return {
            "file_id": row["file_id"],
            "owner_id": row["owner_id"],
            "manifest": json.loads(row["manifest"]),
            "manifest_raw": row["manifest"],
            "signature": row["signature"],
        }

    # --- keys / acl ---

    def set_wrapped_key(self, file_id: str, user_id: str, wrapped_key: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO wrapped_keys (file_id, user_id, wrapped_key) VALUES (?, ?, ?)",
            (file_id, user_id, wrapped_key),
        )
        self._conn.commit()

    def get_wrapped_key(self, file_id: str, user_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT wrapped_key FROM wrapped_keys WHERE file_id = ? AND user_id = ?",
            (file_id, user_id),
        ).fetchone()
        return row["wrapped_key"] if row else None

    def grant_permission(self, user_id: str, file_id: str, permission: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO acl (user_id, file_id, permission) VALUES (?, ?, ?)",
            (user_id, file_id, permission),
        )
        self._conn.commit()

    def get_permission(self, user_id: str, file_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT permission FROM acl WHERE user_id = ? AND file_id = ?",
            (user_id, file_id),
        ).fetchone()
        return row["permission"] if row else None

    # --- access log / anomaly ---

    def log_access(
        self,
        user_id: str,
        file_id: str | None,
        action: str,
        source_ip: str,
        bytes_transferred: int,
        success: bool,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO access_log "
            "(user_id, file_id, action, timestamp, source_ip, bytes_transferred, success) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                user_id,
                file_id,
                action,
                time.time(),
                source_ip,
                bytes_transferred,
                int(success),
            ),
        )
        self._conn.commit()
        assert cur.lastrowid is not None
        return cur.lastrowid

    def recent_events(self, user_id: str, window_seconds: int) -> list[dict[str, Any]]:
        since = time.time() - window_seconds
        rows = self._conn.execute(
            "SELECT * FROM access_log WHERE user_id = ? AND timestamp >= ? ORDER BY timestamp DESC",
            (user_id, since),
        ).fetchall()
        return [dict(r) for r in rows]

    def update_flag(self, log_id: int, score: float, flagged: bool) -> None:
        self._conn.execute(
            "UPDATE access_log SET anomaly_score = ?, flagged = ? WHERE id = ?",
            (score, int(flagged), log_id),
        )
        self._conn.commit()

    def list_flagged(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM access_log WHERE flagged = 1 ORDER BY timestamp DESC"
        ).fetchall()
        return [dict(r) for r in rows]
