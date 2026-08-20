import hashlib
import hmac
import json
import time
from typing import Any


def build_manifest(
    file_id: str,
    chunk_hashes: list[str],
    chunk_nonces: list[str],
    chunk_sizes: list[int],
) -> dict[str, Any]:
    return {
        "file_id": file_id,
        "version": 1,
        "created_at": time.time(),
        "chunks": [
            {"index": i, "hash": h, "nonce": n, "size": s}
            for i, (h, n, s) in enumerate(zip(chunk_hashes, chunk_nonces, chunk_sizes))
        ],
    }


def _canonical_bytes(manifest: dict[str, Any]) -> bytes:
    body = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_manifest(hmac_key: bytes, manifest: dict[str, Any]) -> str:
    return hmac.new(hmac_key, _canonical_bytes(manifest), hashlib.sha256).hexdigest()


def verify_manifest(hmac_key: bytes, manifest: dict[str, Any], signature: str) -> bool:
    expected = sign_manifest(hmac_key, manifest)
    return hmac.compare_digest(expected, signature)
