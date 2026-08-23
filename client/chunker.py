import hashlib
from collections.abc import Iterator
from pathlib import Path

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024


def chunk_file(
    path: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Iterator[bytes]:
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            yield data


def chunk_bytes(data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[bytes]:
    for offset in range(0, len(data), chunk_size):
        yield data[offset : offset + chunk_size]


def hash_ciphertext(ciphertext: bytes) -> str:
    """Content address is the hash of the ciphertext, never the plaintext.

    Storage nodes only ever see ciphertext, and since each chunk is
    encrypted with a random nonce, this hash cannot be used to confirm a
    guess about the plaintext (no dictionary/offline attack on content
    addresses).
    """
    return hashlib.sha256(ciphertext).hexdigest()
