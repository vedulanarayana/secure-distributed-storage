from typing import Any

import httpx

from client.chunker import DEFAULT_CHUNK_SIZE, chunk_bytes, hash_ciphertext
from client.crypto import decrypt_chunk, encrypt_chunk, generate_file_key
from client.manifest import build_manifest, sign_manifest


class StorageCluster:
    """Replicates each chunk across the storage nodes and reads back from whichever answers first.

    No erasure coding or striping here on purpose: three-way replication with
    a write quorum is the simplest thing that survives a single node being
    down, which is all this project needs to demonstrate.
    """

    def __init__(
        self,
        node_urls: list[str],
        client: httpx.Client | None = None,
        verify: bool | str = True,
    ):
        self.node_urls = node_urls
        self.client = client or httpx.Client(verify=verify, timeout=30.0)

    def put_chunk(self, chunk_hash: str, ciphertext: bytes, quorum: int = 2) -> int:
        successes = 0
        for base_url in self.node_urls:
            try:
                resp = self.client.put(
                    f"{base_url}/chunks/{chunk_hash}", content=ciphertext
                )
                if resp.status_code == 200:
                    successes += 1
            except httpx.HTTPError:
                continue
        if successes < quorum:
            raise RuntimeError(
                f"failed to replicate chunk {chunk_hash} to a quorum of storage nodes "
                f"({successes}/{quorum})"
            )
        return successes

    def get_chunk(self, chunk_hash: str) -> bytes:
        for base_url in self.node_urls:
            try:
                resp = self.client.get(f"{base_url}/chunks/{chunk_hash}")
                if resp.status_code == 200:
                    return resp.content
            except httpx.HTTPError:
                continue
        raise RuntimeError(f"chunk {chunk_hash} not available on any storage node")


def upload_file(
    data: bytes,
    file_id: str,
    hmac_key: bytes,
    cluster: StorageCluster,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[dict[str, Any], str, bytes]:
    file_key = generate_file_key()
    chunk_hashes: list[str] = []
    chunk_nonces: list[str] = []
    chunk_sizes: list[int] = []

    for plaintext_chunk in chunk_bytes(data, chunk_size):
        nonce, ciphertext = encrypt_chunk(file_key, plaintext_chunk)
        chunk_hash = hash_ciphertext(ciphertext)
        cluster.put_chunk(chunk_hash, ciphertext)
        chunk_hashes.append(chunk_hash)
        chunk_nonces.append(nonce.hex())
        chunk_sizes.append(len(plaintext_chunk))

    manifest = build_manifest(file_id, chunk_hashes, chunk_nonces, chunk_sizes)
    signature = sign_manifest(hmac_key, manifest)
    return manifest, signature, file_key


def download_file(
    manifest: dict[str, Any], file_key: bytes, cluster: StorageCluster
) -> bytes:
    parts = []
    for chunk in sorted(manifest["chunks"], key=lambda c: c["index"]):
        ciphertext = cluster.get_chunk(chunk["hash"])
        nonce = bytes.fromhex(chunk["nonce"])
        parts.append(decrypt_chunk(file_key, nonce, ciphertext))
    return b"".join(parts)
