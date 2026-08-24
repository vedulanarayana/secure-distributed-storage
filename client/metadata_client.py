from typing import Any

import httpx


class MetadataClient:
    """Thin REST wrapper around the metadata service for the demo and integration flows."""

    def __init__(
        self,
        base_url: str,
        user_id: str,
        api_key: str,
        client: httpx.Client | None = None,
        verify: bool | str = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = {"X-User-Id": user_id, "X-Api-Key": api_key}
        self.client = client or httpx.Client(verify=verify, timeout=30.0)

    def create_user(self, user_id: str) -> str:
        resp = self.client.post(f"{self.base_url}/users", json={"user_id": user_id})
        resp.raise_for_status()
        return resp.json()["api_key"]

    def register_file(
        self, file_id: str, manifest: dict[str, Any], signature: str
    ) -> None:
        resp = self.client.post(
            f"{self.base_url}/files",
            json={"file_id": file_id, "manifest": manifest, "signature": signature},
            headers=self.headers,
        )
        resp.raise_for_status()

    def share(
        self, file_id: str, user_id: str, wrapped_key: bytes, permission: str = "read"
    ) -> None:
        resp = self.client.post(
            f"{self.base_url}/files/{file_id}/share",
            json={
                "user_id": user_id,
                "wrapped_key": wrapped_key.hex(),
                "permission": permission,
            },
            headers=self.headers,
        )
        resp.raise_for_status()

    def get_manifest(self, file_id: str) -> tuple[dict[str, Any], dict[str, str]]:
        resp = self.client.get(
            f"{self.base_url}/files/{file_id}/manifest", headers=self.headers
        )
        resp.raise_for_status()
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.json(), headers

    def get_wrapped_key(self, file_id: str, user_id: str) -> bytes:
        resp = self.client.get(
            f"{self.base_url}/files/{file_id}/keys/{user_id}", headers=self.headers
        )
        resp.raise_for_status()
        return bytes.fromhex(resp.json()["wrapped_key"])
