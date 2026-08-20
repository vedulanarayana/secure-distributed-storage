from fastapi.testclient import TestClient

from client.manifest import build_manifest, sign_manifest
from metadata_service.app import create_app

HMAC_SECRET = b"test-hmac-secret"


def make_client(tmp_path):
    app = create_app(db_path=str(tmp_path / "metadata.db"), hmac_secret=HMAC_SECRET)
    return TestClient(app)


def create_user(client, user_id):
    resp = client.post("/users", json={"user_id": user_id})
    assert resp.status_code == 200
    return resp.json()["api_key"]


def auth_headers(user_id, api_key):
    return {"X-User-Id": user_id, "X-Api-Key": api_key}


def register_sample_file(client, owner_id, api_key, file_id="file-1"):
    manifest = build_manifest(file_id, ["h1"], ["n1"], [10])
    signature = sign_manifest(HMAC_SECRET, manifest)
    resp = client.post(
        "/files",
        json={"file_id": file_id, "manifest": manifest, "signature": signature},
        headers=auth_headers(owner_id, api_key),
    )
    assert resp.status_code == 200
    return manifest, signature


def test_owner_can_read_own_file(tmp_path):
    client = make_client(tmp_path)
    alice_key = create_user(client, "alice")
    register_sample_file(client, "alice", alice_key)

    resp = client.get("/files/file-1/manifest", headers=auth_headers("alice", alice_key))
    assert resp.status_code == 200


def test_unauthorized_user_is_denied(tmp_path):
    client = make_client(tmp_path)
    alice_key = create_user(client, "alice")
    eve_key = create_user(client, "eve")
    register_sample_file(client, "alice", alice_key)

    resp = client.get("/files/file-1/manifest", headers=auth_headers("eve", eve_key))
    assert resp.status_code == 403


def test_shared_user_can_read_after_grant(tmp_path):
    client = make_client(tmp_path)
    alice_key = create_user(client, "alice")
    bob_key = create_user(client, "bob")
    register_sample_file(client, "alice", alice_key)

    share_resp = client.post(
        "/files/file-1/share",
        json={"user_id": "bob", "wrapped_key": "deadbeef", "permission": "read"},
        headers=auth_headers("alice", alice_key),
    )
    assert share_resp.status_code == 200

    resp = client.get("/files/file-1/manifest", headers=auth_headers("bob", bob_key))
    assert resp.status_code == 200


def test_non_owner_cannot_share(tmp_path):
    client = make_client(tmp_path)
    alice_key = create_user(client, "alice")
    eve_key = create_user(client, "eve")
    register_sample_file(client, "alice", alice_key)

    resp = client.post(
        "/files/file-1/share",
        json={"user_id": "eve", "wrapped_key": "deadbeef", "permission": "read"},
        headers=auth_headers("eve", eve_key),
    )
    assert resp.status_code == 403


def test_invalid_credentials_rejected(tmp_path):
    client = make_client(tmp_path)
    create_user(client, "alice")
    resp = client.get("/files/file-1/manifest", headers=auth_headers("alice", "wrong-key"))
    assert resp.status_code == 401


def test_tampered_manifest_signature_rejected(tmp_path):
    client = make_client(tmp_path)
    alice_key = create_user(client, "alice")
    manifest = build_manifest("file-2", ["h1"], ["n1"], [10])
    bad_signature = sign_manifest(b"wrong-secret", manifest)
    resp = client.post(
        "/files",
        json={"file_id": "file-2", "manifest": manifest, "signature": bad_signature},
        headers=auth_headers("alice", alice_key),
    )
    assert resp.status_code == 400
