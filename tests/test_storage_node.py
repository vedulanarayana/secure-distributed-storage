import hashlib

from fastapi.testclient import TestClient

from storage_node.app import create_app


def make_client(tmp_path):
    app = create_app(node_id="test-node", db_path=str(tmp_path / "node.db"))
    return TestClient(app)


def test_put_and_get_chunk(tmp_path):
    client = make_client(tmp_path)
    data = b"ciphertext-bytes"
    chunk_hash = hashlib.sha256(data).hexdigest()

    put_resp = client.put(f"/chunks/{chunk_hash}", content=data)
    assert put_resp.status_code == 200

    get_resp = client.get(f"/chunks/{chunk_hash}")
    assert get_resp.status_code == 200
    assert get_resp.content == data


def test_put_rejects_hash_mismatch(tmp_path):
    client = make_client(tmp_path)
    data = b"ciphertext-bytes"
    wrong_hash = hashlib.sha256(b"different-bytes").hexdigest()

    resp = client.put(f"/chunks/{wrong_hash}", content=data)
    assert resp.status_code == 400


def test_get_missing_chunk_returns_404(tmp_path):
    client = make_client(tmp_path)
    resp = client.get(f"/chunks/{'0' * 64}")
    assert resp.status_code == 404
