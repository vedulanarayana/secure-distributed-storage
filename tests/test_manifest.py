from client.manifest import build_manifest, sign_manifest, verify_manifest


def test_signature_round_trip():
    key = b"a-hmac-secret"
    manifest = build_manifest("file-1", ["h1", "h2"], ["n1", "n2"], [10, 20])
    signature = sign_manifest(key, manifest)
    assert verify_manifest(key, manifest, signature)


def test_tampered_manifest_fails_verification():
    key = b"a-hmac-secret"
    manifest = build_manifest("file-1", ["h1", "h2"], ["n1", "n2"], [10, 20])
    signature = sign_manifest(key, manifest)
    manifest["chunks"][0]["hash"] = "tampered-hash"
    assert not verify_manifest(key, manifest, signature)


def test_wrong_key_fails_verification():
    manifest = build_manifest("file-1", ["h1"], ["n1"], [10])
    signature = sign_manifest(b"key-a", manifest)
    assert not verify_manifest(b"key-b", manifest, signature)
