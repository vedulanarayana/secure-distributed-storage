"""End-to-end demo: alice uploads a file, shares it with bob, bob downloads and decrypts it.

Requires the storage nodes and metadata service to be running locally
(see scripts/run_local.sh):

    ./scripts/run_local.sh &
    python scripts/demo.py
"""

import os
import uuid

import httpx

from client.keywrap import generate_keypair, unwrap_key, wrap_key
from client.metadata_client import MetadataClient
from client.uploader import StorageCluster, download_file, upload_file

HMAC_SECRET = os.environ.get(
    "METADATA_HMAC_SECRET", "dev-only-shared-hmac-secret-change-me"
).encode()
METADATA_URL = os.environ.get("METADATA_URL", "http://127.0.0.1:9000")
STORAGE_NODES = os.environ.get(
    "STORAGE_NODES", "http://127.0.0.1:9001,http://127.0.0.1:9002,http://127.0.0.1:9003"
).split(",")

# Only relevant when the services are reached over https:// (e.g. the
# docker-compose TLS setup); ignored for the plain-HTTP run_local.sh flow.
# Points at the self-signed dev cert so connections are actually verified
# against it instead of skipping certificate validation entirely.
TLS_CA_CERT = os.environ.get("TLS_CA_CERT", "certs/dev-cert.pem")
VERIFY: bool | str = TLS_CA_CERT if os.path.exists(TLS_CA_CERT) else True


def main() -> None:
    cluster = StorageCluster(STORAGE_NODES, verify=VERIFY)
    bootstrap = MetadataClient(
        METADATA_URL, user_id="bootstrap", api_key="unused", verify=VERIFY
    )

    alice_key = bootstrap.create_user("alice")
    bob_key = bootstrap.create_user("bob")
    alice = MetadataClient(METADATA_URL, "alice", alice_key, verify=VERIFY)
    bob = MetadataClient(METADATA_URL, "bob", bob_key, verify=VERIFY)

    bob_private, bob_public = generate_keypair()

    payload = b"quarterly financial report - confidential\n" * 100_000
    file_id = str(uuid.uuid4())

    manifest, signature, file_key = upload_file(payload, file_id, HMAC_SECRET, cluster)
    alice.register_file(file_id, manifest, signature)
    print(f"alice uploaded file {file_id} in {len(manifest['chunks'])} chunk(s)")

    wrapped_key_for_bob = wrap_key(bob_public, file_key)
    alice.share(file_id, "bob", wrapped_key_for_bob, permission="read")
    print("alice shared the file with bob")

    fetched, headers = bob.get_manifest(file_id)
    if headers.get("x-step-up-required") == "true":
        print("anomaly layer flagged this access - would prompt bob for step-up auth")

    wrapped_key = bob.get_wrapped_key(file_id, "bob")
    bob_file_key = unwrap_key(bob_private, wrapped_key)

    recovered = download_file(fetched["manifest"], bob_file_key, cluster)
    assert recovered == payload, "downloaded content did not match the original file"
    print("bob downloaded and decrypted the file successfully")

    try:
        eve_key = bootstrap.create_user("eve")
        eve = MetadataClient(METADATA_URL, "eve", eve_key, verify=VERIFY)
        eve.get_manifest(file_id)
        print("UNEXPECTED: eve was able to read the manifest")
    except httpx.HTTPStatusError:
        print("eve (no ACL entry) was correctly denied access to the manifest")


if __name__ == "__main__":
    main()
