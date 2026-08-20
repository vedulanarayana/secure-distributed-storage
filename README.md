# secure-distributed-storage

A zero-trust, end-to-end encrypted distributed file storage system with
client-side hybrid cryptography (AES-GCM-256 / RSA-4096), content-addressable
chunking, and access-pattern anomaly detection.

Storage nodes and the metadata service never see plaintext, never see keys,
and only ever store or forward bytes they can verify by hash. All
cryptographic work (encryption, key wrapping, hashing, signing) happens on
the client before anything leaves the machine.

## Architecture

```
Client
  |-- Chunk file (4MB blocks, plaintext)
  |-- Encrypt each chunk (AES-GCM-256, random nonce per chunk)
  |-- Hash the CIPHERTEXT (SHA-256) -> this is the storage address
  |-- Wrap AES file key with recipient RSA-4096 public key
  |-- HMAC-sign the manifest (ordered list of chunk hashes)
  `-- Upload chunks + signed manifest over TLS

Storage Nodes (3 independent FastAPI + SQLite processes)
  |-- On PUT: recompute SHA-256 of received ciphertext, reject on mismatch
  |-- Store by content hash, never see plaintext or keys
  `-- Serve chunk-by-hash on GET

Metadata Service (FastAPI + SQLite)
  |-- file_id -> manifest (ordered chunk hashes, HMAC signature)
  |-- file_id -> wrapped AES keys per authorized user (RSA-wrapped)
  |-- ACL: user_id -> {file_id: permission}
  `-- Access log: every request, scored for anomalies

Anomaly Detection Layer
  |-- Logs every access (user_id, file_id, action, timestamp, source_ip, bytes_transferred)
  |-- Isolation Forest scores each request against a simulated normal-access baseline
  `-- Flags feed into the RBAC layer as a step-up-auth signal, not a silent block
```

## Why hash the ciphertext, not the plaintext

Each chunk is encrypted with a fresh random nonce, so two uploads of
identical plaintext never produce identical ciphertext. Content-addressing
by ciphertext hash means there is no collision/overwrite risk between
unrelated uploads that happen to contain the same bytes.

**Deliberate tradeoff:** this gives up cross-file deduplication. Two users
uploading the same file will store two independent copies. That's an
intentional simplicity-over-dedup choice for this project, not an oversight.

## Other stated simplifications

- **Manifest signing is HMAC, not a client signing keypair.** The metadata
  service and the client share one HMAC secret (`METADATA_HMAC_SECRET`).
  That's enough to catch accidental corruption or a tampered manifest in
  transit, but it is not non-repudiation: a party that already holds the
  shared secret (i.e. the metadata service itself) could forge a
  signature. A production version would have each client sign manifests
  with its own RSA/Ed25519 key instead.
- **Replication, not erasure coding.** Chunks are written to all three
  storage nodes with a write quorum of 2; there's no striping or parity.
  Good enough to survive one node being down, not a real durability
  scheme.
- **User provisioning (`POST /users`) is unauthenticated** in this
  reference implementation, to keep the demo self-contained. A real
  deployment would gate it behind an admin identity or a separate
  enrollment flow.

See `THREAT_MODEL.md` for the full writeup, including what the anomaly
layer does and does not catch.

## Components

1. `client/crypto.py` - AES-GCM-256 chunk encrypt/decrypt
2. `client/keywrap.py` - RSA-4096 key wrap/unwrap
3. `client/chunker.py` - plaintext chunking + ciphertext-hash content addressing
4. `client/manifest.py` - HMAC manifest signing/verification
5. `storage_node/` - FastAPI + SQLite chunk store, run as 3 instances via docker-compose
6. TLS - self-signed dev certs (`certs/gen_certs.sh`), used by docker-compose
7. `metadata_service/rbac.py` - RBAC enforced on both share (write) and manifest fetch (read) routes
8. `metadata_service/db.py` access log + `anomaly/` - Isolation Forest scoring service
9. `THREAT_MODEL.md` - what the anomaly layer catches vs. does not
10. `tests/` - tamper rejection, wrong-key decryption failure, RBAC denial, anomaly-flag trigger

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick-start demo (plain HTTP, no TLS)

```bash
./scripts/run_local.sh &
python scripts/demo.py
```

This starts the three storage nodes and the metadata service on
`localhost:9001-9003` and `:9000`, then runs an end-to-end scenario: alice
uploads a file, shares it with bob, bob downloads and decrypts it, and eve
(who was never granted access) is denied.

## Running with TLS via docker-compose

```bash
bash certs/gen_certs.sh
docker compose up --build
```

Each service serves over TLS using the generated self-signed dev
certificate; modern OpenSSL/Python `ssl` defaults negotiate TLS 1.3 when
both peers support it, so no additional flag is needed once certs are in
place.

## Running the tests

```bash
pytest
```

Covers: AES-GCM round trip and tamper/wrong-key rejection, RSA key wrap/
unwrap and wrong-key rejection, ciphertext-hash non-collision, manifest
signature tamper rejection, storage-node content-hash rejection, RBAC
allow/deny paths (owner, shared user, unauthorized user), and anomaly-model
flagging on a synthetic outlier access pattern.

## Anomaly detection - scope

"Real-time" here means each access event is scored synchronously against a
trained Isolation Forest as part of the request path - not a streaming
pipeline. The model is trained on a synthetic/simulated normal-access
dataset (`anomaly/train.py`) built to represent typical usage: a handful of
requests per session, mostly during business hours, moving a few hundred KB
to a few MB, with authentication that almost always succeeds. Flagged
events set `X-Step-Up-Required` on the response rather than blocking the
request outright, so a false positive doesn't lock out a legitimate user
with no recourse.
