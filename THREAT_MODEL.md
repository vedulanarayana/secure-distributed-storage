# Threat Model

## Assets

- File plaintext and per-file AES keys
- RSA private keys (held only by end users, never uploaded)
- The HMAC secret used to sign/verify manifests
- Metadata (who has access to what)
- Availability of stored chunks

## Trust boundaries

- **Client** is trusted to handle plaintext and keys correctly. Everything
  cryptographic happens here before data leaves the machine.
- **Storage nodes** are untrusted for confidentiality: they only ever
  receive and serve ciphertext, addressed by its own hash. A fully
  compromised storage node can deny service or corrupt/withhold chunks,
  but cannot read file contents and cannot silently substitute a chunk
  without failing the hash check on the next read.
- **Metadata service** is trusted for availability and access control
  bookkeeping, but is explicitly *not* trusted to keep plaintext or file
  keys secret from itself, because it never receives either. It does hold
  RSA-wrapped keys (useless without the recipient's private key) and the
  HMAC secret (see limitation below).

## What each control catches

| Attack | Caught by |
| --- | --- |
| A storage node returns corrupted or substituted chunk data | Ciphertext hash check on GET (client re-hashes and compares to the manifest entry) and on PUT (node re-hashes and rejects on mismatch) |
| A manifest is altered in transit or at rest (chunk reordered, hash swapped) | HMAC signature verification, checked by the metadata service on upload |
| Wrong decryption key used, or ciphertext tampered with in a way that breaks the GCM tag | AES-GCM authenticated decryption fails closed |
| A user without an ACL entry tries to read a file's manifest or keys | RBAC check on every read/share route |
| A non-owner tries to grant access to others | RBAC `owner`-level check on the share route |
| A stolen-but-valid credential used unusually (e.g. an off-hours burst of downloads, or a normal user suddenly pulling far more data than usual) | Isolation Forest scoring on access-pattern features (request rate, off-hours flag, bytes transferred, recent failed-auth count); flags trigger a step-up-auth signal rather than a silent block |

## What the anomaly layer does *not* catch

- **A patient, slow-and-low attacker mimicking normal usage.** The model
  is trained on aggregate statistical features (rate, timing, volume,
  recent failures) over a rolling window. An attacker who paces requests
  to stay within the normal range - one file at a time, during business
  hours, small transfers - will not stand out from legitimate traffic.
  Catching that requires longer-horizon behavioral baselining per user
  (e.g. "this user has never touched this file before") or content-aware
  signals, which this project does not implement.
- **Anything upstream of the access log.** If an attacker has the RSA
  private key and a valid session, the anomaly layer only sees what looks
  like ordinary API calls; it cannot detect key theft itself.
- **A malicious insider staying within their normal working pattern.**
  Someone authorized to access a file who exfiltrates it once, at a
  normal time, in a normal amount, looks identical to legitimate use.
- **Collusion between the metadata service and an attacker who also holds
  the shared HMAC secret.** Because manifest signing here is HMAC (a
  shared secret) rather than an asymmetric client signature, the party
  that verifies the signature could in principle also forge one. This is
  a known limitation, not an oversight - see the README for the intended
  production fix (per-client asymmetric signing keys).

## Why flags trigger step-up auth, not an automatic block

An Isolation Forest trained on a small synthetic baseline will have false
positives - a legitimate user working late, or downloading an unusually
large file once, looks anomalous by the numbers. Auto-blocking on every
flag would lock out real users with no recourse. Feeding flags into the
RBAC layer as a step-up-auth requirement (surfaced today as the
`X-Step-Up-Required` response header, recorded in the access log for
review) keeps the false-positive cost low while still creating friction
for suspicious access.
