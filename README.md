# Digital Signature Hash Video Platform

Digital Signature Hash Video Platform is an account-free video authenticity and content-addressed storage application built with Flask, Ed25519, and SHA-256. The Ed25519 public key is the identity, the private key stays on the user’s device, and every public key has exactly one current signed manifest. Users can search by public key to retrieve the complete signed video-hash list, or search by a video SHA-256 value to find every current signed manifest that contains it.

## Core security model

Each video is represented by its own SHA-256 hash. The browser calculates every hash locally and then uses the Ed25519 private key to sign one deterministic JSON document containing the complete hash list and all manifest metadata. The server cannot add, remove, replace, or reorder signed hashes, change the public key, alter the revision chain, or modify the signed time information without invalidating the Ed25519 signature. The server also recalculates every uploaded video hash before storage and again before download, while the browser recalculates the downloaded file hash before saving it.

The platform has no usernames, passwords, accounts, or server-side private keys. Possession of the Ed25519 private key is the authority to publish the next manifest for its derived public key.

## Exact signed manifest

The detached Ed25519 signature covers the compact canonical JSON representation of every field below except `signature` itself:

```json
{
  "public_key": "ed25519:20S_5szfL7bSZ9n30Y1T7E7BDsoMmqP1v_bprWQ4PQc",
  "revision": 3,
  "previous_signature_sha256": "0d8f...64-lowercase-hex-characters...",
  "signed_at": "2026-07-15T10:30:00+08:00",
  "expires_at": "2027-07-15T10:30:00+08:00",
  "note": "Signed at 2026-07-15T10:30:00+08:00; expires at 2027-07-15T10:30:00+08:00.",
  "hashes": [
    "4bb8dcfa2f8b11be8bedb25b27c56ca4510b5eb0cb3d651bc3ba9fd0457097f4",
    "9f9011777b834173969e7eaf2f701676f45adbb9b0a8b72db0f36dab4d74a3e0"
  ],
  "signature": "Tgl_cwZzc55Y5jLkISFpDhPiyeMEon0FzNXYgLuB1ZJSceXsnLNeFhkjstGa_pDNKyFqyJ7BCKgbCbm9n5LRDA"
}
```

Before signing, hashes are converted to lowercase, deduplicated, sorted, and validated as 64-character SHA-256 values. Revision 1 uses `null` for `previous_signature_sha256`. Every later revision contains the SHA-256 of the previous raw Ed25519 signature, creating a signed revision chain. `signed_at`, `expires_at`, and the automatically generated `note` include the user’s timezone offset and are also protected by the signature. The expiration time must be later than the signing time.

## Identity and key format

The Identity page generates an Ed25519 key pair entirely in the browser. The private key is a 32-byte Ed25519 seed and is never transmitted to the server.

```json
{
  "private_key": "ed25519-private:<base64url-encoded-32-byte-seed>",
  "public_key": "ed25519:<base64url-encoded-32-byte-public-key>"
}
```

The Publish page accepts the downloaded JSON key file, a prefixed `ed25519-private:` value, raw Base64URL, or a 64-character hexadecimal seed. The public key is always derived locally from the private seed, and an imported JSON file is rejected if its declared public key does not match the derived key.

## Two-phase AJAX publication

Publishing is intentionally split into two verified phases:

1. The user imports or enters the private key and selects every video that should appear in the new current manifest.
2. The browser calculates SHA-256 sequentially, one file at a time and in 4 MiB chunks, avoiding the need to load large collections fully into memory.
3. The browser requests the current revision state for the derived public key.
4. The browser creates the next canonical manifest, signs it locally with Ed25519, and sends only the public key, metadata, hash list, and detached signature to `/api/publish/prepare`.
5. The server reconstructs the exact canonical JSON, verifies the Ed25519 signature, validates the revision chain, and identifies hashes that are missing or whose stored objects fail integrity checks.
6. The browser uploads only those missing or damaged objects, one at a time, through `/api/publish/upload/<token>/<sha256>`.
7. The server calculates the incoming file SHA-256 while receiving it and rejects any bytes that do not match the preverified signed hash.
8. `/api/publish/finalize` verifies every signed object again and atomically replaces the public key’s previous current manifest.

A prepare token is unpredictable, temporary, and bound to one already verified signed manifest. Video bytes are never accepted as proof of identity; only the Ed25519 signature authorizes the manifest.

## Repeated publication and rollback detection

The same private key may publish repeatedly. A correctly signed revision replaces the previous current manifest for that public key. Replacement is atomic: the new revision becomes current only after every signed object exists and passes SHA-256 verification. An outdated browser page cannot silently overwrite a newer revision because the new manifest must use exactly `current_revision + 1` and must reference the SHA-256 of the current signature.

The browser stores the highest verified revision for each public key in local storage. If the server later returns a lower revision, the browser reports a possible rollback. This detects rollback only when that browser has already seen a newer revision. For cross-device or third-party rollback evidence, keep and share the downloaded signed manifest receipt.

## Search and independent browser verification

The Search page accepts either:

- an Ed25519 public key, which returns that identity’s complete current signed manifest; or
- a 64-character SHA-256 video hash, which returns every current signed manifest whose verified hash list contains that object.

The server never treats database relationships as cryptographic proof. Before returning a result, it reconstructs the stored canonical manifest and verifies the Ed25519 signature. The browser then independently performs the same verification with TweetNaCl.js, confirms that the searched public key or hash matches the signed content, checks canonical hash ordering, checks the signed time and expiration state, and applies rollback detection. Results are displayed only after browser-side verification succeeds.

## Content-addressed storage and deduplication

Video objects are stored by SHA-256 instead of their original filenames. If the same bytes are uploaded again by the same or another public key, the existing valid object is reused rather than stored twice. Original filenames are not trusted and are not part of identity or signature verification.

The server records a conservative media type and extension when possible. Downloads use names such as `<sha256>.mp4`, `<sha256>.webm`, or `<sha256>.mkv`; unknown content falls back to `.bin`. The download route is `/object/<sha256>`.

Before sending a file, the server recalculates its SHA-256 and returns HTTP 409 if the stored bytes no longer match the requested content address. The browser downloads through AJAX, recalculates SHA-256 again, and saves the object only when the result matches the requested hash.

## Security properties

This design provides the following verifiable properties:

- Without the private key, an attacker cannot create a valid new manifest for the corresponding public key.
- The server cannot add, remove, replace, or reorder signed video hashes without invalidating the Ed25519 signature.
- The server cannot alter the revision, previous-signature link, signing time, expiration time, note, or public key without invalidating the signature.
- Different video bytes cannot be substituted under an existing SHA-256 address without detection.
- Forged database relationships are filtered by reconstructing and verifying the signed manifest.
- Identical video bytes are stored only once.
- Search results and downloaded objects are independently verified in the browser rather than trusted because the server claims they are valid.

The design does not force a hostile server to retain data, return every matching result, stay online, or avoid denial of service. A malicious server may delete or hide data, but it cannot generate a valid Ed25519 signature for a public key whose private key it does not possess. Signed receipts should be retained as independent evidence of a published manifest.

## Pages and API routes

- `/`: project overview.
- `/identity`: generate, copy, and download an Ed25519 key pair locally.
- `/publish`: import or enter a private key, hash videos sequentially, sign the manifest, upload missing objects, and download the final receipt.
- `/search`: search by public key or video SHA-256, verify results in the browser, and perform verified downloads.
- `/api/status`: protocol and service information.
- `/api/manifest-state`: current revision-chain head for a public key.
- `/api/publish/prepare`: verify a signed manifest and return missing hashes.
- `/api/publish/upload/<token>/<sha256>`: upload one object already authorized by the verified manifest.
- `/api/publish/finalize`: atomically replace the current manifest after full integrity verification.
- `/api/search`: retrieve verified manifests by public key or video hash.
- `/object/<sha256>`: rehash and download one content-addressed object.

## Installation and startup

Python 3.10 or newer is recommended. Windows and Linux use the same commands:

```bash
git clone https://github.com/wangyifan349/digital-signature-hash-video-platform.git
cd digital-signature-hash-video-platform
python -m pip install -r requirements.txt
python server.py
```

Open `https://127.0.0.1:5000` locally or `https://<server-ip>:5000` from another device. The default development server uses an ad-hoc self-signed certificate, so the browser may display a certificate warning. For local HTTP testing, set `DEVELOPMENT_TLS=off` before starting the application.

## Configuration

- `MAX_UPLOAD_BYTES`: maximum size of one object-upload request; default 32 GiB.
- `MAX_MANIFEST_FILES`: maximum number of unique hashes in one signed manifest; default 10,000.
- `PENDING_LIFETIME_MINUTES`: lifetime of a verified prepare token; default 120 minutes.
- `VERIFY_OBJECTS_ON_SEARCH`: set to `1` to rehash stored objects while building search results; enabled by default.
- `INTEGRITY_WORKERS`: parallel server-side integrity workers; default is up to 4.
- `HOST`: bind address; default `0.0.0.0`.
- `PORT`: bind port; default `5000`.
- `DEVELOPMENT_TLS`: `adhoc` for development HTTPS; another value disables ad-hoc TLS.
- `DATABASE_PATH`: optional SQLite database path override.
- `OBJECT_DIRECTORY`: optional content-addressed object directory override.
- `TEMPORARY_DIRECTORY`: optional temporary upload directory override.

## Project files

- `server.py`: complete Flask backend and embedded HTML, CSS, JavaScript, Ed25519, SHA-256, AJAX publication, search, and verified download logic.
- `requirements.txt`: Python dependencies (`Flask` and `cryptography`).
- `LICENSE`: GNU Affero General Public License v3.0.
- `THIRD_PARTY_NOTICES.md`: notices for browser-side libraries.
- `.gitignore`: excludes generated databases, stored objects, temporary uploads, and Python cache files.

Runtime data is created automatically as `digital_signature_hash_video_platform.db`, `video_objects/`, and `temporary_uploads/` unless overridden by environment variables.

## Browser cryptography and dependencies

The browser loads pinned versions of Bootstrap, TweetNaCl.js, and js-sha256 from jsDelivr. TweetNaCl.js performs Ed25519 key generation, signing, and browser-side verification. js-sha256 performs incremental video hashing and download verification. The server independently verifies Ed25519 with Python `cryptography` and calculates SHA-256 with Python `hashlib`.

## Interface and auditability

The compact orange-red interface has no gradients, and project-defined colors plus Bootstrap overrides use a zero blue channel. `server.py` is divided into labeled sections with descriptive English variable names, docstrings, and security-focused comments so the canonicalization, signature verification, revision-chain checks, object deduplication, atomic replacement, and download integrity logic can be audited directly.

## License

GNU Affero General Public License v3.0 or later. 



## Sponsor

If the Digital Signature Hash Video Platform is useful to you, consider supporting its continued development, security review, documentation, and maintenance by buying me a coffee ☕.

Bitcoin (BTC):

`bc1qnavxqr67kt7jje2tl4rlksmaspzwrzu67f6z5e`

Your support helps improve this project’s Ed25519 signature workflow, SHA-256 integrity verification, public-key and hash-based search, and long-term maintenance.
