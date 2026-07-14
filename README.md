# Digital Signature Hash Video Platform 🔐🎬

Digital Signature Hash Video Platform is an account-free Flask application for publishing complete video collections with Ed25519 signatures and SHA-256 content addressing. The frontend and backend are contained in one file, `server.py`. There are no usernames, passwords, login sessions, trusted filenames, or server-side private keys. A publisher's identity is the Ed25519 public key, while the matching private key remains under the publisher's control.

## How it works 🧩

The publisher selects all videos for one collection at the same time. The browser calculates a separate SHA-256 hash for every file and creates a canonical list containing one hash per line. The Ed25519 private key signs that exact multi-file hash list before anything is published. The public key, detached signature, signed hash list, and all corresponding video bytes are then uploaded together.

The server verifies the Ed25519 signature with the supplied public key and independently recalculates SHA-256 for every uploaded video. Publication succeeds only when the signature is valid, every signed hash has exactly one corresponding file, every uploaded file matches its signed hash, and the complete collection passes validation. The files are stored by SHA-256 hash rather than by filename. The private key is never uploaded or stored.

Searching by public key returns the complete signed list of video hashes for that identity. Searching by a video hash returns the verified public keys whose signed lists contain that hash. Each available hash can be clicked to download its corresponding video object. Before serving a download, the server recalculates SHA-256 and rejects the object if its bytes no longer match the requested hash.

## Security effect 🛡️

Ed25519 prevents identity forgery because a valid publication signature cannot be produced without the matching private key. SHA-256 prevents silent file replacement because any byte change produces a different hash. Signing the complete list prevents the server from adding, removing, replacing, or reordering entries while keeping the original signature valid. Search results are rebuilt from signed data and cryptographically verified instead of trusting database relationships alone.

A malicious service operator can still refuse service, hide records, or delete stored files. However, the operator cannot create a valid publication for another public key, insert a forged video into an existing signed collection, or alter a stored video without causing verification failure. If a stored object is deleted, the signed hash remains evidence that the object belonged to the publication, while the download is reported as unavailable.

## Pages 🧭

- `/identity` generates a new Ed25519 key pair locally and allows the private key to be downloaded and copied.
- `/publish` accepts a private key file or private-key text, derives the public key automatically, hashes all selected videos, signs the complete hash list, and uploads the collection atomically.
- `/search` accepts either an Ed25519 public key or a 64-character SHA-256 video hash.
- `/api/health` reports the active protocol and algorithms.

## Requirements 📦

- Python 3.10 or newer
- Flask
- cryptography
- A modern browser with JavaScript, `BigInt`, `File`, `Blob`, and secure random-number generation

Python dependencies are listed in `requirements.txt`. Browser-side Ed25519 and SHA-256 are bundled inside `server.py`; the application does not depend on `crypto.subtle` for signing or hashing.

## Installation and startup 🚀

Windows and Linux use the same deployment method:

```bash
git clone https://github.com/wangyifan349/digital-signature-hash-video-platform.git
cd digital-signature-hash-video-platform
python -m pip install -r requirements.txt
python server.py
```

Open `https://127.0.0.1:5000` locally or `https://<server-ip>:5000` from another device. The development server uses an automatically generated ad-hoc HTTPS certificate, so the browser may display a self-signed certificate warning.

## Runtime files ⚙️

The application creates these files and directories automatically:

- `digital_signature_hash_video_platform.db`: SQLite metadata database
- `video_objects/`: SHA-256-addressed video storage
- `temporary_uploads/`: temporary staging for atomic publication

Back up the SQLite database and `video_objects/` together. Publishers must separately protect their private-key files. Losing a private key means losing control of that public-key identity; exposing it allows another person to create valid signatures for that identity.

## Repository and license 📚⚖️

Repository: `https://github.com/wangyifan349/digital-signature-hash-video-platform`

This project is licensed under the GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`). See `LICENSE` for the complete license text.
