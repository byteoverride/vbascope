"""
File hashing utilities.

Why it matters for malware analysis:
    Cryptographic hashes are the primary way an analyst pivots. A SHA256
    dropped into VirusTotal / MalwareBazaar / an internal sandbox DB tells
    you instantly whether a sample has been seen before, which family it
    belongs to, and what the sandbox already learned about it. MD5/SHA1 are
    kept for compatibility with older feeds and YARA hash modules even though
    they are cryptographically broken.
"""

from __future__ import annotations

import hashlib
import os
from typing import Dict


def compute_hashes(path: str, chunk_size: int = 65536) -> Dict[str, object]:
    """Compute MD5, SHA1 and SHA256 of a file plus its size and magic bytes.

    Reads the file in chunks so that multi-hundred-MB samples do not blow up
    memory. Returns a dict that is JSON serialisable.

    Args:
        path: Path to the file on disk.
        chunk_size: Bytes to read per iteration.

    Returns:
        Dict with keys: md5, sha1, sha256, size, magic_bytes (first 8 bytes
        rendered as a hex string).
    """
    md5 = hashlib.md5()      # noqa: S324 - needed for threat-intel compatibility
    sha1 = hashlib.sha1()    # noqa: S324 - needed for threat-intel compatibility
    sha256 = hashlib.sha256()

    first_bytes = b""
    with open(path, "rb") as handle:
        first_bytes = handle.read(8)
        # Rewind so the first 8 bytes are also fed to the hash functions.
        handle.seek(0)
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": os.path.getsize(path),
        "magic_bytes": first_bytes.hex(),
    }
