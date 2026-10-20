"""File hashing — SHA-256, SHA-1, MD5 with streaming reads."""

from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK_SIZE = 65536  # 64 KB chunks

SUPPORTED_ALGORITHMS = {
    "sha256": hashlib.sha256,
    "sha1": hashlib.sha1,
    "md5": hashlib.md5,
}


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    """Stream-hash a file and return the hex digest.

    Args:
        path: Path to the file.
        algorithm: One of 'sha256', 'sha1', 'md5'.

    Returns:
        Hex-encoded hash string.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use one of {list(SUPPORTED_ALGORITHMS)}")

    hasher = SUPPORTED_ALGORITHMS[algorithm]()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_file_multi(path: Path) -> dict[str, str]:
    """Hash a file with all supported algorithms in one pass.

    Returns a dict mapping algorithm name to hex digest.
    """
    hashers = {name: fn() for name, fn in SUPPORTED_ALGORITHMS.items()}
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            for h in hashers.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}


def collect_files(target: Path, recursive: bool = True) -> list[Path]:
    """Yield all files under a directory (or a single file).

    Args:
        target: File or directory path.
        recursive: If target is a directory, recurse into subdirectories.

    Returns:
        Sorted list of absolute file paths.
    """
    target = target.resolve()
    if target.is_file():
        return [target]
    if target.is_dir():
        pattern = "**/*" if recursive else "*"
        files = [p for p in target.glob(pattern) if p.is_file()]
        return sorted(files)
    raise FileNotFoundError(f"Path not found: {target}")