"""Tests for vt-scanner."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from vt_scanner.hasher import collect_files, hash_file, hash_file_multi


class TestHasher:
    def test_hash_file_sha256(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello world")
            path = Path(f.name)

        try:
            expected = hashlib.sha256(b"hello world").hexdigest()
            assert hash_file(path, "sha256") == expected
        finally:
            path.unlink()

    def test_hash_file_md5(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data")
            path = Path(f.name)

        try:
            expected = hashlib.md5(b"test data").hexdigest()
            assert hash_file(path, "md5") == expected
        finally:
            path.unlink()

    def test_hash_file_invalid_algorithm(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="Unsupported algorithm"):
                hash_file(path, "sha512")
        finally:
            path.unlink()

    def test_hash_file_multi(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"multi hash test")
            path = Path(f.name)

        try:
            result = hash_file_multi(path)
            assert result["sha256"] == hashlib.sha256(b"multi hash test").hexdigest()
            assert result["sha1"] == hashlib.sha1(b"multi hash test").hexdigest()
            assert result["md5"] == hashlib.md5(b"multi hash test").hexdigest()
            assert len(result) == 3
        finally:
            path.unlink()

    def test_hash_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = Path(f.name)

        try:
            assert hash_file(path) == hashlib.sha256(b"").hexdigest()
        finally:
            path.unlink()

    def test_hash_large_file(self):
        # 1MB of 'A's
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"A" * (1024 * 1024))
            path = Path(f.name)

        try:
            expected = hashlib.sha256(b"A" * (1024 * 1024)).hexdigest()
            assert hash_file(path) == expected
        finally:
            path.unlink()


class TestCollectFiles:
    def test_single_file(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_text("test")
        files = collect_files(f)
        assert len(files) == 1
        assert files[0] == f.resolve()

    def test_directory_recursive(self, tmp_path: Path):
        (tmp_path / "a.txt").write_text("a")
        (tmp_path / "b.txt").write_text("b")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "c.txt").write_text("c")

        files = collect_files(tmp_path)
        assert len(files) == 3
        names = {f.name for f in files}
        assert names == {"a.txt", "b.txt", "c.txt"}

    def test_directory_non_recursive(self, tmp_path: Path):
        (tmp_path / "a.txt").write_text("a")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "c.txt").write_text("c")

        files = collect_files(tmp_path, recursive=False)
        assert len(files) == 1
        assert files[0].name == "a.txt"

    def test_missing_path(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            collect_files(tmp_path / "nonexistent")

    def test_empty_directory(self, tmp_path: Path):
        files = collect_files(tmp_path)
        assert files == []


class TestCache:
    def test_set_and_get(self, tmp_path: Path):
        from vt_scanner.cache import HashCache

        db = tmp_path / "test.db"
        cache = HashCache(db)
        result = {"malicious": 0, "clean": True}
        cache.set("abc123", result, path="/tmp/test", mtime=12345.0)
        cached = cache.get("abc123")
        assert cached == result
        cache.close()

    def test_miss(self, tmp_path: Path):
        from vt_scanner.cache import HashCache

        db = tmp_path / "test.db"
        cache = HashCache(db)
        assert cache.get("nonexistent") is None
        cache.close()

    def test_lookup_by_path(self, tmp_path: Path):
        from vt_scanner.cache import HashCache

        db = tmp_path / "test.db"
        cache = HashCache(db)
        result = {"malicious": 2, "suspicious": 1}
        cache.set("def456", result, path="/tmp/malware", mtime=99999.0)

        cached = cache.lookup_by_path("/tmp/malware", 99999.0)
        assert cached is not None
        assert cached[0] == "def456"
        assert cached[1] == result

        # Stale mtime
        stale = cache.lookup_by_path("/tmp/malware", 88888.0)
        assert stale is None

        cache.close()

    def test_clear(self, tmp_path: Path):
        from vt_scanner.cache import HashCache

        db = tmp_path / "test.db"
        cache = HashCache(db)
        cache.set("test", {"data": 1})
        assert cache.get("test") is not None

        cache.conn.execute("DELETE FROM cache")
        cache.conn.commit()
        assert cache.get("test") is None
        cache.close()