"""VirusTotal API scanner with rate limiting and retries."""

from __future__ import annotations

import os
import time
from typing import Any

import vt

DEFAULT_RATE_LIMIT = 4  # VT free tier: 4 requests per minute


class VTScanner:
    """Rate-limited VirusTotal client using vt-py."""

    def __init__(self, api_key: str | None = None, rate_limit: int = DEFAULT_RATE_LIMIT):
        key = api_key or os.environ.get("VT_API_KEY", "")
        if not key:
            raise ValueError("VT_API_KEY is required. Set it via --key or the VT_API_KEY environment variable.")
        self.client = vt.Client(key)
        self.rate_limit = rate_limit
        self._min_interval = 60.0 / rate_limit  # seconds between requests
        self._last_request = 0.0

    def _wait(self) -> None:
        """Enforce rate limit between API calls."""
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def lookup_hash(self, file_hash: str) -> dict[str, Any] | None:
        """Look up a file hash on VirusTotal.

        Returns parsed result dict, or None if the hash is unknown on VT.
        """
        self._wait()
        try:
            obj = self.client.get_object(f"/files/{file_hash}")
            return self._parse_file_obj(obj)
        except vt.error.APIError as e:
            if e.code == "NotFoundError":
                return None
            raise

    def lookup_hashes(self, hashes: list[str]) -> list[tuple[str, dict[str, Any] | None]]:
        """Look up multiple hashes. Returns list of (hash, result_or_None)."""
        results = []
        for i, h in enumerate(hashes):
            try:
                result = self.lookup_hash(h)
                results.append((h, result))
            except Exception as e:
                results.append((h, {"error": str(e)}))
        return results

    @staticmethod
    def _parse_file_obj(obj) -> dict[str, Any]:
        """Extract the fields we care about from a VT file object."""
        attrs = obj.get("attributes", {})
        return {
            "sha256": obj.get("id", ""),
            "sha1": attrs.get("sha1", ""),
            "md5": attrs.get("md5", ""),
            "meaningful_name": attrs.get("meaningful_name", ""),
            "type_description": attrs.get("type_description", ""),
            "size": attrs.get("size", 0),
            "last_analysis_date": attrs.get("last_analysis_date", 0),
            "last_analysis_stats": attrs.get("last_analysis_stats", {}),
            "tags": attrs.get("tags", []),
            "reputation": attrs.get("reputation", 0),
            "times_submitted": attrs.get("times_submitted", 0),
            "first_submission_date": attrs.get("first_submission_date", 0),
        }

    def close(self) -> None:
        self.client.close()