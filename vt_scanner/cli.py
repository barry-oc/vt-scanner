"""CLI — scan files and directories against VirusTotal."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import __version__
from .cache import HashCache
from .hasher import collect_files, hash_file
from .output import print_json, print_result_table
from .scanner import VTScanner


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vt-scanner",
        description="Scan files and directories against VirusTotal with hash caching.",
    )
    p.add_argument("--version", action="version", version=f"vt-scanner {__version__}")

    subs = p.add_subparsers(dest="command", required=True)

    # ── scan ──
    scan = subs.add_parser("scan", help="Scan files/directories once and exit")
    scan.add_argument("target", help="File or directory to scan")
    scan.add_argument("--key", help="VirusTotal API key (or set VT_API_KEY env var)")
    scan.add_argument("--algorithm", default="sha256", choices=["sha256", "sha1", "md5"], help="Hash algorithm (default: sha256)")
    scan.add_argument("--json", dest="json_out", action="store_true", help="Output results as JSON")
    scan.add_argument("--no-cache", dest="use_cache", action="store_false", default=True, help="Skip cache — always hit VT")
    scan.add_argument("--rate-limit", type=int, default=4, help="VT requests per minute (default: 4 for free tier)")
    scan.add_argument("--cache-db", default="~/.vt_cache.db", help="SQLite cache path (default: ~/.vt_cache.db)")

    # ── monitor ──
    mon = subs.add_parser("monitor", help="Watch a directory continuously for new files")
    mon.add_argument("target", help="Directory to monitor")
    mon.add_argument("--key", help="VirusTotal API key (or set VT_API_KEY env var)")
    mon.add_argument("--interval", type=int, default=60, help="Seconds between directory scans (default: 60)")
    mon.add_argument("--rate-limit", type=int, default=4, help="VT requests per minute (default: 4 for free tier)")
    mon.add_argument("--cache-db", default="~/.vt_cache.db", help="SQLite cache path")

    # ── cache ──
    cch = subs.add_parser("cache", help="Manage the hash cache")
    cch.add_argument("action", choices=["stats", "clear"], help="'stats' shows cache info, 'clear' wipes it")
    cch.add_argument("--cache-db", default="~/.vt_cache.db", help="SQLite cache path")

    return p


def cmd_scan(args: argparse.Namespace) -> None:
    target = Path(args.target)
    cache = HashCache(args.cache_db) if args.use_cache else None
    scanner = VTScanner(api_key=args.key, rate_limit=args.rate_limit)

    try:
        files = collect_files(target)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not files:
        print(f"No files found in '{args.target}'")
        sys.exit(0)

    print(f"Scanning {len(files)} file(s)...")
    total_known = 0

    results = []
    for i, fpath in enumerate(files):
        mtime = fpath.stat().st_mtime

        # Check cache first
        result = None
        file_hash = None
        if cache:
            cached = cache.lookup_by_path(str(fpath), mtime, args.algorithm)
            if cached:
                file_hash, result = cached
                total_known += 1

        # Hash if not cached
        if file_hash is None:
            file_hash = hash_file(fpath, args.algorithm)
            if cache:
                pass  # Will cache after lookup

        # Check VT
        if result is not None:
            pass  # Use cached result
        else:
            try:
                result = scanner.lookup_hash(file_hash)
                if cache and result is not None:
                    cache.set(file_hash, result, str(fpath), mtime, args.algorithm)
            except Exception as e:
                result = {"error": str(e)}

        results.append({"path": str(fpath), "hash": file_hash, "result": result})

    scanner.close()

    if args.json_out:
        print_json(results)
    else:
        print_result_table(results)

    remaining = len(files) - total_known
    if not args.json_out:
        print(f"  Files scanned: {len(files)}  |  Cache hits: {total_known}  |  VT lookups: {remaining}")


def cmd_monitor(args: argparse.Namespace) -> None:
    target = Path(args.target)
    if not target.is_dir():
        print(f"Error: '{args.target}' is not a directory", file=sys.stderr)
        sys.exit(1)

    cache = HashCache(args.cache_db)
    scanner = VTScanner(api_key=args.key, rate_limit=args.rate_limit)

    print(f"Monitoring '{args.target}' (interval: {args.interval}s).  Ctrl+C to stop.\n")

    seen_files: dict[str, float] = {}  # path → mtime

    try:
        while True:
            files = collect_files(target)
            for fpath in files:
                fpath_str = str(fpath)
                mtime = fpath.stat().st_mtime

                # Skip if unchanged
                if fpath_str in seen_files and seen_files[fpath_str] == mtime:
                    continue
                seen_files[fpath_str] = mtime

                # Check cache
                cached = cache.lookup_by_path(fpath_str, mtime, "sha256")
                if cached:
                    file_hash, result = cached
                else:
                    file_hash = hash_file(fpath)
                    try:
                        result = scanner.lookup_hash(file_hash)
                        if result is not None:
                            cache.set(file_hash, result, fpath_str, mtime)
                    except Exception as e:
                        result = {"error": str(e)}

                # Print result
                print_result_table([{"path": fpath_str, "hash": file_hash, "result": result}])

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        scanner.close()
        cache.close()


def cmd_cache(args: argparse.Namespace) -> None:
    cache = HashCache(args.cache_db)
    if args.action == "clear":
        cache.conn.execute("DELETE FROM cache")
        cache.conn.commit()
        print("Cache cleared.")
    elif args.action == "stats":
        count = cache.conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
        size = Path(cache.db_path).stat().st_size if cache.db_path.exists() else 0
        print(f"Cache entries: {count}")
        print(f"Database size: {size / 1024:.1f} KB")
        print(f"Location:      {cache.db_path}")
    cache.close()


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "monitor":
        cmd_monitor(args)
    elif args.command == "cache":
        cmd_cache(args)