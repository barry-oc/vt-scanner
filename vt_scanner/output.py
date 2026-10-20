"""Formatted output — terminal tables and JSON."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any

# ── terminal styling ──
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

MALICIOUS_THRESHOLD = 3  # engines detecting = malicious
SUSPICIOUS_THRESHOLD = 1


def _summarise(stats: dict[str, int]) -> tuple[int, int]:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    return malicious, suspicious


def _verdict(malicious: int, suspicious: int) -> str:
    if malicious >= MALICIOUS_THRESHOLD:
        return f"{RED}MALICIOUS{RESET}"
    if malicious > 0 or suspicious > 0:
        return f"{YELLOW}SUSPICIOUS{RESET}"
    return f"{GREEN}CLEAN{RESET}"


def _shorten(name: str, width: int = 40) -> str:
    if not name:
        return "-"
    return name if len(name) <= width else name[: width - 3] + "..."


def _ts(epoch: int) -> str:
    if not epoch:
        return "never"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def print_result_table(results: list[dict[str, Any]]) -> None:
    """Print a formatted terminal table of VT scan results."""
    if not results:
        print(f"{DIM}No results to display.{RESET}")
        return

    header = (
        f"{BOLD}{'FILE':<36} {'VERDICT':<14} {'ENGINES':>8} "
        f"{'NAME':<42} {'LAST SEEN':>10}{RESET}"
    )
    print()
    print(header)
    print("─" * len(header.replace(BOLD, "").replace(RESET, "")))

    for r in results:
        path = r.get("path", "-")[-36:]
        result = r.get("result")
        if result is None:
            line = f"{path:<36} {DIM}UNKNOWN{RESET:<14} {'-':>8} {'-':<42} {'-':>10}"
        elif "error" in result:
            line = f"{path:<36} {RED}ERROR{RESET:<14} {'-':>8} {result['error']:<42} {'-':>10}"
        else:
            stats = result.get("last_analysis_stats", {})
            mal, sus = _summarise(stats)
            total = sum(stats.values())
            verdict = _verdict(mal, sus)
            engines = f"{mal}{RED}/{total}{RESET}" if mal else f"0/{total}"
            name = _shorten(result.get("meaningful_name", ""))
            last = _ts(result.get("last_analysis_date", 0))
            line = f"{path:<36} {verdict:<24} {engines:>18} {name:<42} {last:>10}"
        print(line)
    print()


def print_json(results: list[dict[str, Any]]) -> None:
    """Print results as JSON to stdout."""
    json.dump(results, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")