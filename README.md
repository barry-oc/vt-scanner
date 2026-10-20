# vt-scanner

**Scan files and directories against VirusTotal with hash caching.**

`vt-scanner` is a fast CLI that hashes files (SHA-256, SHA-1, MD5) and
checks them against VirusTotal's database. It caches results in SQLite so you
never hit the API twice for the same file.

## Features

- **Hash caching** — unchanged files skip VT entirely (mtime-based)
- **Three modes** — `scan` once, `monitor` continuously, `cache` for housekeeping
- **Multi-algorithm** — SHA-256 (default), SHA-1, MD5
- **Rate limiting** — respects VT API limits (free tier: 4 req/min)
- **Clean output** — colored terminal tables or structured JSON
- **Pipe-friendly** — JSON output for scripting and automation

## Install

```bash
pip install git+https://github.com/barry-oc/vt-scanner.git
```

Or locally:

```bash
git clone https://github.com/barry-oc/vt-scanner.git
cd vt-scanner
pip install -e .
```

You need a VirusTotal API key. Get one free at
[virustotal.com](https://www.virustotal.com/gui/join-us).

## Quick start

```bash
# Set your key once
export VT_API_KEY="your_key_here"

# Scan a directory
vt-scanner scan ~/Downloads/malware-samples

# Scan with JSON output
vt-scanner scan ./binaries --json

# Watch a directory for new files
vt-scanner monitor ./incoming --interval 30

# Check cache stats
vt-scanner cache stats
```

## Usage

```
vt-scanner scan <file|dir>       # One-shot scan
vt-scanner monitor <dir>         # Continuous watch
vt-scanner cache stats|clear     # Cache management
```

### Scan

```bash
vt-scanner scan ./samples \
    --algorithm sha256 \
    --rate-limit 4 \
    --cache-db ~/.vt_cache.db
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--key` | `$VT_API_KEY` | VirusTotal API key |
| `--algorithm` | `sha256` | Hash algorithm (`sha256`, `sha1`, `md5`) |
| `--json` | off | Output as structured JSON |
| `--no-cache` | off | Skip SQLite cache — always hit VT |
| `--rate-limit` | `4` | Max VT requests per minute |
| `--cache-db` | `~/.vt_cache.db` | SQLite cache path |

### Monitor

```bash
vt-scanner monitor ./uploads --interval 60 --rate-limit 4
```

Watches a directory continuously. New or modified files are hashed and
checked against VT. Already-seen files (same path + mtime) are skipped.

### Cache

```bash
vt-scanner cache stats       # Show entries, size, location
vt-scanner cache clear       # Wipe all cached results
```

## Output

### Terminal (default)

```
FILE                                 VERDICT    ENGINES  NAME                LAST SEEN
──────────────────────────────────── ────────── ──────── ─────────────────── ────
/Downloads/setup.exe                 CLEAN       0/72   setup_installer      2026-10-15
/Downloads/suspicious.dll            MALICIOUS  12/72   Trojan.Generic       2026-10-18
/incoming/unknown.bin                UNKNOWN       -    -                         -
```

### JSON

```json
[
  {
    "path": "/samples/setup.exe",
    "hash": "a1b2c3...",
    "result": {
      "sha256": "a1b2c3...",
      "meaningful_name": "setup_installer",
      "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 72},
      "tags": [],
      "reputation": 0
    }
  }
]
```

## Rate limits

VirusTotal free tier allows **4 requests per minute**. Adjust with
`--rate-limit`. The scanner automatically spaces requests — no manual
sleeping required.

```bash
# Enterprise key? Crank it up.
vt-scanner scan ./samples --rate-limit 100
```

## How caching works

1. File is hashed (SHA-256 by default)
2. SQLite is checked: `(hash, algorithm)` → cached result
3. Path + mtime tracking: unchanged files skip even the hash step
4. Cache hit → result served instantly, no API call
5. Cache miss → VT lookup, result stored in cache

## Pipe workflows

```bash
# Audit downloaded binaries
find ~/Downloads -name "*.exe" | xargs -I{} vt-scanner scan {} --json | jq '.[] | select(.result.last_analysis_stats.malicious > 0)'

# Watch + notify (with a cron job)
vt-scanner monitor /var/uploads --interval 300
```

## Requirements

- Python 3.9+
- `vt-py` — official VirusTotal Python library
- SQLite (built-in, no extra deps)

## License

MIT © 2026 Barry O'Callaghan