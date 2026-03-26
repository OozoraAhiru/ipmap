#!/usr/bin/env python3
"""
generate.py — Fetch RIR delegated stats and produce per-group CIDR blocklists.

Sources (all five RIRs, IPv4 + IPv6):
  APNIC   https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest
  ARIN    https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest
  LACNIC  https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest
  RIPE    https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest
  AFRINIC https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest

Output per group (e.g. CCP):
  list/CCP_v4.txt   — IPv4 only
  list/CCP_v6.txt   — IPv6 only
"""

import ipaddress
import urllib.error
import urllib.request
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from collections import defaultdict

# ── Paths: work from repo root regardless of where the script lives ───────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# If script is in scripts/, go up one level; if in root, stay
REPO_ROOT  = (os.path.dirname(SCRIPT_DIR)
              if os.path.basename(SCRIPT_DIR) == "scripts"
              else SCRIPT_DIR)
OUTPUT_DIR = os.path.join(REPO_ROOT, "list")

# ── RIR sources ───────────────────────────────────────────────────────────────

RIR_URLS = [
    "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest",
]

# ── Group definitions ─────────────────────────────────────────────────────────

GROUPS = {
    "CCP":        ["CN", "HK", "MO"],
    "Russian":    ["RU", "BY", "KZ", "AM", "KG", "TJ", "MD"],
    "Iran":       ["IR", "LB", "YE", "IQ"],
    "AxisOfEvil": ["CN", "HK", "MO", "RU", "BY", "KZ", "AM", "KG", "TJ", "MD",
                   "IR", "LB", "YE", "IQ", "KP"],
    "HackerTier1": ["NG", "RO", "BR", "UA"],
    "HackerTier2": ["IN", "ID", "VN", "PK", "BD"],
    "HackerTier3": ["TR", "MA", "DZ", "MX"],
    "AsianScams":  ["MM", "KH", "LA", "PH"],
}

GROUP_DESCRIPTIONS = {
    "CCP":         "Chinese Communist Party direct control",
    "Russian":     "Russian sphere of influence (CSTO + Belarus)",
    "Iran":        "Iranian axis of resistance proxy states",
    "AxisOfEvil":  "All state-actor threats combined (CCP + Russia + Iran + DPRK)",
    "HackerTier1": "High-confidence cybercrime sources",
    "HackerTier2": "Significant cybercrime sources",
    "HackerTier3": "Moderate cybercrime sources",
    "AsianScams":  "Southeast Asian scam farm operations",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def ipv4_range_to_cidrs(start_ip: str, host_count: int) -> list[str]:
    start = int(ipaddress.IPv4Address(start_ip))
    end   = start + host_count - 1
    return [str(n) for n in ipaddress.summarize_address_range(
        ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
    )]


def fetch_rir(url: str) -> list[str]:
    print(f"  Fetching {url} ...", end=" ", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "ipmap/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read().decode("utf-8", errors="replace").splitlines()
        print(f"OK ({len(data)} lines)")
        return data
    except urllib.error.URLError as e:
        print(f"urllib failed ({e}); trying curl ...", end=" ", flush=True)

    curl_bin = shutil.which("curl")
    if not curl_bin:
        print("FAILED (curl not found)")
        return []

    try:
        proc = subprocess.run(
            [curl_bin, "-fsSL", "--connect-timeout", "30", "--max-time", "180", url],
            check=True,
            capture_output=True,
            text=True,
        )
        data = proc.stdout.splitlines()
        print(f"OK ({len(data)} lines)")
        return data
    except subprocess.CalledProcessError as e:
        detail = e.stderr.strip() or f"exit status {e.returncode}"
        print(f"FAILED ({detail})")
        return []


def parse_rir(lines: list[str]) -> dict[str, dict[str, list[str]]]:
    """Returns {cc: {"v4": [...], "v6": [...]}}"""
    result: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"v4": [], "v6": []})
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 7:
            continue
        cc     = parts[1].upper()
        rtype  = parts[2].lower()
        start  = parts[3]
        value  = parts[4]
        status = parts[6].lower().split("[")[0].strip()

        if status not in ("allocated", "assigned"):
            continue
        if cc in ("", "*", "ZZ"):
            continue

        try:
            if rtype == "ipv4":
                result[cc]["v4"].extend(ipv4_range_to_cidrs(start, int(value)))
            elif rtype == "ipv6":
                cidr = f"{start}/{int(value)}"
                ipaddress.IPv6Network(cidr, strict=False)
                result[cc]["v6"].append(cidr)
        except Exception:
            continue

    return result


def dedupe_sort_v4(cidrs: list[str]) -> list[str]:
    nets, seen = [], set()
    for c in cidrs:
        if c in seen:
            continue
        seen.add(c)
        try:
            nets.append(ipaddress.IPv4Network(c, strict=False))
        except ValueError:
            pass
    return [str(n) for n in sorted(nets)]


def dedupe_sort_v6(cidrs: list[str]) -> list[str]:
    nets, seen = [], set()
    for c in cidrs:
        if c in seen:
            continue
        seen.add(c)
        try:
            nets.append(ipaddress.IPv6Network(c, strict=False))
        except ValueError:
            pass
    return [str(n) for n in sorted(nets)]


def write_file(path: str, name: str, suffix: str, version: str,
               cidrs: list[str], countries: list[str],
               country_counts: dict[str, int]) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# {name}_{suffix}.txt",
        f"# Auto-generated by ipmap — {timestamp}",
        f"# Countries / Regions: {', '.join(countries)}",
        f"# IP version: {version}",
        f"# Total CIDR entries: {len(cidrs)}",
        "#",
    ]
    for cc in countries:
        lines.append(f"#   {cc}: {country_counts.get(cc, 0)} {version} entries")
    lines.append("#")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
        f.write("\n".join(cidrs) + "\n")


def write_group(name: str, countries: list[str],
                country_map: dict[str, dict[str, list[str]]]) -> tuple[int, int]:
    all_v4, all_v6 = [], []
    counts_v4: dict[str, int] = {}
    counts_v6: dict[str, int] = {}

    for cc in countries:
        v4 = country_map.get(cc, {}).get("v4", [])
        v6 = country_map.get(cc, {}).get("v6", [])
        counts_v4[cc] = len(v4)
        counts_v6[cc] = len(v6)
        all_v4.extend(v4)
        all_v6.extend(v6)

    sorted_v4 = dedupe_sort_v4(all_v4)
    sorted_v6 = dedupe_sort_v6(all_v6)

    write_file(os.path.join(OUTPUT_DIR, f"{name}_v4.txt"),
               name, "v4", "IPv4", sorted_v4, countries, counts_v4)
    write_file(os.path.join(OUTPUT_DIR, f"{name}_v6.txt"),
               name, "v6", "IPv6", sorted_v6, countries, counts_v6)

    print(f"  → {name}_v4.txt ({len(sorted_v4)} CIDRs) / {name}_v6.txt ({len(sorted_v6)} CIDRs)")
    return len(sorted_v4), len(sorted_v6)


def write_manifest(group_stats: dict[str, tuple[int, int]]) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Blocklist Files",
        "",
        f"**Last updated:** {ts}",
        "",
        "| Files | Countries / Regions | IPv4 | IPv6 | Description |",
        "|-------|---------------------|:----:|:----:|-------------|",
    ]
    for name, countries in GROUPS.items():
        v4_count, v6_count = group_stats.get(name, (0, 0))
        desc    = GROUP_DESCRIPTIONS.get(name, "")
        regions = ", ".join(countries)
        lines.append(
            f"| `{name}_v4.txt` `{name}_v6.txt` "
            f"| {regions} | {v4_count} | {v6_count} | {desc} |"
        )
    lines += [
        "",
        "> Source: APNIC / ARIN / LACNIC / RIPE NCC / AFRINIC delegated-extended-latest",
    ]
    with open(os.path.join(OUTPUT_DIR, "README.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"Repo root : {REPO_ROOT}")
    print(f"Output dir: {OUTPUT_DIR}")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("\n=== Fetching RIR delegated-extended files ===")
    all_lines: list[str] = []
    for url in RIR_URLS:
        all_lines.extend(fetch_rir(url))

    if not all_lines:
        print("\nERROR: failed to fetch delegated stats from every RIR source.")
        print("Refusing to overwrite blocklists with empty output.")
        sys.exit(1)

    print(f"\n=== Parsing {len(all_lines)} total lines ===")
    country_map = parse_rir(all_lines)
    print(f"    Found data for {len(country_map)} country codes")

    print("\n=== Writing group files ===")
    group_stats: dict[str, tuple[int, int]] = {}
    for group_name, countries in GROUPS.items():
        group_stats[group_name] = write_group(group_name, countries, country_map)

    write_manifest(group_stats)
    print(f"\n✓ Done. Files written to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
