#!/usr/bin/env python3
"""
generate.py — Fetch RIR delegated stats and produce per-group CIDR blocklists.

Sources (all five RIRs, IPv4 + IPv6):
  APNIC   https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest
  ARIN    https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest
  LACNIC  https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest
  RIPE    https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest
  AFRINIC https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest
"""

import math
import ipaddress
import urllib.request
import urllib.error
import os
import sys
from datetime import datetime, timezone
from collections import defaultdict

# ── RIR sources ──────────────────────────────────────────────────────────────

RIR_URLS = [
    "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest",
]

# ── Group definitions ─────────────────────────────────────────────────────────

GROUPS = {
    # Political / state-actor groups
    "CCP": ["CN", "HK", "MO"],
    "Russian": ["RU", "BY", "KZ", "AM", "KG", "TJ", "MD"],
    "Iran": ["IR", "LB", "YE", "IQ"],
    "AxisOfEvil": ["CN", "HK", "MO", "RU", "BY", "KZ", "AM", "KG", "TJ", "MD",
                   "IR", "LB", "YE", "IQ", "KP"],

    # Cybercrime tiers
    "HackerTier1": ["NG", "RO", "BR", "UA"],
    "HackerTier2": ["IN", "ID", "VN", "PK", "BD"],
    "HackerTier3": ["TR", "MA", "DZ", "MX"],

    # Asian scam farm operations
    "AsianScams": ["MM", "KH", "LA", "PH"],
}

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "lists")


# ── Helpers ───────────────────────────────────────────────────────────────────

def ipv4_range_to_cidrs(start_ip: str, host_count: int):
    """Convert RIR-format (start_ip, host_count) to CIDR notation list."""
    start = int(ipaddress.IPv4Address(start_ip))
    end = start + host_count - 1
    networks = ipaddress.summarize_address_range(
        ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
    )
    return [str(n) for n in networks]


def fetch_rir(url: str) -> list[str]:
    """Download a delegated-extended file; return lines."""
    print(f"  Fetching {url} ...", end=" ", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "geoblock-lists/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read().decode("utf-8", errors="replace").splitlines()
        print(f"OK ({len(data)} lines)")
        return data
    except urllib.error.URLError as e:
        print(f"FAILED ({e})")
        return []


def parse_rir(lines: list[str]) -> dict[str, list[str]]:
    """
    Parse delegated-extended lines into {country_code: [cidr, ...]} mapping.
    Handles both IPv4 (host-count format) and IPv6 (prefix-length format).
    """
    result = defaultdict(list)
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 7:
            continue
        # registry|cc|type|start|value|date|status
        cc = parts[1].upper()
        rtype = parts[2].lower()
        start = parts[3]
        value = parts[4]
        status = parts[6].lower().split("[")[0].strip()  # strip extensions

        if status not in ("allocated", "assigned"):
            continue
        if cc in ("", "*", "ZZ"):
            continue

        try:
            if rtype == "ipv4":
                host_count = int(value)
                cidrs = ipv4_range_to_cidrs(start, host_count)
                result[cc].extend(cidrs)
            elif rtype == "ipv6":
                prefix_len = int(value)
                cidr = f"{start}/{prefix_len}"
                # validate
                ipaddress.IPv6Network(cidr, strict=False)
                result[cc].append(cidr)
        except Exception:
            continue

    return result


def dedupe_sort(cidrs: list[str]) -> list[str]:
    """Remove duplicates and sort CIDRs in a human-friendly order."""
    v4, v6 = [], []
    seen = set()
    for c in cidrs:
        if c in seen:
            continue
        seen.add(c)
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.version == 4:
                v4.append(net)
            else:
                v6.append(net)
        except ValueError:
            pass
    v4.sort()
    v6.sort()
    return [str(n) for n in v4] + [str(n) for n in v6]


def write_group(name: str, countries: list[str], country_map: dict[str, list[str]]):
    """Write a merged, deduplicated CIDR file for one group."""
    all_cidrs = []
    country_counts = {}
    for cc in countries:
        cidrs = country_map.get(cc, [])
        country_counts[cc] = len(cidrs)
        all_cidrs.extend(cidrs)

    sorted_cidrs = dedupe_sort(all_cidrs)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header_lines = [
        f"# {name}.txt",
        f"# Auto-generated by geoblock-lists — {timestamp}",
        f"# Countries: {', '.join(countries)}",
        f"# Total CIDR entries: {len(sorted_cidrs)}",
        "#",
    ]
    for cc in countries:
        header_lines.append(f"#   {cc}: {country_counts.get(cc, 0)} entries")
    header_lines.append("#")

    out_path = os.path.join(OUTPUT_DIR, f"{name}.txt")
    with open(out_path, "w") as f:
        f.write("\n".join(header_lines) + "\n")
        f.write("\n".join(sorted_cidrs) + "\n")

    print(f"  → {name}.txt  ({len(sorted_cidrs)} CIDRs, "
          f"countries: {', '.join(f'{c}={country_counts.get(c,0)}' for c in countries)})")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=== Fetching RIR delegated-extended files ===")
    all_lines = []
    for url in RIR_URLS:
        all_lines.extend(fetch_rir(url))

    print(f"\n=== Parsing {len(all_lines)} total lines ===")
    country_map = parse_rir(all_lines)
    print(f"    Found data for {len(country_map)} country codes")

    print("\n=== Writing group files ===")
    for group_name, countries in GROUPS.items():
        write_group(group_name, countries, country_map)

    # Write a README-style manifest
    manifest_path = os.path.join(OUTPUT_DIR, "README.md")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open(manifest_path, "w") as f:
        f.write(f"# Blocklist Files\n\n")
        f.write(f"**Last updated:** {ts}\n\n")
        f.write("| File | Countries | Description |\n")
        f.write("|------|-----------|-------------|\n")
        descriptions = {
            "CCP": "Chinese Communist Party direct control",
            "Russian": "Russian sphere of influence (CSTO + Belarus)",
            "Iran": "Iranian axis of resistance proxy states",
            "AxisOfEvil": "All state-actor threats combined (CCP + Russia + Iran + DPRK)",
            "HackerTier1": "High-confidence cybercrime sources",
            "HackerTier2": "Significant cybercrime sources",
            "HackerTier3": "Moderate cybercrime sources",
            "AsianScams": "Southeast Asian scam farm operations",
        }
        for name, countries in GROUPS.items():
            f.write(f"| `{name}.txt` | {', '.join(countries)} | {descriptions.get(name,'')} |\n")
        f.write("\n> Source: APNIC / ARIN / LACNIC / RIPE NCC / AFRINIC delegated-extended-latest\n")

    print(f"\n✓ Done. Files written to: {os.path.abspath(OUTPUT_DIR)}")


if __name__ == "__main__":
    main()
