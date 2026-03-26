# ipmap

Daily-updated IP CIDR blocklists, built from authoritative RIR data (APNIC / ARIN / LACNIC / RIPE NCC / AFRINIC).  
A GitHub Action fetches the upstream `delegated-extended-latest` files every day at 04:00 UTC and commits fresh lists to `list/`.

IPv4 and IPv6 are split into separate files for easy router integration.

---

## Files

| Files | Countries / Regions | Description |
|-------|---------------------|-------------|
| `CCP_v4.txt` / `CCP_v6.txt` | CN, HK, MO | Chinese Communist Party direct control |
| `Russian_v4.txt` / `Russian_v6.txt` | RU, BY, KZ, AM, KG, TJ, MD | Russian sphere of influence (CSTO + Belarus) |
| `Iran_v4.txt` / `Iran_v6.txt` | IR, LB, YE, IQ | Iranian axis of resistance proxy states |
| `AxisOfEvil_v4.txt` / `AxisOfEvil_v6.txt` | all of the above + KP | All state-actor threats combined |
| `HackerTier1_v4.txt` / `HackerTier1_v6.txt` | NG, RO, BR, UA | High-confidence cybercrime sources |
| `HackerTier2_v4.txt` / `HackerTier2_v6.txt` | IN, ID, VN, PK, BD | Significant cybercrime sources |
| `HackerTier3_v4.txt` / `HackerTier3_v6.txt` | TR, MA, DZ, MX | Moderate cybercrime sources |
| `AsianScams_v4.txt` / `AsianScams_v6.txt` | MM, KH, LA, PH | Southeast Asian scam farm operations |

---

## Raw URLs

### IPv4
```
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/CCP_v4.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/Russian_v4.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/Iran_v4.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/AxisOfEvil_v4.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/HackerTier1_v4.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/HackerTier2_v4.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/HackerTier3_v4.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/AsianScams_v4.txt
```

### IPv6
```
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/CCP_v6.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/Russian_v6.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/Iran_v6.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/AxisOfEvil_v6.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/HackerTier1_v6.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/HackerTier2_v6.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/HackerTier3_v6.txt
https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/AsianScams_v6.txt
```

---

## Router usage examples

### OpenWrt / nftables (recommended)
```sh
# Block IPv4
curl -sL "https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/AxisOfEvil_v4.txt" \
  | grep -v '^#' \
  | xargs -I{} nft add element inet fw4 block_src { {} }

# Block IPv6
curl -sL "https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/AxisOfEvil_v6.txt" \
  | grep -v '^#' \
  | xargs -I{} nft add element inet fw4 block_src { {} }
```

### OpenWrt / ipset (iptables)
```sh
ipset create AXIS_OF_EVIL_V4 hash:net family inet
ipset create AXIS_OF_EVIL_V6 hash:net family inet6

curl -sL "https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/AxisOfEvil_v4.txt" \
  | grep -v '^#' | while read cidr; do ipset add AXIS_OF_EVIL_V4 "$cidr"; done

curl -sL "https://raw.githubusercontent.com/OozoraAhiru/ipmap/main/list/AxisOfEvil_v6.txt" \
  | grep -v '^#' | while read cidr; do ipset add AXIS_OF_EVIL_V6 "$cidr"; done

iptables  -I INPUT -m set --match-set AXIS_OF_EVIL_V4 src -j DROP
ip6tables -I INPUT -m set --match-set AXIS_OF_EVIL_V6 src -j DROP
```

### DD-WRT / Tomato
Load via startup script using the same `ipset` method above.  
Note: DD-WRT does not support IPv6 ipsets by default; use only the `_v4` files if needed.

---

## Data sources

All data sourced from the five Regional Internet Registries (RIRs):

| RIR | Region | URL |
|-----|--------|-----|
| APNIC | Asia-Pacific | `https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest` |
| ARIN | North America | `https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest` |
| LACNIC | Latin America | `https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest` |
| RIPE NCC | Europe / Middle East / Central Asia | `https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest` |
| AFRINIC | Africa | `https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest` |

---

## Run locally

```sh
python scripts/generate.py
```

Requires Python 3.9+, no external dependencies.

---

## Notes

- IPv4 and IPv6 are in separate files (`_v4.txt` / `_v6.txt`) for compatibility with routers that handle them differently.
- `AxisOfEvil_v*.txt` is the deduplicated union of CCP + Russian + Iran + KP.
- Lines starting with `#` are comments — filter with `grep -v '^#'` before loading into ipset/nftables.
- The Action only commits when files actually change (diff check before commit).
- `list/README.md` is auto-generated on each run with live entry counts.
