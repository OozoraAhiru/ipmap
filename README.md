# ipmap

Daily-updated IP CIDR blocklists, built from authoritative RIR data (APNIC / ARIN / LACNIC / RIPE NCC / AFRINIC).  
A GitHub Action fetches the upstream `delegated-extended-latest` files every day at 04:00 UTC and commits fresh lists to `lists/`.

---

## Files

| File | Countries | Description |
|------|-----------|-------------|
| `CCP.txt` | CN, HK, MO | Chinese Communist Party direct control |
| `Russian.txt` | RU, BY, KZ, AM, KG, TJ, MD | Russian sphere of influence (CSTO + Belarus) |
| `Iran.txt` | IR, LB, YE, IQ | Iranian axis of resistance proxy states |
| `AxisOfEvil.txt` | all of the above + KP | All state-actor threats combined |
| `HackerTier1.txt` | NG, RO, BR, UA | High-confidence cybercrime sources |
| `HackerTier2.txt` | IN, ID, VN, PK, BD | Significant cybercrime sources |
| `HackerTier3.txt` | TR, MA, DZ, MX | Moderate cybercrime sources |
| `AsianScams.txt` | MM, KH, LA, PH | Southeast Asian scam farm operations |

---

## Raw URLs (for routers / scripts)

Replace `main` with your branch name if different.

```
https://raw.githubusercontent.com/YOUR_USERNAME/geoblock-lists/main/lists/CCP.txt
https://raw.githubusercontent.com/YOUR_USERNAME/geoblock-lists/main/lists/Russian.txt
https://raw.githubusercontent.com/YOUR_USERNAME/geoblock-lists/main/lists/Iran.txt
https://raw.githubusercontent.com/YOUR_USERNAME/geoblock-lists/main/lists/AxisOfEvil.txt
https://raw.githubusercontent.com/YOUR_USERNAME/geoblock-lists/main/lists/HackerTier1.txt
https://raw.githubusercontent.com/YOUR_USERNAME/geoblock-lists/main/lists/HackerTier2.txt
https://raw.githubusercontent.com/YOUR_USERNAME/geoblock-lists/main/lists/HackerTier3.txt
https://raw.githubusercontent.com/YOUR_USERNAME/geoblock-lists/main/lists/AsianScams.txt
```

---

## Router usage examples

### OpenWrt / nftables
```sh
# Download a list and add to an nftables set
curl -sL "https://raw.githubusercontent.com/YOUR_USERNAME/geoblock-lists/main/lists/AxisOfEvil.txt" \
  | grep -v '^#' \
  | xargs -I{} nft add element inet fw4 block_src { {} }
```

### OpenWrt / ipset (iptables)
```sh
ipset create AXIS_OF_EVIL hash:net
curl -sL "https://raw.githubusercontent.com/YOUR_USERNAME/geoblock-lists/main/lists/AxisOfEvil.txt" \
  | grep -v '^#' \
  | while read cidr; do ipset add AXIS_OF_EVIL "$cidr"; done
iptables -I INPUT -m set --match-set AXIS_OF_EVIL src -j DROP
```

### DD-WRT / Tomato
Load via a startup script using the same `ipset` method above.

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

- Lists include **both IPv4 and IPv6** prefixes.
- `AxisOfEvil.txt` is the union of CCP + Russian + Iran + KP — deduplicated.
- Lines starting with `#` are comments and safe to ignore in any parser.
- The Action only commits when files actually change (diff check before commit).
