# nft-block

This project started for me to **learn nft** and **explore data sources**. It is deliberately
simple, not a hardened firewall distribution.

It periodically downloads several public blocklists and loads everything into a single nftables
ruleset that drops traffic from known internet-wide scanners, abuse-heavy ASNs, and reported
malicious IPs.

### Files

| File | Purpose |
|---|---|
| [`nft-block.sh`](nft-block.sh) | Fetches blocklists, builds and loads the nftables ruleset |
| [`known-scanners.txt`](known-scanners.txt) | Hand-maintained list of research scanners (Shodan, Censys, Stretchoid, ...) |
| [`nft-block.service`](nft-block.service) | systemd unit that runs the script |
| [`nft-block.timer`](nft-block.timer) | Re-runs the service every ~4 h |

### Data sources

| Set name | Source | Strategy |
|---|---|---|
| `known-scanners` | Local curated list | Dropped unconditionally |
| `ipfire-override-xd` | IPFire | Dropped unconditionally |
| `spamhaus-asn` | Spamhaus | Dropped unconditionally |
| `abuseipdb` | AbuseIPDB | Dropped on non-service ports only |
| `duggytuxy-data-shield` | Duggytuxy | Dropped on non-service ports only |
| `ctuaipp` | CTU-AIPP | Dropped on non-service ports only |

### Ruleset structure

Two chains live in `table inet block`:

- **`raw-filter`** (prerouting @ `raw` — earliest possible hook):  high-confidence sets
  drop immediately; then `tcp dport {25,80,443}` and `udp dport 443` `accept` short-circuit the
  chain so the *dynamic* lists can never lock out legitimate mail/web visitors, while port probes
  to other ports still get blocked. The dynamic lists use separate `counter`-then-`drop` rule pairs
  to measure each list's individual impact.
- **`proto-filter`** (input @ `filter`, `policy drop`): accepts loopback,
  established/related, ICMP/IGMP/ICMPv6 and all TCP/UDP; anything else (ESP, GRE, stray protocols)
  is logged with the `proto-block:` prefix and dropped.

### Monitoring

```sh
systemctl status nft-block
nft -to list table inet block |grep counter
```

### Limitations

- **IPv4 only** — IPv6 traffic is accepted and not filtered.
- Brief window during refresh where the ruleset exists but sets are empty.

### Acknowledgements

- [AbuseIPDB](https://www.abuseipdb.com/)
- [CTU-AIPP](https://github.com/stratosphereips/AIP)
- [Duggytuxy Data-Shield](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist)
- [IPFire](https://www.ipfire.org/)
- [jq](https://jqlang.org/)
- [netfilter](https://www.netfilter.org/)
- [Spamhaus ASN-DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
- [systemd](https://systemd.io/)

### License

[Apache 2.0](https://opensource.org/license/apache-2.0) Data sources have their own terms.