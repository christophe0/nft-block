# nft-block

This project started for me to learn nft and explore data sources. It is deliberately
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
| `known-scanners` / `-v6` | Local curated list | Dropped unconditionally (IPv4 + IPv6) |
| `ipfire-override-xd` / `-v6` | IPFire | Dropped unconditionally (IPv4 + IPv6) |
| `spamhaus-asn` / `-v6` | Spamhaus | Dropped unconditionally (IPv4 + IPv6) |
| `abuseipdb` | AbuseIPDB | Dropped on non-service ports only (IPv4) |
| `duggytuxy-data-shield` | Duggytuxy | Dropped on non-service ports only (IPv4) |
| `ctuaipp` | CTU-AIPP | Dropped on non-service ports only (IPv4) |

### Ruleset structure

Two chains live in `table inet block`:

- `raw-filter` (prerouting @ `raw` — earliest possible hook):  high-confidence sets
  drop immediately; then `tcp dport {25,80,443}` and `udp dport 443` `accept` short-circuit the
  chain so the *dynamic* lists can never lock out legitimate mail/web visitors, while port probes
  to other ports still get blocked. The dynamic lists use separate `counter`-then-`drop` rule pairs
  to measure each list's individual impact.
- `proto-filter` (input @ `filter`, `policy drop`): default-deny port allowlist. Accepts loopback,
  established/related, ICMP/IGMP/ICMPv6, `tcp dport { 22, 25, 80, 443, 465, 853, 993 }` and
  `udp dport 443`; anything else (other ports, ESP, GRE, stray protocols) is logged with the
  `proto-block:` prefix and dropped. Applies to IPv6 as well, so the open port set is identical
  for both families.

### Monitoring

```sh
systemctl status nft-block
nft -to list table inet block |grep counter
```

### Limitations

- The dynamic reputation lists (AbuseIPDB, Duggytuxy, CTU-AIPP) are IPv4 only.
- Brief window during refresh where the ruleset exists but sets are empty.
- `known-scanners.txt` is currently maintained by hand and may be outdated.

### References

- [`man systemd.service`](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [Network Configuration Synchronization Points](https://systemd.io/NETWORK_ONLINE/)
- [`man nft`](https://www.netfilter.org/projects/nftables/manpage.html)
- [nftables wiki](https://wiki.nftables.org/wiki-nftables/)
- [Ubuntu nftables documentation](https://documentation.ubuntu.com/security/security-features/network/firewall/nftables/)

### Further reading

- [Jesper Brouer: DDoS protection Using Netfilter/iptables (2014)](https://people.netfilter.org/hawk/presentations/dknog4/iptables-ddos-mitigation_JesperBrouer.pdf)
- [Marek Majkowski: Lessons from defending the indefensible (2015)](https://blackhat.com/docs/eu-15/materials/eu-15-Majkowski-Lessons-From-Defending-The-Indefensible.pdf)
- [Understanding the Mirai Botnet (2017)](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-antonakakis.pdf)
- [Intrisec: ShadowSyndicate Infrastructure Illumination (2025)](https://www.intrinsec.com/wp-content/uploads/2025/10/TLP-CLEAR-31072025-ShadowSyndicate-infrastructure-illumination-EN.pdf)
- [Internet Weather Report: ASN Watchlist (2025)](https://internetweather.net/asn-watchlist/)
- [Breakglass: Block One ASN, Kill Sixteen Malware Families (2026)](https://intel.breakglass.tech/post/omegatech-bph-as202412-67-c2-servers-16-malware-families-one-subnet)
- [ipapi.is: Most Abusive ASNs on the Internet](https://ipapi.is/most-abusive-asn.html)

### Acknowledgements

- [AbuseIPDB](https://www.abuseipdb.com/)
- [bgp.tools](https://bgp.tools/)
- [Stratosphere Laboratory CTU-AIPP](https://github.com/stratosphereips/AIP)
- [Duggytuxy Data-Shield](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist)
- [IPFire](https://www.ipfire.org/)
- [Spamhaus ASN-DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
- [jq](https://jqlang.org/), [netfilter](https://www.netfilter.org/), and [systemd](https://systemd.io/)

### AI Usage

*[Qwen3.8-27b](https://huggingface.co/Qwen/Qwen3.8-27B)* and *[Qwen3.8-Flash-Next](https://qwen.ai/blog?id=qwen3.8-flash-next)* were used via during the development of this project.

### License

[Apache 2.0](https://opensource.org/license/apache-2.0); Data sources have their own terms.