# nft-block

This project started for me to learn nft and explore blocklists. It is deliberately
simple, not a hardened firewall distribution.

It periodically downloads several public lists and loads everything into a single nftables
ruleset that drops traffic from known internet-wide scanners, abuse-heavy ASNs, and reported
malicious IPs.

### Files

| Name | Purpose |
|---|---|
| [`nft-block.sh`](nft-block.sh) | Fetches blocklists, builds and loads the nftables ruleset |
| [`known-scanners.txt`](known-scanners.txt) | Hand-maintained list of research scanners (Shodan, Censys, Stretchoid, ...) |
| [`nft-block.service`](nft-block.service) | systemd unit that runs the script |
| [`nft-block.timer`](nft-block.timer) | Re-runs the service every ~4 h |

### Data sources

| Set name | Source | Dropped |
|---|---|---|
| `known-scanners` / `-v6` | Local curated list | Unconditionally (IPv4 + IPv6) |
| `ipfire-override-xd` / `-v6` | [IPFire override-xd](https://git.ipfire.org/?p=location/location-database.git;a=blob_plain;f=overrides/override-xd.txt) | Unconditionally (IPv4 + IPv6) |
| `spamhaus-asn` / `-v6` | [Spamhaus ASN-DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | Unconditionally (IPv4 + IPv6) |
| `abuseipdb` / `-v6` | [AbuseIPDB](https://www.abuseipdb.com/) | Non-service ports only (IPv4 + IPv6) |
| `duggytuxy-data-shield` | [duggytuxy Data-Shield](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) | Non-service ports only (IPv4) |
| `ctuaipp` | [Stratosphere Laboratory CTU-AIPP](https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/) | Non-service ports only (IPv4) |

### Ruleset structure

Two chains live in `table inet block`:

- `raw-filter` (prerouting @ `raw` — earliest possible hook): high-confidence sets
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
nstat
conntrack -L
```

### Suggested sysctl settings

Drop them into `/etc/sysctl.d/99-nft-block.conf` and apply with `sysctl --system`:

```conf
# anti-DoS
net.ipv4.tcp_synack_retries = 2           # syn flood
net.netfilter.nf_conntrack_tcp_loose = 0  # ack flood
net.ipv4.tcp_min_snd_mss = 536            # CVE-2019-11479

# path mtu / congestion friendliness
net.ipv4.tcp_ecn = 1                      # RFC 8087
net.ipv4.tcp_mtu_probing = 1              # RFC 4821
net.ipv4.tcp_shrink_window = 1            # RFC 7323

# spoofing and routing hygiene
net.ipv4.conf.all.rp_filter = 1           # RFC 3704
net.ipv4.conf.default.rp_filter = 1       # RFC 3704
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
```

### Limitations

- Rate-limiting isn't implemented: there are no nft `limit` rules.
- The dynamic reputation lists (Duggytuxy, CTU-AIPP) are IPv4 only; AbuseIPDB covers both families.
- Brief window during refresh where the ruleset exists but sets are empty.
- `known-scanners` is currently maintained by hand and may be outdated.

### References

- [`man systemd.service`](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [systemd Network Configuration Synchronization Points](https://systemd.io/NETWORK_ONLINE/)
- [`man nft`](https://www.netfilter.org/projects/nftables/manpage.html), [nftables wiki](https://wiki.nftables.org/wiki-nftables/), and [Ubuntu nftables documentation](https://documentation.ubuntu.com/security/security-features/network/firewall/nftables/)

### Further reading

- [Vincent Bernat: Coping with the TCP TIME-WAIT state on busy Linux servers (2014)](https://vincent.bernat.ch/en/blog/2014-tcp-time-wait-state-linux)
- [Jesper Brouer: DDoS protection Using Netfilter/iptables (2014)](https://people.netfilter.org/hawk/presentations/dknog4/iptables-ddos-mitigation_JesperBrouer.pdf)
- [Marek Majkowski: Lessons from defending the indefensible (2015)](https://blackhat.com/docs/eu-15/materials/eu-15-Majkowski-Lessons-From-Defending-The-Indefensible.pdf)
- [Marek Majkowski: Path MTU discovery in practice (2015)](https://blog.cloudflare.com/path-mtu-discovery-in-practice)
- [Understanding the Mirai Botnet (2017)](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-antonakakis.pdf)
- [Marek Majkowski: SYN packet handling in the wild (2018)](https://blog.cloudflare.com/syn-packet-handling-in-the-wild)
- [Marek Majkowski: Conntrack tales - one thousand and one flows (2020)](https://blog.cloudflare.com/conntrack-tales-one-thousand-and-one-flows/)
- [Mike Freemon: Unbounded memory usage by TCP for receive buffers, and how we fixed it (2023)](https://blog.cloudflare.com/unbounded-memory-usage-by-tcp-for-receive-buffers-and-how-we-fixed-it/)
- [Intrisec: ShadowSyndicate Infrastructure Illumination (2025)](https://www.intrinsec.com/wp-content/uploads/2025/10/TLP-CLEAR-31072025-ShadowSyndicate-infrastructure-illumination-EN.pdf)
- [Internet Weather Report: ASN Watchlist (2025)](https://internetweather.net/asn-watchlist/)
- [Breakglass: Block One ASN, Kill Sixteen Malware Families (2026)](https://intel.breakglass.tech/post/omegatech-bph-as202412-67-c2-servers-16-malware-families-one-subnet)
- [Bob Rudis: Bulletproof Hosting Watch (2026)](https://ai.rud.is/tags/bulletproof/)

### Acknowledgements

- [bgp.tools](https://bgp.tools/)
- [Pulsedive](https://pulsedive.com/)
- [jq](https://jqlang.org/), [netfilter](https://www.netfilter.org/), and [systemd](https://systemd.io/)

### AI Usage

[Qwen3.8-27b](https://huggingface.co/Qwen/Qwen3.8-27B) and [Qwen3.8-Flash-Next](https://qwen.ai/blog?id=qwen3.8-flash-next)

### License

[Apache 2.0](https://opensource.org/license/apache-2.0); Data sources have their own terms.