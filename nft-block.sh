#!/usr/bin/env bash
set -euo pipefail

fetch() {
  local name="$1"; shift
  local out="$1"; shift
  if "$@" >>"$out" 2>/dev/null; then
    echo "[ok] $name ($(wc -l <"$out") lines)"
  else
    echo "[skip] $name (unavailable)" >&2
    return 0
  fi
}

known_scanners="$(dirname "$(readlink -f "$0")")/known-scanners.txt"
scanners=$(mktemp)
if [[ -f "$known_scanners" ]]; then
  awk '
    /^[[:space:]]*#/ || !NF { next }
    $1 !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ {
      print "  [warn] bad line in known-scanners: " $0 > "/dev/stderr"; next }
    { print $1 }' "$known_scanners" >"$scanners"
else
  echo "[warn] known scanners list not found: $known_scanners" >&2
fi

duggytuxy=$(mktemp)
ctuaipp=$(mktemp)
spamhaus_asn=$(mktemp)
spamhaus_asns=$(mktemp)
bgptable=$(mktemp)
ipfirexd=$(mktemp)
ipfireasns=$(mktemp)
ipfirenets=$(mktemp)
ipfireasn=$(mktemp)
abuseipdb=$(mktemp)
trap 'rm -f "$scanners" "$spamhaus_asn" "$spamhaus_asns" "$bgptable" "$ipfirexd" "$ipfireasns" "$ipfirenets" "$ipfireasn" "$abuseipdb" "$ctuaipp" "$duggytuxy"' EXIT

fetch "duggytuxy"   "$duggytuxy"   bash -c "wget --secure-protocol=TLSv1_3 -qO- 'https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt' | grep -Exo '([0-9]{1,3}\.){3}[0-9]{1,3}'"
fetch "ctuaipp"     "$ctuaipp"     bash -c "wget --secure-protocol=TLSv1_3 -qO- 'https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_blacklist_for_IPs_seen_last_24_hours.csv' | grep -Exo '([0-9]{1,3}\.){3}[0-9]{1,3}'"
fetch "spamhaus-asn-list" "$spamhaus_asns" bash -c "wget --secure-protocol=TLSv1_3 -qO- 'https://www.spamhaus.org/drop/asndrop.json' | jq -r '.asn // empty'"
fetch "bgp-tools-table"  "$bgptable"     wget --secure-protocol=TLSv1_3 -qO- 'https://bgp.tools/table.txt'
# join: IPv4 prefixes from the bgp.tools routing table whose ASN is in the Spamhaus ASN-DROP list
if [[ -s "$spamhaus_asns" && -s "$bgptable" ]]; then
  awk 'NR==FNR { a[$1]=1; next }
       ($2 in a) && ($1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) { print $1 }' \
    "$spamhaus_asns" "$bgptable" | sort -u >"$spamhaus_asn"
  echo "[ok] spamhaus-asn ($(wc -l <"$spamhaus_asn") prefixes from $(wc -l <"$spamhaus_asns") ASNs)"
fi
fetch "abuseipdb"   "$abuseipdb"   bash -c "wget --secure-protocol=TLSv1_3 -qO- 'https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/abuseipdb_blacklist_ip_score_75.txt' | grep -v ':'"
fetch "ipfire-override-xd" "$ipfirexd" wget --secure-protocol=TLSv1_3 -qO- 'https://git.ipfire.org/?p=location/location-database.git;a=blob_plain;f=overrides/override-xd.txt'
# extract drop:yes ASNs (strip "AS" prefix) and direct IPv4 net: prefixes from override-xd
if [[ -s "$ipfirexd" ]]; then
  awk '
    /^aut-num:[[:space:]]+AS[0-9]+/ { cur = $2; sub(/^AS/, "", cur); rec = cur; next }
    /^net:[[:space:]]+/             { rec = ""; net = $2; if (net ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) print net > NETS; next }
    /^drop:[[:space:]]+yes/ {
      if (rec != "") print rec > ASNS;
      rec = "" }
  ' ASNS="$ipfireasns" NETS="$ipfirenets" "$ipfirexd"
fi
# join: IPv4 prefixes from the bgp.tools routing table whose ASN is in the IPFire override-xd drop list
if [[ -s "$ipfireasns" && -s "$bgptable" ]]; then
  {
    awk 'NR==FNR { a[$1]=1; next }
         ($2 in a) && ($1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) { print $1 }' \
      "$ipfireasns" "$bgptable"
    [[ -s "$ipfirenets" ]] && cat "$ipfirenets"
  } | sort -u >"$ipfireasn"
  echo "[ok] ipfire-override-xd ($(wc -l <"$ipfireasn") prefixes from $(wc -l <"$ipfireasns") ASNs + $(wc -l <"$ipfirenets" 2>/dev/null || echo 0) direct nets)"
fi

nft -f- <<EOF
table inet block
delete table inet block
table inet block {
  set known-scanners {
    type ipv4_addr
    flags interval
    auto-merge
  }
  set duggytuxy-data-shield {
    type ipv4_addr
    flags interval
    auto-merge
  }
  set ctuaipp {
    type ipv4_addr
    flags interval
    auto-merge
  }
  set abuseipdb {
    type ipv4_addr
    flags interval
    auto-merge
  }
  set spamhaus-asn {
    type ipv4_addr
    flags interval
    auto-merge
  }
  set ipfire-override-xd {
    type ipv4_addr
    flags interval
    auto-merge
  }
  chain raw-filter {
    type filter hook prerouting priority raw;
    ip saddr @known-scanners counter drop;
    ip saddr @ipfire-override-xd counter drop;
    ip saddr @spamhaus-asn counter drop;
    tcp dport { 25, 80, 443 } accept;
    udp dport 443 accept;
    # separate counter and drop to measure individual impacts
    ip saddr @abuseipdb counter;
    ip saddr @duggytuxy-data-shield counter;
    ip saddr @ctuaipp counter;
    ip saddr @abuseipdb drop;
    ip saddr @duggytuxy-data-shield drop;
    ip saddr @ctuaipp drop;
  }
  chain proto-filter {
    type filter hook input priority filter; policy drop; iif lo accept;
    ct state established,related accept; ct state invalid drop;
    ether type ip  ip protocol { icmp, igmp } accept;
    ether type ip6 ip6 nexthdr icmpv6 accept;
    tcp dport { 22, 25, 80, 443, 465, 853, 993 } accept;
    udp dport 443 accept;
    # DHCPv4 and DHCPv6
    udp sport 67 udp dport 68 accept; udp sport 68 udp dport 67 accept;
    udp sport 547 udp dport 546 accept; udp sport 546 udp dport 547 accept;
    # broadcast/subnet-broadcast noise
    fib daddr type { broadcast, multicast } counter drop;
    log prefix "proto-block: " counter;
  }
}
EOF

for set_name in known-scanners duggytuxy-data-shield ctuaipp abuseipdb spamhaus-asn ipfire-override-xd; do
  case "$set_name" in
    known-scanners) src_file="$scanners" ;;
    duggytuxy-data-shield) src_file="$duggytuxy" ;;
    ctuaipp) src_file="$ctuaipp" ;;
    abuseipdb) src_file="$abuseipdb" ;;
    spamhaus-asn) src_file="$spamhaus_asn" ;;
    ipfire-override-xd) src_file="$ipfireasn" ;;
  esac
  [[ -s "$src_file" ]] || continue
  readarray -t ips < <(grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' "$src_file")
  for ((i=0; i<${#ips[@]}; i+=20000)); do
    batch=("${ips[@]:$i:20000}")
    batch_with_commas=$(IFS=','; echo "${batch[*]}")
    echo "add element inet block $set_name { $batch_with_commas }" | nft -f-
  done
done
