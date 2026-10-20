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
scanners6=$(mktemp)
if [[ -f "$known_scanners" ]]; then
  awk -v V4="$scanners" -v V6="$scanners6" '
    /^[[:space:]]*#/ || !NF { next }
    $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ { print $1 >> V4; next }
    $1 ~ /^[0-9A-Fa-f]+:[0-9A-Fa-f:]+(\/[0-9]+)?$/     { print $1 >> V6; next }
    { print "  [warn] bad line in known-scanners: " $0 > "/dev/stderr" }' "$known_scanners"
else
  echo "[warn] known scanners list not found: $known_scanners" >&2
fi

duggytuxy=$(mktemp)
ctuaipp=$(mktemp)
spamhaus_asn=$(mktemp)
spamhaus_asn6=$(mktemp)
spamhaus_asns=$(mktemp)
bgptable=$(mktemp)
ipfirexd=$(mktemp)
ipfireasns=$(mktemp)
ipfirenets=$(mktemp)
ipfirenets6=$(mktemp)
ipfireasn=$(mktemp)
ipfireasn6=$(mktemp)
abuseipdb=$(mktemp)
abuseipdb6=$(mktemp)
abuseipdb_raw=$(mktemp)
trap 'rm -f "$scanners" "$scanners6" "$spamhaus_asn" "$spamhaus_asn6" "$spamhaus_asns" "$bgptable" "$ipfirexd" "$ipfireasns" "$ipfirenets" "$ipfirenets6" "$ipfireasn" "$ipfireasn6" "$abuseipdb" "$abuseipdb6" "$abuseipdb_raw" "$ctuaipp" "$duggytuxy"' EXIT

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
# join: IPv6 prefixes from the bgp.tools routing table whose ASN is in the Spamhaus ASN-DROP list
if [[ -s "$spamhaus_asns" && -s "$bgptable" ]]; then
  awk 'NR==FNR { a[$1]=1; next }
       ($2 in a) && ($1 ~ /^[0-9A-Fa-f]+:[0-9A-Fa-f:]*\/[0-9]+$/) { print $1 }' \
    "$spamhaus_asns" "$bgptable" | sort -u >"$spamhaus_asn6"
  echo "[ok] spamhaus-asn-v6 ($(wc -l <"$spamhaus_asn6") prefixes)"
fi
fetch "abuseipdb"   "$abuseipdb_raw" wget --secure-protocol=TLSv1_3 -qO- 'https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/abuseipdb_blacklist_ip_score_75.txt'
# split the mixed feed into validated IPv4 and IPv6 entries
if [[ -s "$abuseipdb_raw" ]]; then
  awk -v V4="$abuseipdb" -v V6="$abuseipdb6" '
    /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ { print > V4; next }
    /^[0-9A-Fa-f]+:[0-9A-Fa-f:]+(\/[0-9]+)?$/     { print > V6; next }' "$abuseipdb_raw"
  echo "[ok] abuseipdb split ($(wc -l <"$abuseipdb" 2>/dev/null || echo 0) v4 + $(wc -l <"$abuseipdb6" 2>/dev/null || echo 0) v6)"
fi
fetch "ipfire-override-xd" "$ipfirexd" wget --secure-protocol=TLSv1_3 -qO- 'https://git.ipfire.org/?p=location/location-database.git;a=blob_plain;f=overrides/override-xd.txt'
# extract drop:yes ASNs (strip "AS" prefix) and direct IPv4/IPv6 net: prefixes from override-xd
if [[ -s "$ipfirexd" ]]; then
  awk '
    /^aut-num:[[:space:]]+AS[0-9]+/ { cur = $2; sub(/^AS/, "", cur); rec = cur; next }
    /^net:[[:space:]]+/ {
      rec = ""; net = $2
      if (net ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/)          print net > NETS
      else if (net ~ /^[0-9A-Fa-f]+:[0-9A-Fa-f:]*\/[0-9]+$/)           print net > NETS6
      next }
    /^drop:[[:space:]]+yes/ {
      if (rec != "") print rec > ASNS;
      rec = "" }
  ' ASNS="$ipfireasns" NETS="$ipfirenets" NETS6="$ipfirenets6" "$ipfirexd"
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
# join: IPv6 prefixes from the bgp.tools routing table whose ASN is in the IPFire override-xd drop list
if [[ -s "$ipfireasns" && -s "$bgptable" ]]; then
  {
    awk 'NR==FNR { a[$1]=1; next }
         ($2 in a) && ($1 ~ /^[0-9A-Fa-f]+:[0-9A-Fa-f:]*\/[0-9]+$/) { print $1 }' \
      "$ipfireasns" "$bgptable"
    [[ -s "$ipfirenets6" ]] && cat "$ipfirenets6"
  } | sort -u >"$ipfireasn6"
  echo "[ok] ipfire-override-xd-v6 ($(wc -l <"$ipfireasn6") prefixes)"
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
  set known-scanners-v6 {
    type ipv6_addr
    flags interval
    auto-merge
  }
  set spamhaus-asn-v6 {
    type ipv6_addr
    flags interval
    auto-merge
  }
  set ipfire-override-xd-v6 {
    type ipv6_addr
    flags interval
    auto-merge
  }
  set abuseipdb-v6 {
    type ipv6_addr
    flags interval
    auto-merge
  }
  chain raw-filter {
    type filter hook prerouting priority raw;
    ip saddr @known-scanners counter drop;
    ip saddr @ipfire-override-xd counter drop;
    ip saddr @spamhaus-asn counter drop;
    ip6 saddr @known-scanners-v6 counter drop;
    ip6 saddr @ipfire-override-xd-v6 counter drop;
    ip6 saddr @spamhaus-asn-v6 counter drop;
    tcp dport { 25, 80, 443 } accept;
    udp dport 443 accept;
    # separate counter and drop to measure individual impacts
    ip saddr @abuseipdb counter;
    ip6 saddr @abuseipdb-v6 counter;
    ip saddr @duggytuxy-data-shield counter;
    ip saddr @ctuaipp counter;
    ip saddr @abuseipdb drop;
    ip6 saddr @abuseipdb-v6 drop;
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

for set_name in known-scanners known-scanners-v6 duggytuxy-data-shield ctuaipp abuseipdb abuseipdb-v6 \
                spamhaus-asn spamhaus-asn-v6 ipfire-override-xd ipfire-override-xd-v6; do
  case "$set_name" in
    known-scanners) src_file="$scanners" ;;
    known-scanners-v6) src_file="$scanners6" ;;
    duggytuxy-data-shield) src_file="$duggytuxy" ;;
    ctuaipp) src_file="$ctuaipp" ;;
    abuseipdb) src_file="$abuseipdb" ;;
    abuseipdb-v6) src_file="$abuseipdb6" ;;
    spamhaus-asn) src_file="$spamhaus_asn" ;;
    spamhaus-asn-v6) src_file="$spamhaus_asn6" ;;
    ipfire-override-xd) src_file="$ipfireasn" ;;
    ipfire-override-xd-v6) src_file="$ipfireasn6" ;;
  esac
  [[ -s "$src_file" ]] || continue
  case "$set_name" in
    *-v6) pattern='^[0-9A-Fa-f]+:[0-9A-Fa-f:]+(/[0-9]+)?$' ;;
    *)    pattern='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' ;;
  esac
  readarray -t ips < <(grep -E "$pattern" "$src_file")
  for ((i=0; i<${#ips[@]}; i+=20000)); do
    batch=("${ips[@]:$i:20000}")
    batch_with_commas=$(IFS=','; echo "${batch[*]}")
    echo "add element inet block $set_name { $batch_with_commas }" | nft -f-
  done
done
