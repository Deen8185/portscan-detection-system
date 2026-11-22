#!/usr/bin/env bash
# Record one lab scenario: normal traffic (optional) plus an Nmap scan
# (optional), captured on the lab bridge and converted to flows.
#
#     sudo bash lab/record_scenario.sh NAME NORMAL_SECONDS SEED "NMAP ARGS"
#
# Example:
#     sudo bash lab/record_scenario.sh train_syn 240 12 "-sS -T4 --top-ports 1000"
#
# Writes lab/captures/NAME.csv (flows) and NAME.json (what happened when);
# the raw capture stays in /root/lab_captures/NAME.pcap.
set -uo pipefail
NAME=$1; NORMAL=$2; SEED=$3; NMAP_ARGS=${4:-}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/captures"; RAW=/root/lab_captures
SCANNER=10.10.0.1; CLIENT=10.10.0.3; TARGET=10.10.0.2
mkdir -p "$OUT" "$RAW"
ip netns list | grep -q scanner || bash "$HERE/setup_lab.sh" >/dev/null

PCAP="$RAW/$NAME.pcap"
rm -f "$PCAP"
tcpdump -i br-lab -w "$PCAP" -U "ip and (tcp or udp)" >/dev/null 2>&1 &
TD=$!
sleep 2
START=$(date '+%Y-%m-%d %H:%M:%S')

NT=""
if (( NORMAL > 0 )); then
    ip netns exec client bash "$HERE/normal_traffic.sh" "$NORMAL" "$SEED" > "$RAW/$NAME.normal.log" 2>&1 &
    NT=$!
fi

SCAN_START=""; SCAN_END=""
if [[ -n "$NMAP_ARGS" ]]; then
    (( NORMAL > 0 )) && sleep 30
    SCAN_START=$(date '+%Y-%m-%d %H:%M:%S')
    # -n: no DNS lookups, so every flow from the scanner is part of the scan
    ip netns exec scanner nmap -n $NMAP_ARGS "$TARGET" -oX "$OUT/$NAME.nmap.xml" > "$RAW/$NAME.nmap.log" 2>&1
    SCAN_END=$(date '+%Y-%m-%d %H:%M:%S')
fi
[[ -n "$NT" ]] && wait "$NT"
sleep 5
END=$(date '+%Y-%m-%d %H:%M:%S')
kill "$TD"; wait "$TD" 2>/dev/null

/opt/cicflowmeter/bin/python "$HERE/pcap_to_flows.py" "$PCAP" "$OUT/$NAME.csv" >/dev/null 2>&1
FLOWS=$(( $(wc -l < "$OUT/$NAME.csv") - 1 ))

cat > "$OUT/$NAME.json" <<EOF
{
  "scenario": "$NAME",
  "nmap_args": "$NMAP_ARGS",
  "normal_seconds": $NORMAL,
  "seed": $SEED,
  "scanner_ip": "$SCANNER",
  "client_ip": "$CLIENT",
  "target_ip": "$TARGET",
  "capture_start": "$START",
  "capture_end": "$END",
  "scan_start": "$SCAN_START",
  "scan_end": "$SCAN_END",
  "pcap_bytes": $(stat -c %s "$PCAP"),
  "flows": $FLOWS,
  "normal_log": "$(tail -1 "$RAW/$NAME.normal.log" 2>/dev/null)"
}
EOF
echo "$(date '+%H:%M:%S') $NAME: $FLOWS flows (scan $SCAN_START -> $SCAN_END)"
