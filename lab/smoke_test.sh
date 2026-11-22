#!/usr/bin/env bash
# Quick end-to-end check of the lab: capture a little normal traffic and a
# short scan, convert it with CICFlowMeter and show the output columns.
#     sudo bash lab/smoke_test.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ip netns list | grep -q scanner || bash "$HERE/setup_lab.sh" >/dev/null

OUT=/root/smoke
mkdir -p "$OUT" && cd "$OUT" && rm -rf in smoke.pcap smoke.csv
tcpdump -i br-lab -w smoke.pcap -U >/dev/null 2>&1 &
TD=$!
sleep 1
for i in 1 2 3; do ip netns exec client curl -s -o /dev/null http://10.10.0.2/; done
ip netns exec client mysql -h 10.10.0.2 -u labuser -plab-only-password campus -e "SELECT 1" >/dev/null
ip netns exec client lftp -u labuser,lab-only-password -e "ls; bye" 10.10.0.2 >/dev/null 2>&1
ip netns exec scanner nmap -sS -p 1-200 -T4 10.10.0.2 >/dev/null
sleep 2
kill "$TD"; wait "$TD" 2>/dev/null
echo "pcap bytes: $(stat -c %s smoke.pcap)"
/opt/cicflowmeter/bin/python "$HERE/pcap_to_flows.py" smoke.pcap smoke.csv >/dev/null 2>&1
echo "flows: $(( $(wc -l < smoke.csv) - 1 ))"
echo "columns:"
head -1 smoke.csv | tr ',' '\n' | paste -sd ' '
cp smoke.csv "$HERE/smoke.csv"
