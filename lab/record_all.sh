#!/usr/bin/env bash
# Record every lab scenario (about 50 minutes). Run as root:
#     sudo bash lab/record_all.sh
#
# Training scenarios teach the lab model; test scenarios are kept apart and
# include scan types and speeds the model never saw during training.
#
# Resumable: a scenario whose lab/captures/NAME.json already exists is
# skipped, so after an interruption simply run the script again.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
R() {
    if [[ -f "$HERE/captures/$1.json" ]]; then
        echo "$(date '+%H:%M:%S') $1: already recorded, skipped"
    else
        bash "$HERE/record_scenario.sh" "$@"
    fi
}
bash "$HERE/setup_lab.sh"

#  name             normal_s seed  nmap arguments
R train_normal       360     11   ""
R train_syn          180     12   "-sS -T4 --top-ports 1000"
R train_connect      180     13   "-sT -T4 --top-ports 1000"
R train_syn_t3       180     14   "-sS -T3 -p 1-2000"

R test_normal        300     21   ""
R test_version       240     23   "-sV -T4 --top-ports 100"
R test_udp           240     24   "-sU -T4 --top-ports 50"
R test_fin           240     25   "-sF -T4 --top-ports 500"
R test_fullrange     240     26   "-sS -T4 -p-"
R test_slow          960     22   "-sS --scan-delay 15s --max-retries 1 -p 1-60"
echo "All scenarios recorded."
