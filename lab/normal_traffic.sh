#!/usr/bin/env bash
# Generate realistic normal (benign) traffic from the client namespace for
# DURATION seconds. Run inside the client namespace:
#     ip netns exec client bash lab/normal_traffic.sh DURATION [SEED]
#
# Mimics a student or staff member: intranet pages and file downloads,
# SSH sessions, FTP transfers, database queries and public websites,
# at random intervals.
set -u
DURATION=${1:-300}
RANDOM=${2:-1}
TARGET=10.10.0.2
USER=labuser
PASS=lab-only-password
SITES=(https://example.com https://www.wikipedia.org https://www.python.org https://github.com
       https://www.bbc.co.uk https://www.gnu.org https://www.ietf.org https://www.unb.ca)
PAGES=(/ /index.html /files/timetable.pdf /files/notes.pdf /files/report.pdf /missing-page /admin)
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5"

end=$(( SECONDS + DURATION ))
count=0
while (( SECONDS < end )); do
    case $(( RANDOM % 10 )) in
        0|1|2) curl -s -m 10 -o /dev/null "http://$TARGET${PAGES[RANDOM % ${#PAGES[@]}]}" ;;
        3)     sshpass -p "$PASS" ssh $SSH_OPTS "$USER@$TARGET" "uptime; ls -la shared; df -h /" >/dev/null 2>&1 ;;
        4)     lftp -u "$USER,$PASS" -e "set net:timeout 5; cd shared; get notes.pdf -o /tmp/notes.pdf; bye" "$TARGET" >/dev/null 2>&1 ;;
        5)     head -c $(( (RANDOM % 200 + 10) * 1024 )) /dev/urandom > /tmp/upload.bin
               lftp -u "$USER,$PASS" -e "set net:timeout 5; put /tmp/upload.bin -o upload_$RANDOM.bin; bye" "$TARGET" >/dev/null 2>&1 ;;
        6|7)   mysql -h "$TARGET" -u "$USER" -p"$PASS" campus --connect-timeout=5 -e \
                   "INSERT INTO results (student, score) VALUES ('s$RANDOM', $(( RANDOM % 100 ))); SELECT COUNT(*), AVG(score) FROM results;" >/dev/null 2>&1 ;;
        8|9)   curl -s -m 15 -o /dev/null "${SITES[RANDOM % ${#SITES[@]}]}" ;;
    esac
    count=$(( count + 1 ))
    sleep "$(( RANDOM % 4 )).$(( RANDOM % 10 ))"
done
echo "normal traffic: $count actions in $DURATION s"
