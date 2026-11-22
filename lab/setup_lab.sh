#!/usr/bin/env bash
# Build the isolated scanning lab inside Ubuntu (WSL). Run as root:
#     sudo bash lab/setup_lab.sh
#
#   [scanner 10.10.0.1] --+
#                         +-- bridge br-lab = target 10.10.0.2 (FTP, SSH, HTTP, MySQL)
#   [client  10.10.0.3] --+
#
# The scanner and client are Linux network namespaces: separate network
# stacks with their own IP addresses, connected to the target through a
# virtual bridge. Nothing here is reachable from outside this computer.
# Safe to run again; it rebuilds the lab from scratch.
set -euo pipefail

BRIDGE=br-lab
TARGET_IP=10.10.0.2

ip netns del scanner 2>/dev/null || true
ip netns del client 2>/dev/null || true
ip link del "$BRIDGE" 2>/dev/null || true

ip link add "$BRIDGE" type bridge
ip addr add "$TARGET_IP/24" dev "$BRIDGE"
ip link set "$BRIDGE" up

add_host () {            # name ip
    local ns=$1 ip=$2
    ip netns add "$ns"
    ip link add "v-$ns" type veth peer name eth0 netns "$ns"
    ip link set "v-$ns" master "$BRIDGE" up
    ip netns exec "$ns" ip addr add "$ip/24" dev eth0
    ip netns exec "$ns" ip link set eth0 up
    ip netns exec "$ns" ip link set lo up
    # The target doubles as the lab's router, so namespace traffic to the
    # internet also crosses br-lab and appears in the capture.
    ip netns exec "$ns" ip route add default via "$TARGET_IP"
    mkdir -p "/etc/netns/$ns"
    grep '^nameserver' /etc/resolv.conf > "/etc/netns/$ns/resolv.conf"
}
add_host scanner 10.10.0.1
add_host client  10.10.0.3

# Internet access for the lab (needed for realistic normal traffic)
sysctl -qw net.ipv4.ip_forward=1
nft delete table ip lab_nat 2>/dev/null || true
nft add table ip lab_nat
nft add chain ip lab_nat post '{ type nat hook postrouting priority 100 ; }'
nft add rule ip lab_nat post ip saddr 10.10.0.0/24 oifname != "$BRIDGE" masquerade

# Target services (installed by lab/install_lab.sh)
for s in vsftpd ssh nginx mariadb; do systemctl start "$s"; done

echo "Lab ready."
for ns in scanner client; do
    printf "  %-8s %s -> target %s: " "$ns" "$(ip netns exec $ns ip -4 -o addr show eth0 | awk '{print $4}')" "$TARGET_IP"
    ip netns exec "$ns" ping -c1 -W1 "$TARGET_IP" >/dev/null && echo -n "reachable" || echo -n "UNREACHABLE"
    ip netns exec "$ns" curl -s -m 8 -o /dev/null https://example.com && echo ", internet OK" || echo ", no internet"
done
