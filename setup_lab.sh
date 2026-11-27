#!/bin/bash
set -e

echo "[*] Cleaning up existing namespaces if present..."
ip netns del ns-client 2>/dev/null || true
ip netns del ns-server 2>/dev/null || true

echo "[*] Creating network namespaces: ns-client and ns-server..."
ip netns add ns-client
ip netns add ns-server

echo "[*] Creating veth pair and linking namespaces..."
ip link add veth-client type veth peer name veth-server
ip link set veth-client netns ns-client
ip link set veth-server netns ns-server

echo "[*] Configuring IP addresses and bringing interfaces UP..."
ip netns exec ns-client ip addr add 192.168.100.1/24 dev veth-client
ip netns exec ns-client ip link set lo up
ip netns exec ns-client ip link set veth-client up

ip netns exec ns-server ip addr add 192.168.100.2/24 dev veth-server
ip netns exec ns-server ip link set lo up
ip netns exec ns-server ip link set veth-server up

echo "[*] Testing baseline connectivity before firewall..."
ip netns exec ns-client ping -c 2 192.168.100.2

echo "[*] Applying stateful iptables ruleset inside ns-server..."
ip netns exec ns-server bash -c '
  # 1. Flush existing rules
  iptables -F
  iptables -X

  # 2. Default Policies (Zero-Trust Inbound)
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  # 3. Loopback Protection
  iptables -A INPUT -i lo -j ACCEPT

  # 4. Drop Malformed / Invalid State Packets
  iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

  # 5. Stateful Connection Tracking (Allow Established & Related)
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # 6. Anti-Spoofing (Example: Drop loopback/reserved ranges arriving on external veth)
  # Note: In production, block RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) on WAN interfaces.
  # Here we allow 192.168.100.0/24 for our lab subnet while blocking other spoofed private ranges:
  iptables -A INPUT -i veth-server -s 127.0.0.0/8 -j DROP
  iptables -A INPUT -i veth-server -s 10.0.0.0/8 -j DROP
  iptables -A INPUT -i veth-server -s 172.16.0.0/12 -j DROP

  # 7. Service Allowlisting (Strictly allow new TCP connections on 443 and 8443)
  iptables -A INPUT -i veth-server -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A INPUT -i veth-server -p tcp --dport 8443 -m conntrack --ctstate NEW -j ACCEPT

  # 8. Log dropped packets for auditing (rate-limited)
  iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPTABLES-DROP: " --log-level 4
'

echo "[+] Setup complete! Exporting ns-server rules:"
ip netns exec ns-server iptables -S
