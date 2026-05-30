#!/bin/bash

# ─── Interfaces ───────────────────────────────────────────────
FWA_IFACE="enp0s1"    
FWB_IFACE="enp0s2"    

# ─── Hosts ────────────────────────────────────────────────────
FWA_IP="10.0.2.1"
FWB_IP="10.0.4.1"

# ══════════════════════════════════════════════════════════════
# 1. FLUSH
# ══════════════════════════════════════════════════════════════
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# ══════════════════════════════════════════════════════════════
# 2. DEFAULT POLICIES
# ══════════════════════════════════════════════════════════════
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

# ══════════════════════════════════════════════════════════════
# 3. INPUT — traffic FOR the IDS/IPS VM itself
# ══════════════════════════════════════════════════════════════

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# Established/related
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH management — from FWA side only
iptables -A INPUT -i $FWA_IFACE -s $FWA_IP -p tcp --dport 22 -j ACCEPT

# ICMP from both neighbors
iptables -A INPUT -i $FWA_IFACE -s $FWA_IP -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i $FWB_IFACE -s $FWB_IP -p icmp --icmp-type echo-request -j ACCEPT

# Log and drop
iptables -A INPUT -j LOG --log-prefix "[IDS-INPUT-DROP] " --log-level 4
iptables -A INPUT -j DROP

# ══════════════════════════════════════════════════════════════
# 4. FORWARD — the IDS/IPS passes all traffic through
#    Suricata running in NFQUEUE mode will inspect it first
#    and drop malicious packets before they reach FORWARD
# ══════════════════════════════════════════════════════════════

# Allow all forwarding between FWA and FWB sides
# Suricata intercepts via NFQUEUE — what Suricata approves gets forwarded
iptables -A FORWARD -i $FWA_IFACE -o $FWB_IFACE \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A FORWARD -i $FWB_IFACE -o $FWA_IFACE \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Send NEW connections through Suricata via NFQUEUE
iptables -A FORWARD -i $FWA_IFACE -o $FWB_IFACE \
  -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0

iptables -A FORWARD -i $FWB_IFACE -o $FWA_IFACE \
  -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0

# Anything not caught above — drop and log
iptables -A FORWARD -j LOG --log-prefix "[IDS-FORWARD-DROP] " --log-level 4
iptables -A FORWARD -j DROP

# ══════════════════════════════════════════════════════════════
# 5. NAT — masquerade so FWB sees IDS/IPS as source
# ══════════════════════════════════════════════════════════════
iptables -t nat -A POSTROUTING -o $FWB_IFACE -j MASQUERADE

echo "[IDS] iptables rules loaded successfully."
