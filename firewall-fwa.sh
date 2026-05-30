#!/bin/bash

# ─── Interfaces ───────────────────────────────────────────────
WAN="enp0s1"        # from Router — 10.0.0.2
LAN="enp0s2"        # toward IDS/IPS — 10.0.2.1
HA="enp0s3"         # HA heartbeat — 10.0.1.1

# ─── Subnets ──────────────────────────────────────────────────
WAN_NET="10.0.0.0/29"
LAN_NET="10.0.2.0/29"

# Downstream subnets (behind FWB — FWA must know about these for return routing)
PUBLIC_DMZ="172.16.10.0/24"
PRIVATE_DMZ="172.16.20.0/24"
INTERNAL_LAN="192.168.10.0/24"

# ─── Hosts ────────────────────────────────────────────────────
ROUTER_IP="10.0.0.1"
IDS_IP="10.0.2.3"
FWA2_HA_IP="10.0.1.2"

# ══════════════════════════════════════════════════════════════
# 1. FLUSH all existing rules
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
# 3. INPUT — traffic destined FOR FWA itself
# ══════════════════════════════════════════════════════════════

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# Established/related sessions
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ── HA Cluster Rules ──────────────────────────────────────────
# Allow all traffic on the dedicated HA link (safest for cluster nodes)
iptables -A INPUT -i $HA -j ACCEPT

# Explicitly allow Heartbeat UDP port 694 (In case broadcast hits WAN/LAN)
iptables -A INPUT -p udp --dport 694 -j ACCEPT

# ── ICMP / Diagnostic ─────────────────────────────────────────
# Allow ping from Router and IDS to any IP on this host (including VIPs)
iptables -A INPUT -i $WAN -s $ROUTER_IP -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i $LAN -s $IDS_IP    -p icmp --icmp-type echo-request -j ACCEPT

# ── SSH management ────────────────────────────────────────────
# Only from IDS/IPS side
iptables -A INPUT -i $LAN -s $IDS_IP -p tcp --dport 22 -j ACCEPT

# ── Log and drop everything else ──────────────────────────────
iptables -A INPUT -j LOG --log-prefix "[FWA-INPUT-DROP] " --log-level 4
iptables -A INPUT -j DROP

# ══════════════════════════════════════════════════════════════
# 4. FORWARD — traffic passing THROUGH FWA
# ══════════════════════════════════════════════════════════════

# Stateful — allow established/related in both directions
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ── WAN → LAN (inbound from Router toward IDS/IPS) ────────────

# HTTP/HTTPS toward web server (downstream — FWA passes it on)
iptables -A FORWARD -i $WAN -o $LAN \
  -p tcp -m multiport --dports 80,443 \
  -m conntrack --ctstate NEW -j ACCEPT

# DNS
iptables -A FORWARD -i $WAN -o $LAN \
  -p udp --dport 53 \
  -m conntrack --ctstate NEW -j ACCEPT

iptables -A FORWARD -i $WAN -o $LAN \
  -p tcp --dport 53 \
  -m conntrack --ctstate NEW -j ACCEPT

# SMTP/IMAP/IMAPS toward mail server
iptables -A FORWARD -i $WAN -o $LAN \
  -p tcp -m multiport --dports 25,143,993 \
  -m conntrack --ctstate NEW -j ACCEPT

# ICMP — allow ping through for diagnostics
iptables -A FORWARD -i $WAN -o $LAN \
  -p icmp --icmp-type echo-request \
  -m conntrack --ctstate NEW -j ACCEPT

# ── LAN → WAN (outbound from IDS/IPS and downstream hosts) ───

# HTTP/HTTPS outbound (LAN users going out)
iptables -A FORWARD -i $LAN -o $WAN \
  -p tcp -m multiport --dports 80,443 \
  -m conntrack --ctstate NEW -j ACCEPT

# DNS outbound
iptables -A FORWARD -i $LAN -o $WAN \
  -p udp --dport 53 \
  -m conntrack --ctstate NEW -j ACCEPT

# ICMP outbound
iptables -A FORWARD -i $LAN -o $WAN \
  -p icmp --icmp-type echo-request \
  -m conntrack --ctstate NEW -j ACCEPT

# ── Block everything else ──────────────────────────────────────
iptables -A FORWARD -j LOG --log-prefix "[FWA-FORWARD-DROP] " --log-level 4
iptables -A FORWARD -j DROP

# ══════════════════════════════════════════════════════════════
# 5. NAT
# ══════════════════════════════════════════════════════════════

# Masquerade traffic leaving toward IDS/IPS
# Only needed if you want FWA to hide downstream IPs from the router
# Comment this out if you want the router to see real downstream IPs
iptables -t nat -A POSTROUTING -o $LAN -j SNAT --to-source 10.0.2.4

echo "[FWA] iptables rules loaded successfully."
