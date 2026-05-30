#!/bin/bash

# ─── Interfaces ───────────────────────────────────────────────
WAN="enp0s1"         # from IDS/IPS
PUBLIC="enp0s3"      # 172.16.10.0/24  public DMZ
PRIVATE="eth2"       # 172.16.20.0/24  private DMZ
LAN="eth3"           # 192.168.10.0/24 internal LAN
HA="enp0s2"          # HA heartbeat

# ─── Subnets ──────────────────────────────────────────────────
PUBLIC_NET="172.16.10.0/24"
PRIVATE_NET="172.16.20.0/24"
LAN_NET="192.168.10.0/24"
HA_NET="10.0.4.0/30"  # Adjust to match your heartbeat subnet block

# ─── Cluster Virtual IPs (VIPs) ───────────────────────────────
WAN_VIP="10.0.3.4"
PUBLIC_VIP="172.16.10.4"
PRIVATE_VIP="172.16.20.4"
LAN_VIP="192.168.10.4"

# ─── Hosts ────────────────────────────────────────────────────
WEBSERVER="172.16.10.10"
DNSSERVER="172.16.10.20"
MAILSERVER="172.16.10.30"
JUMPSERVER="172.16.20.10"

# ══════════════════════════════════════════════════════════════
# 1. FLUSH all existing rules
# ══════════════════════════════════════════════════════════════
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# ══════════════════════════════════════════════════════════════
# 2. DEFAULT POLICIES
# ══════════════════════════════════════════════════════════════
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

# ══════════════════════════════════════════════════════════════
# 3. INPUT — traffic destined FOR this firewall itself
# ══════════════════════════════════════════════════════════════

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established/related sessions back in
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ── HA Cluster Link ───────────────────────────────────────────
# Allow all traffic across the physical HA interface safely
iptables -A INPUT -i $HA -j ACCEPT
# Accept Heartbeat's UDP port 694 broadcast/multicast anywhere
iptables -A INPUT -p udp --dport 694 -j ACCEPT

# Allow ICMP ping (essential for cluster monitoring tools)
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Allow SSH management only from jump server to the physical or VIP interface
iptables -A INPUT -i $PRIVATE -s $JUMPSERVER -p tcp --dport 22 -j ACCEPT

# Drop everything else to INPUT
iptables -A INPUT -j LOG --log-prefix "[FWB-INPUT-DROP] " --log-level 4
iptables -A INPUT -j DROP

# ══════════════════════════════════════════════════════════════
# 4. FORWARD — traffic passing THROUGH this firewall
# ══════════════════════════════════════════════════════════════

# Allow established/related traffic in all directions
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ── WAN → Public DMZ ──────────────────────────────────────────
# Targets the exact internal server IPs (FWA passes traffic here)
iptables -A FORWARD -i $WAN -o $PUBLIC -d $WEBSERVER -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i $WAN -o $PUBLIC -d $DNSSERVER -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i $WAN -o $PUBLIC -d $DNSSERVER -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i $WAN -o $PUBLIC -d $MAILSERVER -p tcp -m multiport --dports 25,143,993 -m conntrack --ctstate NEW -j ACCEPT

# ── LAN → WAN (outbound from internal users) ──────────────────
iptables -A FORWARD -i $LAN -o $WAN -s $LAN_NET -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i $LAN -o $WAN -s $LAN_NET -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# ── LAN → Private DMZ (access jump server) ────────────────────
iptables -A FORWARD -i $LAN -o $PRIVATE -s $LAN_NET -d $JUMPSERVER -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# ── LAN → Public DMZ (internal access to public services) ─────
iptables -A FORWARD -i $LAN -o $PUBLIC -s $LAN_NET -d $WEBSERVER -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i $LAN -o $PUBLIC -s $LAN_NET -d $DNSSERVER -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# ── Private DMZ → WAN (jump server initiated outbound) ────────
iptables -A FORWARD -i $PRIVATE -o $WAN -s $JUMPSERVER -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT

# ── Block inter-DMZ traffic (public ↔ private isolation) ──────
iptables -A FORWARD -i $PUBLIC -o $PRIVATE -j DROP
iptables -A FORWARD -i $PRIVATE -o $PUBLIC -j DROP

# ── Log and drop everything else ──────────────────────────────
iptables -A FORWARD -j LOG --log-prefix "[FWB-FORWARD-DROP] " --log-level 4
iptables -A FORWARD -j DROP

# ══════════════════════════════════════════════════════════════
# 5. NAT — SNAT outbound traffic using the WAN VIP
# ══════════════════════════════════════════════════════════════
# Forces all backend networks out using the FWB Cluster VIP
iptables -t nat -A POSTROUTING -o $WAN -s $LAN_NET -j SNAT --to-source $WAN_VIP
iptables -t nat -A POSTROUTING -o $WAN -s $PRIVATE_NET -j SNAT --to-source $WAN_VIP

# ══════════════════════════════════════════════════════════════
# 6. Port forwarding (DNAT) — Explicitly bound to the WAN VIP
# ══════════════════════════════════════════════════════════════
# Adding `-d $WAN_VIP` stops these rules from breaking normal web transit traffic.
iptables -t nat -A PREROUTING -i $WAN -d $WAN_VIP -p tcp --dport 80  -j DNAT --to-destination $WEBSERVER:80
iptables -t nat -A PREROUTING -i $WAN -d $WAN_VIP -p tcp --dport 443 -j DNAT --to-destination $WEBSERVER:443
iptables -t nat -A PREROUTING -i $WAN -d $WAN_VIP -p tcp --dport 25  -j DNAT --to-destination $MAILSERVER:25
iptables -t nat -A PREROUTING -i $WAN -d $WAN_VIP -p udp --dport 53  -j DNAT --to-destination $DNSSERVER:53

echo "[FWB] Cluster-ready iptables rules loaded successfully."
