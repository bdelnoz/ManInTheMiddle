#!/bin/bash

LOG_DIR="/home/nox/firewall_log"
LOG_FILE="$LOG_DIR/firewall_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$LOG_DIR"

log_to_file() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# 1. Nettoyage initial
iptables -F
iptables -X LOGGING_IN 2>/dev/null
iptables -X LOGGING_OUT 2>/dev/null
iptables -Z

# 2. Politiques par défaut
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# 3. Création des chaînes personnalisées
iptables -N LOGGING_IN
iptables -N LOGGING_OUT

iptables -A LOGGING_IN -m limit --limit 5/min --limit-burst 5 -j LOG --log-prefix "IPTables-Blocked-IN: " --log-level 4
iptables -A LOGGING_IN -j DROP

iptables -A LOGGING_OUT -m limit --limit 5/min --limit-burst 5 -j LOG --log-prefix "IPTables-Blocked-OUT: " --log-level 4
iptables -A LOGGING_OUT -j DROP

# 4. Règles INPUT (du plus spécifique au plus général)
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 0 -m limit --limit 1/sec --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i wlan1 -p udp --dport 67 -j ACCEPT
iptables -A INPUT -i wlan1 -p udp --dport 68 -j ACCEPT
iptables -A INPUT -i eth1 -p udp -d 1.1.1.1 --dport 53 -j ACCEPT
iptables -A INPUT -i eth1 -p tcp -d 1.1.1.1 --dport 53 -j ACCEPT
iptables -A INPUT -i wlan1 -p udp -d 1.1.1.1 --dport 53 -j ACCEPT
iptables -A INPUT -i wlan1 -p tcp -d 1.1.1.1 --dport 53 -j ACCEPT
iptables -A INPUT -i eth1 -p udp -d 1.0.0.1 --dport 53 -j ACCEPT
iptables -A INPUT -i eth1 -p tcp -d 1.0.0.1 --dport 53 -j ACCEPT
iptables -A INPUT -i wlan1 -p udp -d 1.0.0.1 --dport 53 -j ACCEPT
iptables -A INPUT -i wlan1 -p tcp -d 1.0.0.1 --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --sport 67 -j ACCEPT
iptables -A INPUT -p udp --sport 68 -j ACCEPT
iptables -A INPUT -p tcp --sport 443 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j DROP
iptables -A INPUT -p tcp --dport 5228 -j DROP
iptables -A INPUT -p udp --dport 5228 -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/sec --limit-burst 5 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j DROP
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -m state --state NEW -j DROP
iptables -A INPUT -p tcp --sport 443 -m limit --limit 1/min --limit-burst 3 -j LOG --log-prefix "IPTables-Blocked-IN-443: " --log-level 4
iptables -A INPUT -p tcp --dport 5228 -m limit --limit 1/min --limit-burst 3 -j LOG --log-prefix "IPTables-Blocked-IN-5228: " --log-level 4
iptables -A INPUT -j LOGGING_IN

# 5. Règles FORWARD (du plus spécifique au plus général)
iptables -A FORWARD -i wlan0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wlan0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wlan0 -o wlan1 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wlan1 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Mutualisation des règles DNS pour FORWARD
for dns in 1.1.1.1 1.0.0.1; do
    for subnet in 192.168.50.0/24 192.168.51.0/24; do
        iptables -A FORWARD -p udp -s $subnet -d $dns --dport 53 -j ACCEPT
        iptables -A FORWARD -p tcp -s $subnet -d $dns --dport 53 -j ACCEPT
        iptables -A FORWARD -p tcp -s $subnet -d $dns --dport 853 -j ACCEPT
    done
done

# Mutualisation des règles IPTV et port 11254 pour les deux sous-réseaux
for subnet in 192.168.50.0/24 192.168.51.0/24; do
    iptables -A FORWARD -p udp -s $subnet -o wlan0 --dport 123 -j ACCEPT
    iptables -A FORWARD -p tcp -s $subnet -o wlan0 --dport 80 -j ACCEPT
    iptables -A FORWARD -p tcp -s $subnet -o wlan0 --dport 443 -j ACCEPT
    iptables -A FORWARD -p tcp -s $subnet -o wlan0 --dport 11254 -j ACCEPT
done

iptables -A FORWARD -i eth1 -o eth1 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth1 -p tcp --dport 53 -j ACCEPT
iptables -A FORWARD -i wlan1 -o wlan1 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i wlan1 -o wlan1 -p tcp --dport 53 -j ACCEPT

iptables -A FORWARD -p tcp -o wlan0 --sport 11254 -m state --state ESTABLISHED -j ACCEPT

iptables -A FORWARD -s 192.168.50.0/24 -j LOG --log-prefix "MITM-50-BLOCKED: " --log-level 4
iptables -A FORWARD -s 192.168.50.0/24 -j DROP
iptables -A FORWARD -s 192.168.51.0/24 -j LOG --log-prefix "MITM-51-BLOCKED: " --log-level 4
iptables -A FORWARD -s 192.168.51.0/24 -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP

# 6. Règles OUTPUT (du plus spécifique au plus général)
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type 8 -m limit --limit 1/sec --limit-burst 5 -j ACCEPT
iptables -A OUTPUT -o wlan1 -p udp --sport 67 -j ACCEPT
iptables -A OUTPUT -o wlan1 -p udp --sport 68 -j ACCEPT
iptables -A OUTPUT -p udp --sport 67 -j ACCEPT
iptables -A OUTPUT -p udp --sport 68 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Mutualisation des règles DNS pour OUTPUT
for dns in 1.1.1.1 1.0.0.1; do
    iptables -A OUTPUT -o wlan0 -p udp -d $dns --dport 53 -j ACCEPT
    iptables -A OUTPUT -o wlan0 -p tcp -d $dns --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp -d $dns --dport 53 -j ACCEPT
done

# Règles SSH vers GitHub
iptables -A OUTPUT -p tcp -d 192.30.252.0/22 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -d 185.199.108.0/22 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -d 140.82.112.0/20 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -d 143.55.64.0/20 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

# Règles NTP
iptables -A OUTPUT -p udp -d 91.189.91.157 --dport 123 -j ACCEPT
iptables -A OUTPUT -p udp -d 185.125.190.58 --dport 123 -j ACCEPT
iptables -A OUTPUT -p udp -d 185.125.190.56 --dport 123 -j ACCEPT

# Blocage des ports non essentiels
iptables -A OUTPUT -p icmp -j DROP
iptables -A OUTPUT -p tcp --dport 22 -j DROP
iptables -A OUTPUT -p tcp --dport 30 -j DROP
iptables -A OUTPUT -p udp --dport 30 -j DROP
iptables -A OUTPUT -p tcp --dport 5228 -j DROP
iptables -A OUTPUT -p udp --dport 5228 -j DROP
iptables -A OUTPUT -p tcp --dport 137:139 -j DROP
iptables -A OUTPUT -p udp --dport 137:139 -j DROP
iptables -A OUTPUT -p tcp --dport 445 -j DROP
iptables -A OUTPUT -p udp --dport 445 -j DROP

iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -A OUTPUT -p tcp --dport 443 -m limit --limit 1/min --limit-burst 3 -j LOG --log-prefix "IPTables-Blocked-OUT-443: " --log-level 4
iptables -A OUTPUT -p tcp --dport 5228 -m limit --limit 1/min --limit-burst 3 -j LOG --log-prefix "IPTables-Blocked-OUT-5228: " --log-level 4
iptables -A OUTPUT -j LOGGING_OUT
