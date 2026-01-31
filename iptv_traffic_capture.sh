#!/bin/bash
# Capture le trafic IPTV réel pour voir ce qui est bloqué
# Usage: sudo ./capture-iptv.sh <IP_IPTV>

IPTV_IP="${1:-192.168.50.10}"

echo "=========================================="
echo "📊 CAPTURE TRAFIC IPTV"
echo "=========================================="
echo "IP cible: $IPTV_IP"
echo "Capture en cours pendant 30 secondes..."
echo "Active ton IPTV maintenant!"
echo "=========================================="
echo ""

# Capturer le trafic dans les deux sens (FORWARD)
sudo timeout 30 tcpdump -i any -n "host $IPTV_IP" 2>&1 | tee /tmp/iptv-traffic.log

echo ""
echo "=========================================="
echo "Analyse du trafic capturé:"
echo "=========================================="

# Analyser les protocoles
echo "1️⃣  PROTOCOLES UTILISÉS:"
grep -oE "proto [0-9]+" /tmp/iptv-traffic.log | sort | uniq -c
echo ""

# Analyser les ports
echo "2️⃣  PORTS UTILISÉS (source:dest):"
grep -oE "[0-9]{1,5}> |>[0-9]{1,5} " /tmp/iptv-traffic.log | sort | uniq -c | head -20
echo ""

# Analyser les IPs destinataires
echo "3️⃣  IPs DESTINATAIRES:"
grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" /tmp/iptv-traffic.log | sort | uniq -c | sort -rn
echo ""

# Sauvegarder le log complet
echo "4️⃣  LOG COMPLET SAUVEGARDÉ:"
echo "/tmp/iptv-traffic.log"
echo ""

echo "=========================================="
echo "Maintenant, lance le diagnostic:"
echo "sudo iptables -L FORWARD -v -n | grep DROP"
echo "=========================================="