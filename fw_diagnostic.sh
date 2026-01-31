#!/bin/bash
# Diagnostic IPTV - Trouver ce qui bloque
# Usage: sudo ./diagnostic-iptv.sh <IP_IPTV>

set -e

IPTV_IP="${1:-192.168.50.X}"

echo "=========================================="
echo "🔍 DIAGNOSTIC IPTV BLOCAGE"
echo "=========================================="
echo "IP IPTV cible: $IPTV_IP"
echo ""

# Test 1: Vérifier politiques par défaut
echo "1️⃣  POLITIQUES PAR DÉFAUT:"
echo "INPUT: $(sudo iptables -P INPUT 2>&1 | head -1 || echo 'Vérification...')"
echo "OUTPUT: $(sudo iptables -P OUTPUT 2>&1 | head -1 || echo 'Vérification...')"
echo "FORWARD: $(sudo iptables -P FORWARD 2>&1 | head -1 || echo 'Vérification...')"
# Alternative: lire depuis iptables -L
echo "Alternative (depuis iptables -L):"
sudo iptables -L INPUT -n 2>&1 | grep "policy" | head -1
sudo iptables -L OUTPUT -n 2>&1 | grep "policy" | head -1
sudo iptables -L FORWARD -n 2>&1 | grep "policy" | head -1
echo ""

# Test 2: Vérifier les règles FORWARD
echo "2️⃣  RÈGLES FORWARD (trafic IPTV):"
echo "--- INPUT chain ---"
sudo iptables -L INPUT -n -v | head -20
echo ""
echo "--- FORWARD chain ---"
sudo iptables -L FORWARD -n -v | head -30
echo ""
echo "--- OUTPUT chain ---"
sudo iptables -L OUTPUT -n -v | head -20
echo ""

# Test 3: Vérifier les règles NAT
echo "3️⃣  RÈGLES NAT (MASQUERADE):"
sudo iptables -t nat -L -n -v
echo ""

# Test 4: Vérifier les interfaces réseau
echo "4️⃣  CONFIGURATION DES INTERFACES:"
echo "--- eth1 (LAN IPTV) ---"
ip addr show eth1 2>/dev/null || echo "eth1 non trouvé"
echo ""
echo "--- wlan0 (WAN) ---"
ip addr show wlan0 2>/dev/null || echo "wlan0 non trouvé"
echo ""
echo "--- wlan1 (WiFi MITM) ---"
ip addr show wlan1 2>/dev/null || echo "wlan1 non trouvé"
echo ""

# Test 5: Vérifier l'IP forwarding
echo "5️⃣  IP FORWARDING:"
cat /proc/sys/net/ipv4/ip_forward
echo ""

# Test 6: Vérifier dnsmasq
echo "6️⃣  DNSMASQ STATUS:"
ps aux | grep dnsmasq | grep -v grep || echo "dnsmasq non actif"
echo ""

# Test 7: Vérifier hostapd
echo "7️⃣  HOSTAPD STATUS:"
ps aux | grep hostapd | grep -v grep || echo "hostapd non actif"
echo ""

# Test 8: Vérifier les logs iptables récents
echo "8️⃣  LOGS IPTABLES RÉCENTS (dernières 20 lignes):"
sudo tail -20 /var/log/firewall/iptables-fw.log 2>/dev/null || echo "Log firewall non trouvé"
echo ""

# Test 9: Vérifier les paquets bloqués en live
echo "9️⃣  EN DIRECT - Trafic bloqué (appuyer Ctrl+C pour arrêter):"
echo "Attente de 5 secondes de trafic..."
sudo timeout 5 tcpdump -i any "host $IPTV_IP" 2>/dev/null || echo "tcpdump non disponible"
echo ""

# Test 10: Test de connectivité basique
echo "🔟 TEST CONNECTIVITÉ:"
echo "--- Ping IPTV depuis routeur ---"
ping -c 1 -W 2 "$IPTV_IP" 2>&1 || echo "Ping échoué (normal si eth1 pas en local)"
echo ""

echo "=========================================="
echo "📋 OBSERVATIONS À VÉRIFIER:"
echo "=========================================="
echo "✓ Politique FORWARD = ACCEPT ?"
echo "✓ Règles FORWARD pour eth1 présentes ?"
echo "✓ NAT MASQUERADE actif ?"
echo "✓ IP forwarding activé (= 1) ?"
echo "✓ dnsmasq actif ?"
echo "✓ hostapd actif (si WiFi MITM) ?"
echo "=========================================="