#!/bin/bash
# Auteur : Bruno DELNOZ
# Email : bruno.delnoz@protonmail.com
# Nom du script : fw.sh
# Chemin : /root/fw.sh
# Target usage : Firewall strict + MITMProxy (optionnel) + Hotspot WiFi (192.168.50.x/51.x)
# Version : v14.0 – Date : 2026-02-04
# Changelog :
# - v14.0 : Intégration complète de mitmproxy (optionnel via --mitmproxylocal), règles unifiées 192.168.50.x/51.x
# - v13.6 : Suppression des références à mitmproxy (version propre)
# Prérequis : iptables, jq, curl, dig, systemd, hostapd, dnsmasq

set -e
export TERM=xterm

# =================================================================================
# CONFIGURATION GLOBALE
# =================================================================================
LOG_DIR="/var/log/firewall/"
LOG_FILE="/var/log/firewall/iptables-fw.log"
MITMPROXY_ENABLED="false"  # Désactivé par défaut (activation via argument)

# Créer les répertoires et fichiers de log
mkdir -p "$LOG_DIR" 2>/dev/null
touch "$LOG_FILE" 2>/dev/null
chown nox:nox "$LOG_DIR" "$LOG_FILE" 2>/dev/null

# Fonction de logging
log_to_file() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# =================================================================================
# GESTION DES ARGUMENTS (NOUVEAU : support de --mitmproxylocal)
# =================================================================================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mitmproxylocal)
      MITMPROXY_ENABLED="true"
      shift
      ;;
    *)
      echo "Argument inconnu : $1. Utilise --mitmproxylocal pour activer mitmproxy."
      shift
      ;;
  esac
done

log_to_file "=== Début de fw.sh v14.0 (MITMProxy: $MITMPROXY_ENABLED) ==="

# =================================================================================
# TEST DE CONNECTIVITÉ
# =================================================================================
INTERNET_OK=false
GITHUB_OK=false
if ping -c 1 -W 3 1.1.1.1 &>/dev/null; then
  INTERNET_OK=true
  log_to_file "Connectivité Internet : OK"
else
  log_to_file "AVERTISSEMENT : Pas de connectivité Internet"
fi

if $INTERNET_OK && curl -s --connect-timeout 5 https://api.github.com/meta &>/dev/null; then
  GITHUB_OK=true
  log_to_file "Connectivité GitHub : OK"
else
  log_to_file "GitHub inaccessible - Utilisation des IP statiques"
fi

# =================================================================================
# RÉCUPÉRATION DES IP GITHUB/NTP
# =================================================================================
# IP GitHub (fallback si API inaccessible)
GITHUB_SSH_IPS="140.82.112.0/20 143.55.64.0/20 185.199.108.0/22 192.30.252.0/22"
if $GITHUB_OK; then
  GITHUB_SSH_IPS=$(curl -s --max-time 10 https://api.github.com/meta | jq -r '.git[]' 2>>"$LOG_FILE" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' | tr '\n' ' ' || echo "$GITHUB_SSH_IPS")
fi
log_to_file "IP GitHub SSH : $GITHUB_SSH_IPS"

# IP NTP (fallback si DNS échoue)
NTP_IPS="91.189.89.198 91.189.89.199 185.125.190.36"
if $INTERNET_OK; then
  NTP_IPS=$(dig +short +timeout=3 ntp.ubuntu.com 2>>"$LOG_FILE" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -3 | tr '\n' ' ' || echo "$NTP_IPS")
fi
log_to_file "IP NTP : $NTP_IPS"

# =================================================================================
# NETTOYAGE ET POLITIQUES PAR DÉFAUT
# =================================================================================
echo "🧹 Nettoyage des règles iptables..."
sudo iptables -t filter -F
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -X
sudo iptables -t nat -X
sudo iptables -t mangle -X
log_to_file "Tables iptables vidées."

# Politique par défaut : DROP
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
log_to_file "Politique DROP appliquée."

# Activer le forwarding IP
echo 1 > /proc/sys/net/ipv4/ip_forward
log_to_file "Forwarding IP activé."

# Désactiver IPv6
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
log_to_file "IPv6 désactivé."

# =================================================================================
# RÈGLES DE BASE (LOOPBACK, ICMP, DNS, SSH, NTP)
# =================================================================================
# Loopback
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# ICMP (ping limité)
sudo iptables -A OUTPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

# DNS (5 serveurs autorisés)
for dns_ip in 1.1.1.1 8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220; do
  sudo iptables -A OUTPUT -p udp -d "$dns_ip" --dport 53 -j ACCEPT
  sudo iptables -A OUTPUT -p tcp -d "$dns_ip" --dport 53 -j ACCEPT
done
sudo iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT

# SSH (uniquement vers GitHub)
for cidr in $GITHUB_SSH_IPS; do
  sudo iptables -A OUTPUT -p tcp -d "$cidr" --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
done
sudo iptables -A OUTPUT -p tcp --dport 22 -j DROP  # Bloquer tout autre SSH

# NTP (serveurs Ubuntu)
for ip in $NTP_IPS; do
  sudo iptables -A OUTPUT -p udp -d "$ip" --dport 123 -j ACCEPT
done

# =================================================================================
# RÈGLES UNIFIÉES POUR 192.168.50.X ET 192.168.51.X
# =================================================================================
# Chaînes personnalisées
sudo iptables -N ACCEPT_DNS
sudo iptables -A ACCEPT_DNS -p udp --dport 53 -j ACCEPT
sudo iptables -A ACCEPT_DNS -p tcp --dport 53 -j ACCEPT

sudo iptables -N ACCEPT_NTP
sudo iptables -A ACCEPT_NTP -p udp --dport 123 -j ACCEPT

sudo iptables -N ACCEPT_IPTV
sudo iptables -A ACCEPT_IPTV -p tcp --dport 11254 -j ACCEPT
sudo iptables -A ACCEPT_IPTV -p tcp --sport 11254 -m state --state ESTABLISHED -j ACCEPT

# Règles pour eth1 (192.168.50.0/24 - IPTV)
sudo iptables -A FORWARD -i eth1 -o wlan0 -s 192.168.50.0/24 -j ACCEPT_IPTV
sudo iptables -A FORWARD -i eth1 -o wlan0 -s 192.168.50.0/24 -p udp --dport 53 -j ACCEPT_DNS
sudo iptables -A FORWARD -i eth1 -o wlan0 -s 192.168.50.0/24 -p tcp --dport 53 -j ACCEPT_DNS
for ip in $NTP_IPS; do
  sudo iptables -A FORWARD -i eth1 -o wlan0 -s 192.168.50.0/24 -d "$ip" -p udp --dport 123 -j ACCEPT_NTP
done

# Règles pour wlan1 (192.168.51.0/24 - Hotspot)
sudo iptables -A FORWARD -i wlan1 -o wlan0 -s 192.168.51.0/24 -j ACCEPT_IPTV
sudo iptables -A FORWARD -i wlan1 -o wlan0 -s 192.168.51.0/24 -p udp --dport 53 -j ACCEPT_DNS
sudo iptables -A FORWARD -i wlan1 -o wlan0 -s 192.168.51.0/24 -p tcp --dport 53 -j ACCEPT_DNS
for ip in $NTP_IPS; do
  sudo iptables -A FORWARD -i wlan1 -o wlan0 -s 192.168.51.0/24 -d "$ip" -p udp --dport 123 -j ACCEPT_NTP
done

# NAT pour 192.168.50.0/24 et 192.168.51.0/24
sudo iptables -t nat -A POSTROUTING -o wlan0 -s 192.168.50.0/24 -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o wlan0 -s 192.168.51.0/24 -j MASQUERADE

# =================================================================================
# RÈGLES SPÉCIFIQUES (DHCP, NetBIOS/SMB, Port 5228)
# =================================================================================
# DHCP (pour wlan1 et eth1)
sudo iptables -A INPUT -i wlan1 -p udp --dport 67:68 -j ACCEPT
sudo iptables -A OUTPUT -o wlan1 -p udp --sport 67:68 -j ACCEPT
sudo iptables -A INPUT -i eth1 -p udp --dport 67:68 -j ACCEPT
sudo iptables -A OUTPUT -o eth1 -p udp --sport 67:68 -j ACCEPT

# NetBIOS/SMB (ports 137-139, 445)
sudo iptables -A INPUT -p tcp --dport 137:139 -j DROP
sudo iptables -A INPUT -p udp --dport 137:139 -j DROP
sudo iptables -A INPUT -p tcp --dport 445 -j DROP
sudo iptables -A INPUT -p udp --dport 445 -j DROP
sudo iptables -t raw -A PREROUTING -p tcp --dport 137:139 -j NOTRACK
sudo iptables -t raw -A PREROUTING -p udp --dport 137:139 -j NOTRACK
sudo iptables -t raw -A PREROUTING -p tcp --dport 445 -j NOTRACK
sudo iptables -t raw -A PREROUTING -p udp --dport 445 -j NOTRACK

# Port 5228 (Google Talk)
sudo iptables -A INPUT -p tcp --dport 5228 -j DROP
sudo iptables -A INPUT -p udp --dport 5228 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 5228 -j DROP
sudo iptables -A OUTPUT -p udp --dport 5228 -j DROP

# =================================================================================
# MITMPROXY (UNIQUEMENT SI --mitmproxylocal)
# =================================================================================
if [ "$MITMPROXY_ENABLED" = "true" ]; then
  log_to_file "🔍 Activation de mitmproxy (port 8080)"

  # 1. Créer les répertoires pour mitmproxy
  sudo mkdir -p /var/log/mitmproxy /run/mitmproxy /etc/mitmproxy/certs
  sudo chown -R nox:nox /var/log/mitmproxy /run/mitmproxy /etc/mitmproxy

  # 2. Démarrer mitmproxy en arrière-plan
  nohup mitmproxy \
    --mode transparent \
    --listen-port 8080 \
    --confdir /etc/mitmproxy \
    --set cert_storage_dir=/etc/mitmproxy/certs \
    --set log_file=/var/log/mitmproxy/mitmproxy.log \
    --set flow_detail=2 \
    --pid-file /run/mitmproxy/mitmproxy.pid \
    --quiet \
    > /var/log/mitmproxy/mitmproxy_console.log 2>&1 &

  # 3. Attendre le démarrage (max 30s)
  sleep 2
  if [ -f /run/mitmproxy/mitmproxy.pid ] && kill -0 $(cat /run/mitmproxy/mitmproxy.pid) 2>/dev/null; then
    log_to_file "✅ mitmproxy démarré (PID: $(cat /run/mitmproxy/mitmproxy.pid))"

    # 4. Configurer les règles iptables pour mitmproxy
    sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 -j REDIRECT --to-port 8080
    sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 443 -j REDIRECT --to-port 8080
    sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 8080
    sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 443 -j REDIRECT --to-port 8080
    sudo iptables -A FORWARD -i wlan1 -p tcp --dport 8080 -j ACCEPT
    sudo iptables -A FORWARD -i eth1 -p tcp --dport 8080 -j ACCEPT

    log_to_file "✅ Règles iptables pour mitmproxy configurées (ports 80/443 → 8080)"
    log_to_file "   - Interface web : http://0.0.0.0:8081"
    log_to_file "   - Logs : /var/log/mitmproxy/mitmproxy.log"
    log_to_file "   - Certificat CA : /etc/mitmproxy/certs/mitmproxy-ca.crt"
  else
    log_to_file "⚠️ Échec du démarrage de mitmproxy (fallback vers Wireshark)"
    # Supprimer les règles iptables si mitmproxy échoue
    sudo iptables -t nat -D PREROUTING -i wlan1 -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true
    sudo iptables -t nat -D PREROUTING -i wlan1 -p tcp --dport 443 -j REDIRECT --to-port 8080 2>/dev/null || true
  fi
else
  log_to_file "🔕 mitmproxy désactivé (utilise --mitmproxylocal pour l'activer)"
fi

# =================================================================================
# LOGGING DES PAQUETS BLOQUÉS
# =================================================================================
sudo iptables -N LOGGING_IN
sudo iptables -N LOGGING_OUT
sudo iptables -A LOGGING_IN -m limit --limit 5/min -j LOG --log-prefix "IPTables-Blocked-IN: "
sudo iptables -A LOGGING_IN -j DROP
sudo iptables -A LOGGING_OUT -m limit --limit 5/min -j LOG --log-prefix "IPTables-Blocked-OUT: "
sudo iptables -A LOGGING_OUT -j DROP
sudo iptables -A INPUT -j LOGGING_IN
sudo iptables -A OUTPUT -j LOGGING_OUT

# Logging spécifique pour 192.168.50.x et 192.168.51.x
sudo iptables -A FORWARD -i eth1 -o wlan0 -s 192.168.50.0/24 -j LOG --log-prefix "IPTV-50-BLOCKED: "
sudo iptables -A FORWARD -i wlan1 -o wlan0 -s 192.168.51.0/24 -j LOG --log-prefix "HOTSPOT-51-BLOCKED: "

# =================================================================================
# SAUVEGARDE ET FINALISATION
# =================================================================================
sudo iptables-save > /etc/iptables/rules.v4
log_to_file "Règles sauvegardées dans /etc/iptables/rules.v4"

# Affichage des règles appliquées
echo "📋 Règles iptables appliquées :"
sudo iptables -L -v -n
echo "📋 Règles NAT :"
sudo iptables -t nat -L -v -n

log_to_file "=== Fin de fw.sh v14.0 ==="
echo "🎉 Firewall configuré avec succès !"
echo "📊 Résumé :"
echo " - MITMProxy : $([ "$MITMPROXY_ENABLED" = "true" ] && echo "ACTIF (port 8080)" || echo "DÉSACTIVÉ")"
echo " - Règles unifiées pour 192.168.50.x/51.x : OK"
echo " - Logging : Actif (/var/log/firewall/iptables-fw.log)"
echo " - NAT : Configuré pour wlan0 (Internet)"
echo " - Ports bloqués : NetBIOS/SMB (137-139, 445), 5228"
