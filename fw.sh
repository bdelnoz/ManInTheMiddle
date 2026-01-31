#!/bin/bash
# Auteur : Bruno DELNOZ
# Email : bruno.delnoz@protonmail.com
# Nom du script : fw.sh
# Target usage : Firewall strict avec logging des paquets bloqués (SystemD)
# Version : v13.0 – Date : 2025-01-27
# Changelog :
# - v13.0 (2025-01-27) : Ajout support hotspot WiFi MITM sur wlan1 (DHCP + FORWARD)
#   Autorisation trafic DHCP sur wlan1 (INPUT/OUTPUT ports 67:68)
#   Autorisation FORWARD bidirectionnel wlan0 <-> wlan1 (ESTABLISHED/RELATED)
#   Règles FORWARD explicites pour eth0, eth1, ET wlan1 vers wlan0
#   Support complet pour le script MITM v2.5 avec hotspot WiFi
# - v12.0 (2025-10-08) : Correction technique - Politiques NAT ne peuvent pas être DROP (limitation kernel), uniquement table filter
# - v11.0 (2025-10-08) : Ajout politiques DROP pour table NAT (sécurité maximale)
# - v10.0 (2025-10-08) : Version PICO BELLO - Nettoyage complet NAT, correction ICMP, meilleure lisibilité, ajout DHCP INPUT
# - v9.5 (2025-10-01) : Correction compatibilité : remplacement conntrack par state, suppression nettoyages parasites
# - v9.4 (2025-10-01) : Correction DNS - Commenté règles DROP redondantes qui cassaient les autorisations, suppression ligne NTP cassée
# - v9.3 (2025-09-22) : Correction règle DNS INPUT pour autoriser les réponses depuis n'importe quel serveur DNS
# Prérequis : iptables, jq, curl, dig, systemd

set -e
export TERM=xterm

# Configuration des logs
LOG_DIR="/var/log/firewall/"
LOG_FILE="/var/log/firewall/iptables-fw.log"

# Créer le répertoire et le fichier de log si nécessaire
if [ ! -d "$LOG_DIR" ]; then
  mkdir -p "$LOG_DIR" || { echo "⚠️ Erreur lors de la création de $LOG_DIR"; exit 1; }
  chown nox:nox "$LOG_DIR" || { echo "⚠️ Erreur lors du chown de $LOG_DIR"; exit 1; }
fi
if [ ! -f "$LOG_FILE" ]; then
  touch "$LOG_FILE" || { echo "⚠️ Erreur lors de la création de $LOG_FILE"; exit 1; }
  chown nox:nox "$LOG_FILE" || { echo "⚠️ Erreur lors du chown de $LOG_FILE"; exit 1; }
fi

# Fonction pour logger dans le fichier dédié
log_to_file() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

log_to_file "=== Début de l'exécution de fw.sh v13.0 avec support WiFi MITM ==="

# Test de connectivité avec fallback pour systemd
INTERNET_OK=false
GITHUB_OK=false
echo "🔍 Test de connectivité..."
log_to_file "Test de connectivité..."
if ping -c 1 -W 3 1.1.1.1 &> /dev/null; then
  INTERNET_OK=true
  echo "✅ Connectivité internet : OK"
  log_to_file "Connectivité internet : OK"
else
  echo "⚠️ Pas de connectivité internet - Mode fallback activé"
  log_to_file "AVERTISSEMENT : Pas de connectivité internet - Mode fallback activé"
fi
if $INTERNET_OK && curl -s --connect-timeout 5 --max-time 10 https://api.github.com/meta &> /dev/null; then
  GITHUB_OK=true
  echo "✅ Connectivité GitHub : OK"
  log_to_file "Connectivité GitHub : OK"
else
  echo "⚠️ GitHub inaccessible - Utilisation IP statiques"
  log_to_file "AVERTISSEMENT : GitHub inaccessible - Utilisation IP statiques"
fi

# Désactiver IPv6
echo "🚫 Désactivation IPv6..."
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>>"$LOG_FILE" || log_to_file "Erreur lors de la désactivation d'IPv6 (all)"
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>>"$LOG_FILE" || log_to_file "Erreur lors de la désactivation d'IPv6 (default)"
echo "✅ IPv6 désactivé"
log_to_file "IPv6 désactivé."

# Fonction pour récupérer les plages IPv4 GitHub SSH avec fallback
get_github_ssh_ips() {
  if $GITHUB_OK; then
    ips=$(curl -s --max-time 10 https://api.github.com/meta | jq -r '.git[]' 2>>"$LOG_FILE" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' | tr '\n' ' ' | sed 's/[[:space:]]*$//' || true)
    if [ -n "$ips" ] && [ "$ips" != " " ]; then
      log_to_file "IP GitHub récupérées dynamiquement: $ips"
      echo "$ips"
      return
    fi
  fi
  # Fallback avec IP statiques connues de GitHub (mise à jour 2025)
  fallback_ips="140.82.112.0/20 143.55.64.0/20 185.199.108.0/22 192.30.252.0/22"
  log_to_file "Utilisation des IP GitHub en fallback: $fallback_ips"
  echo "$fallback_ips"
}

GITHUB_SSH_IPS=($(get_github_ssh_ips))
log_to_file "IP GitHub SSH récupérées: ${GITHUB_SSH_IPS[*]}"
echo "🔍 Récupération des IP GitHub SSH..."
echo "✅ IP GitHub SSH récupérées (${#GITHUB_SSH_IPS[@]} ranges)"

# Vérification robuste des IP GitHub
if [ ${#GITHUB_SSH_IPS[@]} -eq 0 ]; then
  echo "⚠️ Aucune IP GitHub valide trouvée, SSH non configuré"
  log_to_file "Erreur : Aucune IP GitHub valide, SSH non configuré"
fi

# NTP : RÉSOLUTION AVANT LES RÈGLES IPTABLES
echo "🕒 Résolution des serveurs NTP..."
log_to_file "Résolution NTP avant application des règles..."
if $INTERNET_OK; then
  NTP_IPS=$(dig +short +timeout=3 +tries=1 ntp.ubuntu.com 2>>"$LOG_FILE" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -3 | tr '\n' ' ' || true)
fi
if [ -z "$NTP_IPS" ] || [ "$NTP_IPS" = " " ]; then
  # Fallback avec IP statiques des serveurs NTP Ubuntu
  NTP_IPS="91.189.89.198 91.189.89.199 185.125.190.36"
  echo "⚠️ Utilisation des IP NTP en fallback: $NTP_IPS"
  log_to_file "Utilisation des IP NTP en fallback: $NTP_IPS"
else
  echo "✅ IP NTP résolues: $NTP_IPS"
  log_to_file "IP NTP résolues: $NTP_IPS"
fi

if [ -z "$NTP_IPS" ]; then
  echo "⚠️ Aucune IP NTP valide trouvée, NTP non configuré"
  log_to_file "Erreur : Aucune IP NTP valide, NTP non configuré"
fi

echo ""
echo "🧹 Nettoyage COMPLET de toutes les règles iptables..."

# Vider TOUTES les tables (filter, nat, mangle)
sudo iptables -t filter -F 2>>"$LOG_FILE" || log_to_file "Erreur lors du vidage table filter"
sudo iptables -t filter -X 2>>"$LOG_FILE" || log_to_file "Erreur lors suppression chaînes filter"
sudo iptables -t filter -Z 2>>"$LOG_FILE" || log_to_file "Erreur lors reset compteurs filter"

sudo iptables -t nat -F 2>>"$LOG_FILE" || log_to_file "Erreur lors du vidage table nat"
sudo iptables -t nat -X 2>>"$LOG_FILE" || log_to_file "Erreur lors suppression chaînes nat"
sudo iptables -t nat -Z 2>>"$LOG_FILE" || log_to_file "Erreur lors reset compteurs nat"

sudo iptables -t mangle -F 2>>"$LOG_FILE" || log_to_file "Erreur lors du vidage table mangle"
sudo iptables -t mangle -X 2>>"$LOG_FILE" || log_to_file "Erreur lors suppression chaînes mangle"
sudo iptables -t mangle -Z 2>>"$LOG_FILE" || log_to_file "Erreur lors reset compteurs mangle"

echo "✅ Toutes les tables iptables vidées (filter, nat, mangle)"
log_to_file "Toutes les tables iptables vidées (filter, nat, mangle)."

# Politique par défaut : tout bloquer (table filter)
echo "🔒 Application des politiques par défaut (DROP)..."
sudo iptables -P INPUT DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors de la définition de la politique INPUT DROP"
sudo iptables -P OUTPUT DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors de la définition de la politique OUTPUT DROP"
sudo iptables -P FORWARD DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors de la définition de la politique FORWARD DROP"

# ----------------------------------------------------------------------------------------------------------------------------
sudo iptables -F FORWARD
sudo iptables -P FORWARD DROP

# ============================================================
# RÈGLES MITM WIFI HOTSPOT (WLAN1)
# ============================================================
echo " ↳ Configuration du hotspot WiFi MITM (wlan1)"

# Autoriser le trafic DHCP sur wlan1 (nécessaire pour le hotspot)
sudo iptables -A INPUT -i wlan1 -p udp --dport 67:68 -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur DHCP INPUT wlan1"
sudo iptables -A OUTPUT -o wlan1 -p udp --sport 67:68 -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur DHCP OUTPUT wlan1"

# Autoriser les retours de connexions EXISTANTES (WAN <-> LAN)
sudo iptables -A FORWARD -i wlan0 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Autoriser les retours de connexions wlan0 <-> wlan1 (WiFi hotspot)
sudo iptables -A FORWARD -i wlan0 -o wlan1 -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -i wlan1 -o wlan0 -m state --state ESTABLISHED,RELATED -j ACCEPT

log_to_file "Trafic DHCP et FORWARD autorisé pour hotspot WiFi MITM (wlan1)."

# ----------------------------------------------------------------------------------------------------------------------------

# REGLES IPTV - DNS
echo " ↳ Autorisation DNS pour range IPTV"
sudo iptables -A FORWARD -m iprange --src-range 192.168.50.10-192.168.50.100 -d 1.1.1.1 -p udp --dport 53 -j ACCEPT
sudo iptables -A FORWARD -m iprange --src-range 192.168.50.10-192.168.50.100 -d 1.0.0.1 -p udp --dport 53 -j ACCEPT
sudo iptables -A FORWARD -m iprange --src-range 192.168.50.10-192.168.50.100 -d 1.0.0.1 -p tcp --dport 53 -j ACCEPT
sudo iptables -A FORWARD -m iprange --src-range 192.168.50.10-192.168.50.100 -d 1.1.1.1 -p tcp --dport 53 -j ACCEPT

# DNS over TLS (port 853)
sudo iptables -A FORWARD -m iprange --src-range 192.168.50.10-192.168.50.100 -d 1.0.0.1 -p tcp --dport 853 -j ACCEPT
sudo iptables -A FORWARD -m iprange --src-range 192.168.50.10-192.168.50.100 -d 1.1.1.1 -p tcp --dport 853 -j ACCEPT

# ============================================================
# AUTORISER DNSMASQ SUR WLAN1/ETH1 (LISTENING)
# ============================================================
echo " ↳ Autorisation dnsmasq (récepteur) sur wlan1 et eth1"

# INPUT : accepter DNS depuis les clients
sudo iptables -A INPUT -i eth1 -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -i eth1 -p tcp --dport 53 -j ACCEPT
sudo iptables -A INPUT -i wlan1 -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -i wlan1 -p tcp --dport 53 -j ACCEPT

# OUTPUT : dnsmasq forward vers les vrais DNS
sudo iptables -A OUTPUT -o wlan0 -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -o wlan0 -p tcp --dport 53 -j ACCEPT

# FORWARD : autoriser clients → MITM DNS
sudo iptables -A FORWARD -i eth1 -o eth1 -p udp --dport 53 -j ACCEPT
sudo iptables -A FORWARD -i eth1 -o eth1 -p tcp --dport 53 -j ACCEPT
sudo iptables -A FORWARD -i wlan1 -o wlan1 -p udp --dport 53 -j ACCEPT
sudo iptables -A FORWARD -i wlan1 -o wlan1 -p tcp --dport 53 -j ACCEPT

log_to_file "dnsmasq INPUT/OUTPUT/FORWARD autorisé sur eth1 et wlan1."

# Autoriser les flux SORTANTS IPTV -> Internet (depuis eth0, eth1, wlan1)
echo " ↳ Autorisation flux IPTV vers Internet (eth0, eth1, wlan1)"

# Port 11254
sudo iptables -A FORWARD -i eth0 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p tcp --dport 11254 -j ACCEPT
sudo iptables -A FORWARD -i eth1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p tcp --dport 11254 -j ACCEPT
sudo iptables -A FORWARD -i wlan1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p tcp --dport 11254 -j ACCEPT

# NTP (port 123)
sudo iptables -A FORWARD -i eth0 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p udp --dport 123 -j ACCEPT
sudo iptables -A FORWARD -i eth1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p udp --dport 123 -j ACCEPT
sudo iptables -A FORWARD -i wlan1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p udp --dport 123 -j ACCEPT

# HTTP (port 80)
sudo iptables -A FORWARD -i eth0 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p tcp --dport 80 -j ACCEPT
sudo iptables -A FORWARD -i eth1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p tcp --dport 80 -j ACCEPT
sudo iptables -A FORWARD -i wlan1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p tcp --dport 80 -j ACCEPT

# HTTPS (port 443)
sudo iptables -A FORWARD -i eth0 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p tcp --dport 443 -j ACCEPT
sudo iptables -A FORWARD -i eth1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p tcp --dport 443 -j ACCEPT
sudo iptables -A FORWARD -i wlan1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -p tcp --dport 443 -j ACCEPT

# NAT sortant IPTV
sudo iptables -t nat -F POSTROUTING
sudo iptables -t nat -A POSTROUTING -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -j MASQUERADE

# Logging du trafic BLOQUÉ uniquement (1 seul LOG, juste avant DROP)
echo " ↳ Configuration logging trafic bloqué IPTV"
sudo iptables -A FORWARD -i eth0 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -j LOG --log-prefix "VB-BLOCKED: "
sudo iptables -A FORWARD -i eth1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -j LOG --log-prefix "VB-BLOCKED: "
sudo iptables -A FORWARD -i wlan1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -j LOG --log-prefix "VB-BLOCKED: "

# Drop final IPTV
sudo iptables -A FORWARD -i eth0 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -j DROP
sudo iptables -A FORWARD -i eth1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -j DROP
sudo iptables -A FORWARD -i wlan1 -o wlan0 -m iprange --src-range 192.168.50.10-192.168.50.100 -j DROP

log_to_file "Règles IPTV configurées pour eth0, eth1 et wlan1 (hotspot WiFi)."

# ----------------------------------------------------------------------------------------------------------------------------

# Note : Les politiques des tables NAT/MANGLE ne peuvent pas être changées (limitation kernel)
# Elles restent ACCEPT par défaut, mais on peut ajouter des règles DROP explicites si besoin

echo "✅ Politique par défaut : DROP pour table filter (INPUT, OUTPUT, FORWARD)"
log_to_file "Politique par défaut : DROP pour INPUT, OUTPUT, FORWARD (filter). NAT reste ACCEPT (limitation kernel)."

echo ""
echo "🛡️ Application des règles de sécurité..."

# Autoriser le loopback
echo " ↳ Loopback autorisé"
sudo iptables -A INPUT -i lo -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation du loopback (INPUT)"
sudo iptables -A OUTPUT -o lo -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation du loopback (OUTPUT)"
log_to_file "Loopback autorisé."

# Autoriser les connexions déjà établies ou liées
echo " ↳ Connexions établies/liées autorisées"
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation des connexions établies (INPUT)"
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation des connexions établies (OUTPUT)"
log_to_file "Connexions établies/liées autorisées."

# ICMP : ping sortant limité à 1/s, réponses entrantes autorisées
echo " ↳ ICMP : ping sortant limité (1/s), réponses entrantes autorisées"
sudo iptables -A OUTPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur ICMP OUTPUT"
sudo iptables -A INPUT -p icmp --icmp-type echo-reply -m limit --limit 1/s --limit-burst 5 -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur ICMP INPUT"
# Autoriser les autres types ICMP nécessaires (ESTABLISHED/RELATED déjà autorisé au-dessus)
sudo iptables -A INPUT -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur ICMP RELATED INPUT"
# Bloquer le reste (destination-unreachable, time-exceeded, etc. non sollicités)
sudo iptables -A INPUT -p icmp -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur DROP ICMP INPUT"
sudo iptables -A OUTPUT -p icmp -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur DROP ICMP OUTPUT"
log_to_file "ICMP : ping sortant limité (1/s), réponses entrantes autorisées."

# DNS : Autoriser uniquement UDP vers les serveurs DNS configurés (OUTPUT)
echo " ↳ DNS autorisé vers 5 serveurs configurés (OUTPUT)"
for dns_ip in "1.1.1.1" "8.8.8.8" "8.8.4.4" "208.67.222.222" "208.67.220.220"; do
  sudo iptables -A OUTPUT -p udp -d "$dns_ip" --dport 53 -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation DNS pour $dns_ip (OUTPUT)"
done

# Autoriser les réponses DNS entrantes (UDP, port source 53, ESTABLISHED)
echo " ↳ Réponses DNS entrantes autorisées (UDP port source 53, ESTABLISHED)"
sudo iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation des réponses DNS (INPUT)"
log_to_file "DNS autorisé uniquement en UDP vers 5 serveurs configurés (avec réponses entrantes)."

# DHCP
echo " ↳ DHCP autorisé"
sudo iptables -A OUTPUT -p udp --sport 67:68 --dport 67:68 -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation DHCP OUTPUT"
sudo iptables -A INPUT -p udp --sport 67:68 --dport 67:68 -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation DHCP INPUT"
log_to_file "DHCP autorisé."

# HTTPS uniquement (pas de HTTP)
echo " ↳ HTTPS autorisé (HTTP bloqué)"
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation HTTPS OUTPUT"
sudo iptables -A INPUT -p tcp --sport 443 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation HTTPS INPUT"
log_to_file "HTTPS autorisé (INPUT et OUTPUT), HTTP bloqué."

# HTTP uniquement pour l'IP 109.61.81.65
echo " ↳ HTTP autorisé UNIQUEMENT pour l'IP 109.61.81.65 (port 80)"
sudo iptables -A OUTPUT -p tcp -d 109.61.81.65 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation HTTP pour 109.61.81.65 (OUTPUT)"
sudo iptables -A INPUT -p tcp -s 109.61.81.65 --sport 80 -m state --state ESTABLISHED -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation HTTP pour 109.61.81.65 (INPUT)"
log_to_file "HTTP autorisé UNIQUEMENT pour l'IP 109.61.81.65 (port 80)."

# SSH uniquement vers IP GitHub (output seulement) - avec validation
set +e
echo " ↳ Configuration SSH vers GitHub..."
ssh_rules_added=0
for cidr in ${GITHUB_SSH_IPS[@]}; do
  if [[ "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    if sudo iptables -A OUTPUT -p tcp -d "$cidr" --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT 2>>"$LOG_FILE"; then
      ((ssh_rules_added++))
    else
      log_to_file "Erreur lors de l'autorisation SSH pour $cidr"
      echo "⚠️ Erreur lors de l'ajout de la règle SSH pour $cidr"
    fi
  else
    log_to_file "CIDR invalide ignoré (format): '$cidr'"
  fi
done
# Bloquer tout autre SSH
sudo iptables -A OUTPUT -p tcp --dport 22 -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage SSH"
set -e
echo " ↳ SSH autorisé vers GitHub ($ssh_rules_added ranges)"
log_to_file "SSH autorisé uniquement vers les IP GitHub ($ssh_rules_added ranges valides)."

# NTP : avec fallback si résolution DNS échoue
set +e
echo " ↳ Configuration NTP..."
ntp_rules_added=0
for ip in $NTP_IPS; do
  if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    if sudo iptables -A OUTPUT -p udp -d "$ip" --dport 123 -j ACCEPT 2>>"$LOG_FILE"; then
      ((ntp_rules_added++))
    else
      log_to_file "Erreur lors de l'autorisation NTP pour $ip"
      echo "⚠️ Erreur lors de l'ajout de la règle NTP pour $ip"
    fi
  else
    log_to_file "IP NTP invalide ignorée: $ip"
    echo "⚠️ IP NTP invalide ignorée: $ip"
  fi
done
set -e
echo " ↳ NTP autorisé vers $ntp_rules_added serveurs"
log_to_file "NTP autorisé vers $ntp_rules_added serveurs."
echo ""

echo "🚫 Application des règles de blocage..."

# Bloquer le port 5228 (Google Talk/Android Push Notifications)
echo " ↳ Port 5228 bloqué (IN/OUT)"
sudo iptables -A INPUT -p tcp --dport 5228 -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage port 5228 (TCP INPUT)"
sudo iptables -A INPUT -p udp --dport 5228 -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage port 5228 (UDP INPUT)"
sudo iptables -A OUTPUT -p tcp --dport 5228 -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage port 5228 (TCP OUTPUT)"
sudo iptables -A OUTPUT -p udp --dport 5228 -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage port 5228 (UDP OUTPUT)"
log_to_file "Port 5228 bloqué en INPUT/OUTPUT (Google Talk/Android Push Notifications)."

# Bloquer explicitement les nouvelles connexions entrantes non établies
echo " ↳ Nouvelles connexions entrantes bloquées"
sudo iptables -A INPUT -m state --state NEW -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage des nouvelles connexions (INPUT)"
log_to_file "Nouveaux paquets entrants non établis bloqués."

# Protéger contre les scans de ports (limiter les SYN entrants)
echo " ↳ Protection anti-scan activée"
sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 5 -j ACCEPT 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'autorisation SYN (INPUT)"
sudo iptables -A INPUT -p tcp --syn -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage SYN (INPUT)"
log_to_file "Protection contre les scans de ports activée."

# Bloquer les paquets invalides
echo " ↳ Paquets invalides bloqués"
sudo iptables -A INPUT -m state --state INVALID -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage des paquets invalides (INPUT)"
sudo iptables -A OUTPUT -m state --state INVALID -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage des paquets invalides (OUTPUT)"
sudo iptables -A FORWARD -m state --state INVALID -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage des paquets invalides (FORWARD)"
log_to_file "Paquets invalides bloqués."
echo ""

echo "📊 Configuration du logging..."
# Créer les chaînes de logging
sudo iptables -N LOGGING_IN 2>>"$LOG_FILE" || log_to_file "Chaîne LOGGING_IN existe déjà"
sudo iptables -N LOGGING_OUT 2>>"$LOG_FILE" || log_to_file "Chaîne LOGGING_OUT existe déjà"


# Logging des paquets bloqués
echo " ↳ Logging des paquets bloqués activé"
sudo iptables -A LOGGING_IN -m limit --limit 5/min --limit-burst 5 -j LOG --log-prefix "IPTables-Blocked-IN: " --log-level 4 2>>"$LOG_FILE" || log_to_file "Erreur lors de la configuration du logging INPUT"
sudo iptables -A LOGGING_IN -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage LOGGING_IN"
sudo iptables -A LOGGING_OUT -m limit --limit 5/min --limit-burst 5 -j LOG --log-prefix "IPTables-Blocked-OUT: " --log-level 4 2>>"$LOG_FILE" || log_to_file "Erreur lors de la configuration du logging OUTPUT"
sudo iptables -A LOGGING_OUT -j DROP 2>>"$LOG_FILE" || log_to_file "Erreur lors du blocage LOGGING_OUT"

# Logging spécifique pour HTTPS (port 443)
echo " ↳ Logging spécifique port 443 activé"
sudo iptables -A INPUT -p tcp --sport 443 -m limit --limit 1/min --limit-burst 3 -j LOG --log-prefix "IPTables-Blocked-IN-443: " --log-level 4 2>>"$LOG_FILE" || log_to_file "Erreur lors du logging port 443 (INPUT)"
sudo iptables -A OUTPUT -p tcp --dport 443 -m limit --limit 1/min --limit-burst 3 -j LOG --log-prefix "IPTables-Blocked-OUT-443: " --log-level 4 2>>"$LOG_FILE" || log_to_file "Erreur lors du logging port 443 (OUTPUT)"

# Logging spécifique pour le port 5228
echo " ↳ Logging spécifique port 5228 activé"
sudo iptables -A INPUT -p tcp --dport 5228 -m limit --limit 1/min --limit-burst 3 -j LOG --log-prefix "IPTables-Blocked-IN-5228: " --log-level 4 2>>"$LOG_FILE" || log_to_file "Erreur lors du logging port 5228 (INPUT)"
sudo iptables -A OUTPUT -p tcp --dport 5228 -m limit --limit 1/min --limit-burst 3 -j LOG --log-prefix "IPTables-Blocked-OUT-5228: " --log-level 4 2>>"$LOG_FILE" || log_to_file "Erreur lors du logging port 5228 (OUTPUT)"

# Rediriger vers les chaînes de logging
sudo iptables -A INPUT -j LOGGING_IN 2>>"$LOG_FILE" || log_to_file "Erreur lors de la redirection INPUT vers LOGGING_IN"
sudo iptables -A OUTPUT -j LOGGING_OUT 2>>"$LOG_FILE" || log_to_file "Erreur lors de la redirection OUTPUT vers LOGGING_OUT"

log_to_file "Logging configuré et actif."
echo ""

echo "💾 Sauvegarde et finalisation..."

# Sauvegarde des règles (TOUTES LES TABLES)
sudo iptables-save > /etc/iptables/rules.v4 2>>"$LOG_FILE" || log_to_file "Erreur lors de la sauvegarde des règles iptables"
echo " ↳ Règles sauvegardées dans /etc/iptables/rules.v4"
log_to_file "Règles sauvegardées dans /etc/iptables/rules.v4."

# Journaliser les règles appliquées (compatible systemd)
{
  echo "=== Règles iptables appliquées ==="
  sudo iptables -L -v -n 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'affichage des règles pour systemd"
} | systemd-cat -t fw.sh 2>>"$LOG_FILE" || log_to_file "Erreur lors de l'envoi des règles à systemd-cat"

# Afficher les règles en place sur le terminal
echo ""
echo "📋 Affichage des règles iptables appliquées..."
echo "=============================================="
if ! sudo iptables -L -v -n 2>>"$LOG_FILE"; then
  echo "⚠️ Erreur lors de l'affichage des règles iptables"
  log_to_file "Erreur lors de l'affichage des règles iptables"
fi
echo ""

echo "🎉 Firewall appliqué avec succès! PICO BELLO! ✨"
echo "📊 Résumé de la configuration:"
echo " • Mode: $($INTERNET_OK && echo 'En ligne' || echo 'Fallback')"
echo " • SSH: $ssh_rules_added ranges GitHub"
echo " • NTP: $ntp_rules_added serveurs"
echo " • DNS: Autorisé UNIQUEMENT vers 5 serveurs configurés"
echo " • HTTPS: Autorisé (HTTP bloqué)"
echo " • Port 5228: Bloqué et loggé"
echo " • Paquets INVALID: Bloqués"
echo " • Table NAT: Vidée (politiques ACCEPT par défaut kernel)"
echo " • Hotspot WiFi MITM: wlan1 (DHCP + FORWARD autorisés)"
echo " • Logging: Actif (voir $LOG_FILE)"
echo ""
sleep 3
log_to_file "=== Fin de l'exécution de fw.sh v13.0 avec support WiFi MITM ==="
log_to_file "Résumé :"
log_to_file "- Internet: $($INTERNET_OK && echo 'OK' || echo 'FALLBACK')"
log_to_file "- GitHub: $($GITHUB_OK && echo 'OK' || echo 'FALLBACK')"
log_to_file "- DNS: OUTPUT UNIQUEMENT vers 5 serveurs configurés"
log_to_file "- SSH: Autorisé vers GitHub uniquement ($ssh_rules_added ranges)"
log_to_file "- NTP: $ntp_rules_added serveurs ($($INTERNET_OK && echo 'dynamique' || echo 'statique'))"
log_to_file "- HTTPS: Autorisé, HTTP bloqué"
log_to_file "- Port 5228: Bloqué et loggé"
log_to_file "- Paquets INVALID: Bloqués"
log_to_file "- Tables nettoyées: filter, nat, mangle"
log_to_file "- Module: state (compatibilité maximale)"
log_to_file "- Hotspot WiFi MITM: wlan1 configuré avec DHCP et FORWARD"

# Signal de fin pour systemd
exit 0
