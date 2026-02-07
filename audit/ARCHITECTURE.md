# Architecture — ManInTheMiddle

## Vue d’ensemble
Le dépôt fournit un ensemble de scripts shell pour configurer un routeur MITM (Man-in-the-Middle) destiné à capturer et analyser le trafic d’un appareil cible (SOURCESVR). L’architecture repose sur :
- iptables pour le NAT/forwarding et le filtrage.
- dnsmasq pour le DHCP.
- hostapd pour le hotspot WiFi.

## Modules/Blocs

### 1) Setup MITM (script principal)
- **Script**: `mitm-sourcesvr.sh`
- **Fonctions clés**:
  - Sauvegarde de l’état système (iptables, sysctl, interfaces).
  - Configuration interfaces LAN/WiFi.
  - Démarrage dnsmasq (DHCP) et hostapd (AP).
  - Configuration des règles NAT & FORWARD.
  - Restauration propre lors du `--stop`.

### 2) Firewall strict
- **Script**: `fw.sh`
- **Fonctions clés**:
  - Politiques DROP par défaut (filter).
  - Exceptions contrôlées (DNS, HTTPS, NTP, DHCP, SSH vers GitHub).
  - Logging fin (LOGGING_IN/LOGGING_OUT) vers syslog/systemd.

### 3) Diagnostics & capture
- **Scripts**: `fw_diagnostic.sh`, `client_traffic_capture.sh`
- **Fonctions clés**:
  - Vérifications iptables, NAT, services et interfaces.
  - Capture tcpdump 30s pour analyse rapide.

## Flux de données (simplifié)
1. **Initialisation**: `mitm-sourcesvr.sh --exec`
2. **DHCP**: Clients reçoivent IP via dnsmasq (LAN/WIFI séparés).
3. **Routage**: trafic client → iptables NAT → WAN.
4. **DNS**: redirection ou relais selon règles NAT/DNS.
5. **Capture**: opérateur lance Wireshark/tshark/tcpdump.
6. **Arrêt**: `mitm-sourcesvr.sh --stop` restaure l’état.

## Dépendances majeures
- `iptables`, `iproute2`, `dnsmasq`, `hostapd`, `iw`, `sysctl`.
- `curl`, `jq`, `dig` (pour `fw.sh`).
- Outils d’analyse recommandés: `tshark`, `tcpdump`, `wireshark`.
