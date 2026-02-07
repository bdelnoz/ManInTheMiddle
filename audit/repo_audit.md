# Audit du dépôt ManInTheMiddle

Date: 2025-02-XX

## 1) Inventaire complet des fichiers (classés par domaines/fonctions)

### Scripts (shell)
- `client_traffic_capture.sh`
- `fw.sh`
- `fw_diagnostic.sh`
- `mitm-sourcesvr.sh`

### Documentation
- `README.md`

### Frontend / statique (HTML)
- `linkedin_mitm_post.html`
- `wifi-channels-guide.html`
- `wifi-channels-guide-en.html`

### Configuration
- `.gitignore`

### Infra
- (aucun)

### Backend
- (aucun)

### Data
- (aucun)

### Tests
- (aucun)

## 2) Fichiers clés par domaine + usage

### Scripts (shell)
- `mitm-sourcesvr.sh`: script principal qui configure le routeur MITM (iptables, dnsmasq, hostapd), sauvegarde/restaure l’état système, et gère les interfaces LAN/WIFI/WAN. C’est le point d’entrée principal opérationnel. Il gère aussi les logs, les fichiers temporaires et les sauvegardes d’état.
- `fw.sh`: script “firewall strict” pour iptables avec logging, règles de sécurité restrictives, et support pour hotspot WiFi MITM. Il met en place des politiques DROP et des exceptions (DNS, HTTPS, NTP, DHCP, etc.).
- `fw_diagnostic.sh`: script de diagnostic pour vérifier les règles iptables, l’état des interfaces, la présence de dnsmasq/hostapd et des logs, utile pour la résolution d’incidents.
- `client_traffic_capture.sh`: script de capture rapide du trafic d’un client, avec analyse basique (protocoles, ports, IPs) après capture tcpdump.

### Documentation
- `README.md`: documentation très complète orientée Kali Linux, avec prérequis, explications techniques, étapes d’usage (start/stop), règles iptables, et guides de dépannage.

### Frontend / statique (HTML)
- `wifi-channels-guide.html`: guide visuel complet (FR) sur les canaux WiFi.
- `wifi-channels-guide-en.html`: guide visuel complet (EN) sur les canaux WiFi.
- `linkedin_mitm_post.html`: page de présentation (style “post”) sur le projet.

### Configuration
- `.gitignore`: ignore des artefacts de logs, outputs, archives, etc.

## 3) Structure globale du projet

### Points d’entrée
- Principal: `mitm-sourcesvr.sh` (setup/restore MITM, DHCP, DNS, iptables).
- Compléments: `fw.sh` (firewall), `fw_diagnostic.sh` (diagnostic), `client_traffic_capture.sh` (capture ponctuelle).

### Modules principaux (logiques)
- **Routage + NAT + DNS**: géré par iptables dans `mitm-sourcesvr.sh` et renforcé par `fw.sh`.
- **DHCP**: géré via `dnsmasq` (config générée à la volée).
- **Hotspot WiFi**: géré via `hostapd` (config générée à la volée).
- **Logging & sauvegarde d’état**: création de logs et backups pour restauration.

### Flux de données (haut niveau)
1. L’opérateur lance `mitm-sourcesvr.sh --exec` pour initialiser le MITM.
2. Le script configure les interfaces (LAN/WIFI), iptables (NAT + FORWARD), et lance dnsmasq/hostapd.
3. Le trafic des clients est routé vers le WAN, avec redirection DNS transparente.
4. Les logs et captures (manuelles) sont stockés localement dans `logs/` et `results/`.
5. Sur arrêt (`--stop`), le script restaure l’état système.

### Dépendances majeures
- Système/réseau: `iptables`, `iproute2`, `sysctl`, `dnsmasq`, `hostapd`, `iw`, `rfkill`, `tshark` (recommandé), `tcpdump`.
- Utilitaires: `curl`, `jq`, `dig` (pour `fw.sh`), `systemd` pour logging.

## 4) API & endpoints
- Aucune API web (FastAPI/Flask/Express/etc.) détectée.

## 5) Scripts .sh (détails d’usage)

### `mitm-sourcesvr.sh`
- Usage principal: `sudo ./mitm-sourcesvr.sh --exec` (ou `--start`), `sudo ./mitm-sourcesvr.sh --stop`.
- Rôle: configuration complète du MITM (iptables, DNS, DHCP, WiFi hotspot).
- Génère: configs temporaires `dnsmasq`/`hostapd`, backups d’état, logs.

### `fw.sh`
- Usage: `sudo ./fw.sh`.
- Rôle: firewall strict avec journalisation, gestion DNS/HTTPS/NTP/SSH, règles spécifiques pour hotspot WiFi MITM.
- Dépendances: iptables, curl, jq, dig.

### `fw_diagnostic.sh`
- Usage: `sudo ./fw_diagnostic.sh <IP_IPTV>`.
- Rôle: diagnostic complet des politiques iptables, NAT, interfaces, services et logs.

### `client_traffic_capture.sh`
- Usage: `sudo ./client_traffic_capture.sh <IP_CLIENT>`.
- Rôle: capture tcpdump 30s + analyse rapide du trafic (protocoles/ports/IP).

## 6) Scripts .py
- Aucun fichier `.py` détecté.

## 7) Duplications, conflits potentiels, obsolescence
- **README vs script réel**: le README fait référence à `mitm-clientmitm-capture.sh` alors que le dépôt contient `mitm-sourcesvr.sh`. Cela peut causer de la confusion.
- **Nom d’usage incohérent**: `client_traffic_capture.sh` mentionne `./capture-client.sh` dans l’usage, ce qui ne correspond pas au nom du fichier.
- **.gitignore**: le pattern `*.html` ignore potentiellement des pages statiques utiles qui sont déjà versionnées dans le dépôt.
- **Redondance**: deux guides WiFi (FR/EN) ont un contenu similaire (acceptable si ciblage multi-langues).

## 8) Tableau synthétique des fichiers

| Fichier | Usage |
|---|---|
| `README.md` | Documentation complète d’installation, usage, et dépannage MITM. |
| `mitm-sourcesvr.sh` | Script principal: configure NAT/DHCP/DNS/hotspot pour MITM. |
| `fw.sh` | Script firewall strict avec logging et exceptions contrôlées. |
| `fw_diagnostic.sh` | Diagnostic iptables/services/réseau. |
| `client_traffic_capture.sh` | Capture courte du trafic client + analyse rapide. |
| `linkedin_mitm_post.html` | Page statique de présentation du projet. |
| `wifi-channels-guide.html` | Guide FR des canaux WiFi. |
| `wifi-channels-guide-en.html` | Guide EN des canaux WiFi. |
| `.gitignore` | Ignore logs/outputs/archives/fichiers générés. |

## 9) Tableau des endpoints
- N/A (aucune API détectée).
