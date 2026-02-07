# Testing — ManInTheMiddle

## Principes
Les scripts modifient le réseau local. Les tests doivent être non destructifs et ne pas altérer la configuration réelle sauf en environnement de labo.

## Tests recommandés (non destructifs)
1. **Syntaxe Bash**
```bash
bash -n mitm-sourcesvr.sh
bash -n fw.sh
bash -n fw_diagnostic.sh
bash -n client_traffic_capture.sh
```

2. **Vérification des dépendances**
```bash
command -v iptables dnsmasq hostapd iw tcpdump
```

## Tests fonctionnels (en labo)
- Démarrer MITM : `sudo ./mitm-sourcesvr.sh --exec`
- Vérifier attribution DHCP (LAN/WIFI).
- Capturer trafic (tshark/tcpdump).
- Stop & restore : `sudo ./mitm-sourcesvr.sh --stop`
