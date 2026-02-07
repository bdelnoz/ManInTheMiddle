# Installation — ManInTheMiddle

## Prérequis (Kali/Debian)
```bash
sudo apt-get update
sudo apt-get install -y \
  iproute2 iptables procps dnsmasq hostapd iw wireless-tools net-tools rfkill \
  tshark tcpdump curl jq dnsutils
```

## Vérifications matérielles
- Carte WiFi compatible AP (nl80211) :
```bash
sudo iw list | grep -A10 "Supported interface modes"
```

- Régulation et RFKill :
```bash
sudo iw reg set BE
sudo rfkill unblock all
```

## Notes iptables/nftables
Si nécessaire, basculer vers iptables-legacy:
```bash
sudo update-alternatives --config iptables
```

## Permissions
Les scripts doivent être exécutés en root:
```bash
sudo -s
```
