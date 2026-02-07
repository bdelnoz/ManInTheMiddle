# Debug — ManInTheMiddle

## Checks rapides
```bash
sudo iptables -L -v -n
sudo iptables -t nat -L -v -n
ip addr show
ps aux | grep -E 'dnsmasq|hostapd'
```

## Diagnostic complet
```bash
sudo ./fw_diagnostic.sh 192.168.50.10
```

## Logs
- Firewall: `/var/log/firewall/iptables-fw.log`
- Logs MITM: `./logs/`
- Résultats: `./results/`

## Problèmes fréquents
- **Pas d’AP**: vérifier support AP `iw list`.
- **DHCP inactif**: vérifier `dnsmasq` et les ports UDP 67/68.
- **Pas de DNS**: vérifier règles NAT/DNS et resolv.conf.
