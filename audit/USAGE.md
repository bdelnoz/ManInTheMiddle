# Usage — ManInTheMiddle

## 1) Lancer le MITM (script principal)
```bash
sudo ./mitm-sourcesvr.sh --exec
```

### Mode sans WiFi
```bash
sudo ./mitm-sourcesvr.sh --exec --wifi-disable
```

### Arrêt & restauration
```bash
sudo ./mitm-sourcesvr.sh --stop
```

## 2) Démarrer le firewall strict
```bash
sudo ./fw.sh
```

## 3) Diagnostic IPTV/MITM
```bash
sudo ./fw_diagnostic.sh 192.168.50.10
```

## 4) Capture rapide d’un client
```bash
sudo ./client_traffic_capture.sh 192.168.50.10
```

## 5) Capture détaillée (exemples)
```bash
sudo tshark -i eth1 -b filesize:10240 -w ./results/capture-%Y%m%d_%H%M%S.pcap
```
