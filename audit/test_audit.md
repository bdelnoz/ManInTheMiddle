# Test Audit — ManInTheMiddle

## Tests exécutés

### Syntaxe Bash (non destructif)
- `bash -n mitm-sourcesvr.sh`
- `bash -n fw.sh`
- `bash -n fw_diagnostic.sh`
- `bash -n client_traffic_capture.sh`

## Résultats
- Tous les tests de syntaxe Bash ont réussi (exit code 0).

## Tests non exécutés (et pourquoi)
- Les tests fonctionnels complets (`--exec`/`--stop`) n’ont pas été lancés car ils modifient iptables, interfaces réseau et services (hostapd/dnsmasq), ce qui est risqué hors environnement de lab contrôlé.
