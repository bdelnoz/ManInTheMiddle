# TODO Audit — ManInTheMiddle

## Court terme (1–2 jours)
- [ ] Corriger les références de script dans le README (référencer `mitm-sourcesvr.sh`).
- [ ] Corriger l’usage dans `client_traffic_capture.sh`.
- [ ] Revoir `.gitignore` pour éviter d’ignorer les HTML utiles.
- [ ] Ajouter section dépendances spécifiques à `fw.sh` dans la doc.

## Moyen terme (1–2 semaines)
- [ ] Restructurer le dépôt (ex: `scripts/`, `docs/`).
- [ ] Ajouter une licence (MIT/Apache-2.0/etc.).
- [ ] Ajouter des scripts de tests non destructifs (lint shell, `bash -n`, check root).

## Long terme
- [ ] Ajouter des scripts de simulation pour valider les règles iptables sans les appliquer.
- [ ] Créer des templates de configurations pour hostapd/dnsmasq et les documenter.
