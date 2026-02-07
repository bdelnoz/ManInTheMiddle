# Correction Audit — ManInTheMiddle

## Objectif
Liste des corrections concrètes à appliquer pour aligner la documentation, améliorer la cohérence et réduire les risques d’usage.

## Corrections recommandées (par priorité)

### Critiques
1. **Aligner la documentation sur le script réel**
   - Mettre à jour le README pour référencer `mitm-sourcesvr.sh` au lieu de `mitm-clientmitm-capture.sh`.
   - Vérifier tous les exemples de commandes et les corriger en conséquence.

2. **Corriger l’usage dans `client_traffic_capture.sh`**
   - L’usage actuel mentionne `./capture-client.sh` (inexistant). Ajuster vers `./client_traffic_capture.sh`.

### Importantes
3. **Revoir `.gitignore`**
   - Le pattern `*.html` ignore des fichiers HTML utiles (guides). Retirer ou remplacer par un dossier spécifique d’artefacts générés.

4. **Clarifier les dépendances**
   - Regrouper dans le README une section « dépendances exactes » pour `fw.sh` (curl, jq, dig).

5. **Séparer scripts “run” et scripts “diagnostic”**
   - Ajouter un dossier `scripts/` et déplacer `fw.sh`, `fw_diagnostic.sh`, `client_traffic_capture.sh`, `mitm-sourcesvr.sh` (si possible). Mettre à jour les chemins dans la doc.

### Moyennes
6. **Ajouter un fichier LICENSE**
   - Le dépôt n’indique pas de licence. Ajouter la licence souhaitée pour clarifier l’usage.

7. **Ajouter une convention de logs**
   - Définir clairement où sont écrits les logs et comment les purger.

## Effets attendus
- Réduction des erreurs d’usage.
- Documentation cohérente avec les scripts réellement présents.
- Meilleure maintenabilité pour l’équipe.
