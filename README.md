# Qualys VMDR vers Wazuh

Ce connecteur interroge l'API Qualys VMDR, normalise les détections de vulnérabilites et écrit des évenements JSON Lines pour Wazuh.

## Installation

```bash
npm install
```

Renseigner ensuite `.env` :

```env
QUALYS_BASE_URL=https://qualysapi.qualys.eu
QUALYS_USERNAME=...
QUALYS_PASSWORD=...
OUTPUT_FILE=/var/ossec/integrations/qualys/qualys.ndjson
```

Lancement manuel :

```bash
npm start
```

## Architecture

```text
Qualys Host Detection API
  -> src/qualysClient.js
  -> src/normalizer.js
  -> cache QID KnowledgeBase
  -> data/state.json
  -> data/qualys.ndjson
  -> Wazuh JSON decoder
  -> ../rulesets wazuh/rules/qualys_vmdr_api.xml
```

Le collecteur utilise :

- `Host List VM Detection API` pour les détections par asset.
- `KnowledgeBase API` pour enrichir les QID avec titre, CVE, CVSS, solution et menace.
- un état local pour ne re-émettre que les changements importants.

## Configuration Wazuh

Sur le manager Wazuh, surveiller le fichier JSON Lines produit en modifiant le fichier de configuration :

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/integrations/qualys/qualys.ndjson</location>
</localfile>
```



Installer ensuite `./rules/qualys_vmdr_api.xml` dans les règles locales Wazuh, puis tester avec :

```bash
/var/ossec/bin/wazuh-logtest
```

Exemple d'évènement attendu :

```json
{"integration":"qualys_vmdr","event_type":"vulnerability_detection","asset_ip":"10.0.1.20","qid":"38173","title":"Example critical vulnerability","status":"New","severity":5,"qds":96,"risk_tier":"critical","internet_facing":true}
```
