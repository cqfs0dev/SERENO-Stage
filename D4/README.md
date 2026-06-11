# Jour 4 - Après-Midi

Voici deux fichiers Dockerfile:

- Dockerfile.node: déclare une image docker pour une application nodejs (javascript/typescript)
- Dockerfile.python déclare une image docker pour une application python

Le développeur a introduit des failles de sécurité critiques dans ces images docker (en plus de la récente faille de `Debian13 - Trixie` sur `perl-base`)

Ton objectif en tant qu'Ingénieur Sécurité _"DevSecOps"_ est de les trouver grâce à ton programme `scan.py`

## Principales étapes:

1. Récupérer ce code depuis github sur ta machine dans ton envionement ubuntu (`git ...`)
2. Construire les images docker à partir des `Dockerfile` (`docker ... -f ... -t ... .`, cherche à quoi servent les options `-f` et `-t` dans le `dcoker --help` de la commande qui sert à construire une image).
3. Analyser les images locales avec ton programme `scan.py` pour trouver les vulnérabilités `CRITICAL` qui ne sont pas présentent dans les images de base `node:lts-trixie-slim` et `python:3.14-slim-trixie` (tu peux exécuter trivy directement dans ton terminal pour vérifier que ton programme te donne un résultat cohérent `trivy image ...`)
4. (Bonus) Faire évoluer ton programme pour afficher les résultats ainsi:

- Pour l'image node:

```bash
> Vuln(s) found:

> debian 13.5
> critical: 2
> -  perl-base
> -  perl-base

> node-pkg
> critical: 2
> - lodash
> - minimist
```

- Pour l'image python:

```bash
> Vuln(s) found:

> debian 13.5
> critical: 2
> -  perl-base
> -  perl-base

> python-pkg
> critical: 2
> - PyYAML
> - PyYAML
```

5. (Super bonus) Faire évoluer ton programme pour permettre de lui donner plusieurs images à scanner en une fois: `python scan --image=...` pour afficher un unique résultat:

```bash
> SCAN REPORT:
> -------------------------

> Docker Image: Hello-Node
> Vuln(s) found:

> debian 13.5
> critical: 2
> -  perl-base
> -  perl-base

> node-pkg
> critical: 2
> - lodash
> - minimist

> -------------------------

> Docker Image: Hello-Py
> Vuln(s) found:

> debian 13.5
> critical: 2
> -  perl-base
> -  perl-base

> python-pkg
> critical: 2
> - PyYAML
> - PyYAML

> -------------------------
```
