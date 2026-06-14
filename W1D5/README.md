# Jour 4 - Après-Midi

Voici deux fichiers Dockerfile:

- Dockerfile.node: déclare une image docker pour une application nodejs (javascript/typescript)
- Dockerfile.python déclare une image docker pour une application python

Le développeur a introduit des failles de sécurité critiques dans ces images docker (en plus de la récente faille de `Debian13 - Trixie` sur `perl-base`)

Ton objectif en tant qu'Ingénieur Sécurité _"DevSecOps"_ est de les trouver grâce à ton programme `scan.py`

## Principales étapes (suite de D4):

1. Faire évoluer ton programme pour afficher les résultats ainsi:

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

2. (Super bonus) Faire évoluer ton programme pour permettre de lui donner plusieurs images à scanner en une fois: `python scan --image=...` pour afficher un unique résultat:

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
