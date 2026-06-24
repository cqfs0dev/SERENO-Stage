# Jour 13

L'objectif de la semaine est d'éxcuter le programme `scan.py` depuis son image docker dans la CI/CD avec Github Actions (éventuellement Gitlab-CI si le temps le permet) pour envoyer l'alerte quand nécessaire sur le chat de l'équipe (Discord).

🎉🎉🎉 Une grande étape d'accomplie puisque tu as réalisé le scan de bout en bout dans la Github Action, tu peux être fier de toi 🎉🎉🎉

Etapes du jour:

- Reprendre toutes tes notes depuis 2 semaines et les mettre au propre.
- Surligner les concepts et sujets pas complètement compris pour échanger dessus.
- Faire un commit avec un fichier resume-des-W1-a-3.md dans W3D3/

**Note:** Notre succès était prématuré puisque après relecture plus profonde, voici ce qui se passe lors de l'execution de la github action:

```yaml
name: Security Scan

on:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Pull scanner image
        run: docker pull propageur/scanner:latest <-- docker pull l'image publique depuis docker hub

      - name: Run scan
        run: |
          docker run --rm propageur/scanner:latest \
            --image=propageur/scanner:latest \ <-- ici trivy dans scan.py analyze l'image publique présente sur docker hub
            --discord-webhook=${{ secrets.DISCORD_WEBHOOK_URL }} \
            --project="SERENO"
```

Il n'y a pas d'étape de build de l'image dans le repository c'est pourquoi "ça marchait" et qu'on ne trouvait pas le "docker save" dans le code hier soir.

Ta github action doit build le dockerfile local puisq l'analyzer (et pour ça d'abord créer l'archive de l'image autrement ça ne fonctionnera pas).

La réussite n'est donc pas encore totale (ce qui n'enlève rien au grand bravo initial que tu mérites).

J'ai remis dans le dossier du jour W3D3, nos deux images vulnérables qu'on avait utilisé pour nos premiers tests :

- Dockerfile.node
- Dockerfile.python
- les versions W3D1/W3D2 qu'on a corrigé/amélioré hier:
  - Dockerfile
  - scan.py
  - requirements.txt

Etapes en local pour mettre en place l'environment de test pour valider que tout fonctionne comme voulu:

```bash
cd ./W3D3

docker buildx build -t node:vuln -f Dockerfile.node . # construit l'image vulnérable basée sur node
docker save node:vuln -o node_vuln.tar # sauvegarde l'archive tarball pour l'image node:vuln

docker buildx build -t python:vuln -f Dockerfile.python . # construit l'image vulnérable basée sur python
docker save python:vuln -o python_vuln.tar # sauvegarde l'archive tarball pour l'image python:vuln

docker buildx build -t scan:w3d3 -f Dockerfile . # construit l'image de ton scanner
docker save scan:w3d3 -o scan_w3d3.tar # sauvegarde l'archive tarball pour l'image de ton scanner scan:w3d3
```

A ce stade tu as dans ton deamon docker les images:

```bash
docker images

IMAGE                ID             DISK USAGE   CONTENT SIZE   EXTRA
node:vuln            0fc36eee8379        361MB         83.6MB
python:vuln          b394895e4abf        227MB           50MB
scan:w3d3            7f6285d553a0        441MB         97.9MB
```

Et tu as les archives dans ton dossier W3D3:

```bash
ls *.tar

node_vuln.tar
python_vuln.tar
scan_w3d3.tar
```

Si tu executes ton scan depuis docker avec la nouvelle image de scanner build juste au dessus en ciblant l'image publique sur dockerhub `propageur/scanner:latest`, le résultat va être le même que dans ta github action (et la même qu'en utilisant ton image publique elle-même)

```bash
docker run -e DISCORD_WEBHOOK_URL scan:w3d3 --image=propageur/scanner:latest --level=critical,high --project=w3d3

docker pull propageur/scanner:latest
docker run -e DISCORD_WEBHOOK_URL propageur/scanner:latest --image=propageur/scanner:latest --level=critical,high --project=w3d3
```

Par contre, si tu scannes tes images locales tu ne trouveras pas de vulnérabilités - tu auras même une erreur - en utilisant l'image du daemon puisque on ne lui ouvre pas de socket par mesure de sécurité.

```
docker run -e DISCORD_WEBHOOK_URL scan:w3d3 --image=scan:w3d3 --level=critical,high --project=w3d3-scan
docker run -e DISCORD_WEBHOOK_URL scan:w3d3 --image=node:vuln --level=critical,high --project=w3d3-node
docker run -e DISCORD_WEBHOOK_URL scan:w3d3 --image=python:vuln --level=critical,high --project=w3d3-python
```

On doit passer par les archives construites, en donnant accès à celles-ci :

```bash
docker run -v $(pwd):/archive -e DISCORD_WEBHOOK_URL scan:w3d3 --archive=/archive/scan_w3d3.tar --level=critical,high --project=w3d1-scan-archive
docker run -v $(pwd):/archive -e DISCORD_WEBHOOK_URL scan:w3d3 --archive=/archive/node_vuln.tar --level=critical,high --project=w3d1-scan-node
docker run -v $(pwd):/archive -e DISCORD_WEBHOOK_URL scan:w3d3 --archive=/archive/python_vuln.tar --level=critical,high --project=w3d1-scan-python
```

Ta github action doit donc `docker build` puis `docker save` puis utiliser ton scan `docker run propageur/scanner:latest ...` pour scanner l'image locale.

Etapes du jour supplémentaire après tout ça :

- (Ne pas oublier de mettre à jour l'image de ton scanner sur Docker Hub pour récupérer la dernière version buildée)
- Faire fonctionner la github action aec quelque chose qui devrait ressembler à ça:

```yaml

...
    - name: Run scan
        run: |
          docker buildx build -t my_local_image:latest .
          docker save my_local_image:latest -o my_local_image_latest.tar
          docker run -v ${pwd}/target --rm propageur/scanner:latest \
            --archive=/target/my_local_image_latest.tar \
            --discord-webhook=${{ secrets.DISCORD_WEBHOOK_URL }} \
            --project="SCANNER FROM GITHUB ACTION"

    - name: Run more scans - node
        run: |
          docker buildx build -t node:vuln -f Dockerfile.node .
          docker save node:vuln -o node_vuln.tar
          docker run -v ${pwd}/target --rm propageur/scanner:latest \
            --archive=/target/node_vuln.tar \
            --discord-webhook=${{ secrets.DISCORD_WEBHOOK_URL }} \
            --project="NODE FROM GITHUB ACTION"

    - name: Run more scans - python
        run: |
          docker buildx build -t python:vuln -f Dockerfile.python .
          docker save python:vuln -o python_vuln.tar
          docker run -v ${pwd}/target --rm propageur/scanner:latest \
            --archive=/target/python_vuln.tar \
            --discord-webhook=${{ secrets.DISCORD_WEBHOOK_URL }} \
            --project="PYTHON FROM GITHUB ACTION"

```
