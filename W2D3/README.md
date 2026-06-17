# Jour 8

L'objectif de la semaine est de brancher le programme `scan.py` à Discord (et si le temps le permet à Google Chat) via un webhook pour envoyer des alertes sous formes de "cartes" correctement formatées avec les informations essentielles concernant le **projet** concerné(\*), les **images** scannées, les **vulnérabilités** trouvées et les **bibliothèques** (libraries) touchées à l'équipe.

Pour le troisième jour, on continue :

- [ ] Régler le problème identifié hier à propos du comptable des vulnérabilités avec `python W2D2/scan.py --image=hello-py:latest --image=hello-nod:latest --level=critical --project="manual scan tests"`

- [ ] S'assurer d'avoir complètement restauré le comportement de W1D4 pour que le terminal affiche:
```bash
python W1/D4scan.py --image=hello-py:latest --image=hello-nod:latest --level=critical --project="manual scan tests

SCAN REPORT: manual scan tests
-------------------------

Docker Image: hello-py:latest
Vuln(s) found:

debian 13.5
critical: 2
- perl-base
- perl-base

python-pkg
critical: 2
- PyYAML
- PyYAML

-------------------------

Docker Image: hello-node:latest
Vuln(s) found:

debian 13.5
critical: 2
- perl-base
- perl-base

node-pkg
critical: 2
- lodash
- minimist

-------------------------
```
- [ ] S'assurer que le même affichage avec les mêmes informations apparaît sur Discord lorsque la notification est envoyée
- [ ] S'assurer que le nouveau fichier `scan.py` dans W2D3 est le bon fichier utilisé, à jour, propre et que c'est celui qui rempli les objectis ci-dessus pour avoir une base de travaille saine et claire.

Puis, on va rendre l'affichage sur Discord plus efficace et rapide à lire en cas d'alerte, pour ça on va ajouter de la structure visuelle (organisation, hiérarchie, couleur, ...). Ce n'est pas uniquement de l'esthétique pour faire jolie, mais ce qu'on appelle de la hiérarchie de l'information pour l'oeil et le cerveau comprennent plus vite (ça fait partie de l'UX - expérience utilisateur) :

- [ ] Lire la documentation de Discord sur les `Embeds`, demander des explications à ton LLM préféré et faire des recherches sur le fonctionement de ce type de message. Quelques ressources officielles:
  - https://discord.com/developers/docs/resources/webhook#execute-webhook
  - https://discord.com/developers/docs/resources/message#embed-object

- [ ] Faire des essais et expérimentations à partir des informations stockées dans la variable result pour arriver à un message Discord qui pourrait ressembler à quelque chose comme ça (pour une unique image): 

    ```markdown
                                                                        (aides qui ne font pas partie du message)
    ┌────────────────────────────────────────────────────────────────┐
    │  🔴  scan.py                                          [webhook]│   ← username + bot tag
    │                                                                │
    │  ┃ 🛡️  Vulnerabilities found — hello-py:latest                 │   ← embed title
    │  ┃                                                             │
    │  ┃ Scan completed · debian 13.5 · python-pkg                   │   ← description
    │  ┃                                                             │
    │  ┃  debian 13.5                                                │   ← field (per target)
    │  ┃  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
    │  ┃  │ 🔴 CRITICAL │  │ 🟠 HIGH      │  │ 🟡 MEDIUM   │          │   ← inline fields
    │  ┃  │      2      │  │      10     │  │      32     │          │     (counts)
    │  ┃  └─────────────┘  └─────────────┘  └─────────────┘          │
    │  ┃  • perl-base    CVE-2026-42496                              │
    │  ┃  • perl-base    CVE-2026-8376                               │
    │  ┃                                                             │
    │  ┃  python-pkg                                                 │   ← field (per target)
    │  ┃  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
    │  ┃  │ 🔴 CRITICAL │  │ 🟠 HIGH      │  │ 🟡 MEDIUM   │          │   ← inline fields
    │  ┃  │      2      │  │      7      │  │      17     │          │     (counts)
    │  ┃  └─────────────┘  └─────────────┘  └─────────────┘          │
    │  ┃  • PyYAML       CVE-2017-18342                              │
    │  ┃  • PyYAML       CVE-2020-14343                              │
    │  ┃                                                             │
    │  ┃ ─────────────────────────────────────────────────────────── │
    │  ┃ scan.py · 2026-06-17 14:32 UTC                  [footer]    │   ← footer + timestamp
    └────────────────────────────────────────────────────────────────┘

    ```

- [ ] Envoyer un message sur le modèle ci-dessus pour CHAQUE image scannée donc avec l'exemple `python scan.py --image=hello-py:latest --image=hello-nod:latest --level=critical --project="manual scan tests`, on obtiendra 
  - un message dans le terminal qui englobe les deux images (ça ne change pas de W1D4)
  - un message Discord pour l'image python, 
  - un message Discord pour l'image node