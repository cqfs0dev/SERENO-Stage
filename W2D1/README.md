# Jour 6 après-midi

L'objectif de la semaine est de brancher le programme `scan.py` à Discord (et si le temps le permet à Google Chat) via un webhook pour envoyer des alertes sous formes de "cartes" correctement formatées avec les informations essentielles concernant le **projet** concerné(\*), les **images** scannées, les **vulnérabilités** trouvées et les **bibliothèques** (libraries) touchées à l'équipe.

_Note(\*):_ le projet concerné sera pour le moment `"default unset project"` puisqu'il n'est pas encore branché dans une pipeline gitlab-ci ou github-action.

Pour le premier jour (après-midi, le matin étant occupé avec les réunions de la semaine):

- Créer un webhook sur Discord.
- **NE JAMAIS COMMIT AUCUN SECRET DANS GIT (DONC NE PAS COMMIT L'URL DU WEBHOOK)**
- Chercher comment lire une valeur depuis une variable d'environnement et depuis un fichier .env en python pour "cacher la valeur" de l'URL du Webhook
- Envoyer un premier message sans lien avec le scanner: `"hello platform team!"`
- Envoyer un premier message depuis le scanner: `"hello platform team from scan.py"`
- Gérer les codes HTTP (200, 400, 500...) renvoyer par le webhook en cas d'erreur et afficher un message dans le terminal: `"Oups. Something went wrong. ERR:{code et message d'erreur retourné}"`
- 🍒 (Bonus) Améliorer le programme `scan.py` avec un argument optionel `--project NOM_DU_PROJET` qui aura pour valeur par default: `"default unset project"` et l'afficher dans le terminal:

```bash
> SCAN REPORT: [NOM_DU_PROJET]
> -------------------------

# no change
# ...

```
