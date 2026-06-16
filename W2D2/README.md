# Jour 7

L'objectif de la semaine est de brancher le programme `scan.py` à Discord (et si le temps le permet à Google Chat) via un webhook pour envoyer des alertes sous formes de "cartes" correctement formatées avec les informations essentielles concernant le **projet** concerné(\*), les **images** scannées, les **vulnérabilités** trouvées et les **bibliothèques** (libraries) touchées à l'équipe.

_Note(\*):_ le projet concerné sera pour le moment `"default unset project"` puisqu'il n'est pas encore branché dans une pipeline gitlab-ci ou github-action.

Pour le second jour, on continue :

- [x] Créer un webhook sur Discord.
- [x] **NE JAMAIS COMMIT AUCUN SECRET DANS GIT (DONC NE PAS COMMIT L'URL DU WEBHOOK)**
- [x] Chercher comment lire une valeur depuis une variable d'environnement et depuis un fichier .env en python pour "cacher la valeur" de l'URL du Webhook
- [x] Envoyer un premier message sans lien avec le scanner: `"hello platform team!"`
- [x] Envoyer un premier message depuis le scanner: `"hello platform team from scan.py"`
- [ ] 🍒 (Bonus) Gérer les codes HTTP (200, 400, 500...) renvoyer par le webhook en cas d'erreur et afficher un message dans le terminal: `"Oups. Something went wrong. ERR:{code et message d'erreur retourné}"`
- [ ] Améliorer le programme `scan.py` avec un argument optionel `--project NOM_DU_PROJET` qui aura pour valeur par default: `"default unset project"` et l'afficher dans le terminal:

```bash
> SCAN REPORT: [NOM_DU_PROJET]
> -------------------------

# no change
# ...

```

- [ ] Envoyer le message sur Discord via `scan.py` en suivant le même format que dans le terminal

```bash
> SCAN REPORT: manual scan tests
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

- [ ] S'assurer que l'ordre des vulnérabilités affichées soit toujours de la plus sévère à la moins sévère quelque soit l'ordre des valeurs données à l'argument `--level=`

> Exemple:
> ... --level=critical,high ...
> et
> ... --level=high,critical ...
> affiche toujours les vulnérabilités `critical` en premier et les vulnérabilités `high`
