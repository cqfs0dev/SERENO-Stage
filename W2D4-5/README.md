# Jour 9

L'objectif de la semaine est de brancher le programme `scan.py` à Discord (et si le temps le permet à Google Chat) via un webhook pour envoyer des alertes sous formes de "cartes" correctement formatées avec les informations essentielles concernant le **projet** concerné(\*), les **images** scannées, les **vulnérabilités** trouvées et les **bibliothèques** (libraries) touchées à l'équipe.

Pour le quatrième jour (peut-être que la mantinée, on verra), comme tu es en avance on attaque la partie pipeline DevSecOps et en te laissant plus d'autonomie dans tes recherches et investigations (ce qui sera une des plus grandes compétences pour faire carrière en OSINT: "savoir chercher") :

- [ ] Visiter DockerHub https://hub.docker.com/ et chercher des images compatibles et adaptées pour utiliser ton scanner depuis un conteneur docker (fais une sélection de 4 ou 5 images qui te semblent intéressantes d'un point de vue sécurité, taille, version récente...).
- [ ] Comparer les vulnérabilités (docker scout) des images que tu retiens avec les résultats de ton scan.py (trivy).
- [ ] Créer un fichier csv avec les résulats de tes observations avec les colonnes suivantes:
  - image_name_and_tag
  - docker_hub_critical
  - docker_hub_high
  - docker_hub_medium
  - docker_hub_low
  - docker_hub_unspecified
  - scan_trivy_critical
  - scan_trivy_high
  - scan_trivy_medium
  - scan_trivy_low
  - scan_trivy_unknown
- [ ] Choisir une image après cette comparaison, pouvoir expliquer pourquoi.
- [ ] Créer une image docker pour ton programme 
  - [ ] Rechercher comment écrire une image docker pour un programme python
  - [ ] Comprendre chacune des lignes du fichier (beaucoup de failles de sécurités peuvent se cacher dans une image docker).
- [ ] Builder ton image docker grâce à (quelque chose comme) `docker build -t scanner .`
- [ ] Scanner ta propre image docker avec... ton scanner (version python `python scan.py ...`)
- [ ] Executer ton scanner (avec ses options, au moins `--image=...`) depuis docker, grâce à (quelque chose comme) `docker run scanner ...`
  - [ ] Chercher une solution au problème qui va se poser à ce moment-là
  - [ ] Chercher à comprendre pourquoi cette limitation existe et pourquoi elle est importante d'un point de vue sécurité (pouvoir l'expliquer à l'équipe vendredi ou lundi matin sous forme de devinette: "est-ce que vous savez pourquoi on ne peut pas ... ?", "Non? Voici pourquoi, c'est parce que ...").
- [ ] Scanner ta propre image docker avec... ton scanner (version docker `docker run ... scanner ...`)
- [ ] Vérifier que les résultats sont les mêmes qu'avec python et que le message Discord est bien envoyé et identique.
