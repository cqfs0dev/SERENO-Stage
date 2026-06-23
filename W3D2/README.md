# Jour 12

L'objectif de la semaine est d'éxcuter le programme `scan.py` depuis son image docker dans la CI/CD avec Github Actions (éventuellement Gitlab-CI si le temps le permet) pour envoyer l'alerte quand nécessaire sur le chat de l'équipe (Discord).

Etapes du jour (sans ordre particulier):

- Chercher comment rendre l'image docker `scanner:latest` qui est pour le moment utniquement en local sur ta machine, accessible depuis internet (gratuitement) avec par exemple: https://docs.docker.com/docker-hub
  - Si c'est toujours le cas tu as même droit à 1 image privée sur un compte gratuit.

- Commencer à lire la documentation des Github Actions: https://docs.github.com/en/actions
  - Chercher comment reécupérer une image docker externe (publique) depuis une github action
  - Chercher comment exécuter une image docker depuis une github action

- Lire la documentation Github sur la gestion des secrets (pour l'url du webhook Discord) https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets?versionId=free-pro-team%40latest&productId=actions
