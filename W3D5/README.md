# Jour 15

L'objectif de la semaine est d'éxcuter le programme `scan.py` depuis son image docker dans la CI/CD avec Github Actions (éventuellement Gitlab-CI si le temps le permet) pour envoyer l'alerte quand nécessaire sur le chat de l'équipe (Discord).

C'est réussi 🎉

Pour aujourd'hui : 

- Continuer la mise au propre de tes notes sur W1, W2, W3
- Essayer de changer l'image de base `python` pour réduire les vulnérabilités présentes dans le scanner
  - example: `3.12-alpine` 
- Si vraiment tu veux te faire du mal, regarder pour utiliser une image `distroless` de chez Google comme par exemple: `gcr.io/distroless` 
  - ce qui implique de regarder ce que sont les image docker dites `multi-stage`
