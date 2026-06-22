# Jour 11

L'objectif de la semaine est d'éxcuter le programme `scan.py` depuis son image docker dans la CI/CD avec Github Actions (éventuellement Gitlab-CI si le temps le permet) pour envoyer l'alerte quand nécessaire sur le chat de l'équipe (Discord).

Suite de la semaine 2, l'étape 8 a été blocante.

Voici l'indice qui était présent dans le message Discord que j'ai envoyé avec une solution possible pour gérer le problème d'accès au daemon docker depuis un conteneur docker.

```
SCAN REPORT : scan-depuis-docker-un-indice-est-caché-dans-ce-message-pour-résoudre-l-etape-8
Date        : 2026-06-19 13:45 UTC
============================================================

IMAGE : scanner.tar <-- L'indice est ici
----------------------------------------
```

Lors du point de vendredi, tu as choisi l'option: "Ne me donne pas la solution, je vais chercher avec l'indice".

Voici donc une idée de prompt pour t'aider avec les LLMs si besoin:

```markdown
Mon responsable de stage (CTO) m'a dit que ma solution alternative au problème d'accès root à l'hôte via le montage de la socket du daemon docker n'était pas correcte puisque utiliser l'image docker officielle trivy en montant la socket présente exactement le même problème. Au lieu de faire confiance à mon code dans mon image, je fais confiance à l'image officielle trivy, certes surement plus sécurisée par des ingénieurs professionnels et expérimentés, mais le risque de RCE par une `supply-chain attack` reste réel.

D'autre part, il a réalisé lui même l'exercice, en analysant l'image docker de mon scanner avec mon propre scanner via trivy, vi python ET via docker, sans problème.
Il l'a fait sans avoir besoin d'accéder au daemon docker et m'a laissé l'indice suivant :

> SCAN REPORT : scan-depuis-docker-un-indice-est-caché-dans-ce-message-pour-résoudre-l-etape-8
> Date : 2026-06-19 13:45 UTC
> ============================================================
>
> ## IMAGE : scanner.tar <-- L'indice est ici

L'image scannée `scanner.tar` me parait différente de tout ce que j'ai analysé jusqu'à maintenant qui suivait le format: `scanner:latest`, `python:3.14`, ...

- Qu'est-ce que l'extension `.tar` ?
- Est-ce une image docker aussi ?
- Quand j'ai fait mon docker build, où est-ce que je la trouve ?
- Il a du changer du code dans mon scan.py j'imagine, je dois tout recommencer ?

Explique moi en détail pouquoi et comment ça marche et pourquoi je n'ai pas trouvé ça plus tôt sur internet ou avec Claude, ChatGPT, et autres LLMs?
```

Etapes du jour:

- Comprendre la réponse du LLM, comprendre ce qu'est un `.tar` dans le contexte d'une image docker
- Contruire `scanner.tar` en plus de `scanner:latest` afin de l'anaylser avec `docker run scanner...` sans monter la socker du daemon docker.
- Adapter le code de `scan.py` afin que la subcommand trivy analyse correctement l'image.
- Parvenir à envoyer le message Discord avec l'analyse (comme le mien de vendredi): ./W3D1/discord_message_example.png
- Commencer à lire la documentation des Github Actions: https://docs.github.com/en/actions
  - Chercher comment reécupérer une image docker externe (publique) depuis une github action
  - Chercher comment exécuter une image docker depuis une github action
- Lire la documentation Github sur la gestion des secrets (pour l'url du webhook Discord) https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets?versionId=free-pro-team%40latest&productId=actions
- Chercher comment rendre l'image docker `scanner:latest` qui est pour le moment utniquement en local sur ta machine, publique sur internet (gratuitement) avec par exemple: https://docs.docker.com/docker-hub
