cat > probleme.md << 'EOF'
# Problème : Scanner une image Docker depuis un conteneur Docker

## Le problème
Quand on scanne `scanner:latest` depuis `scanner:latest` lui-même,
on crée une dépendance circulaire — l'image scanne sa propre image.

## Pourquoi cette limitation existe (sécurité)

> "Est-ce que vous savez pourquoi on ne peut pas monter `/var/run/docker.sock` en production ?"

1. **Accès root à l'hôte** — monter le socket Docker dans un conteneur
   donne à ce conteneur un contrôle total sur la machine hôte.
2. **Bloqué en production** — Kubernetes et les CI/CD restrictifs
   interdisent ce montage pour éviter qu'un conteneur compromis
   prenne le contrôle de l'hôte.
3. **Surface d'attaque connue** — si le conteneur scanner est compromis,
   l'attaquant a accès à tous les conteneurs et à l'hôte.

## Solution alternative
Utiliser l'image officielle Trivy directement :

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image scanner:latest
```
EOF