# Déploiement : Docker Compose, k3s, KEDA

Ordre : tout faire marcher avec Docker Compose d'abord, puis passer à k3s, puis ajouter KEDA.

## Docker Compose (`chore/docker-compose`)

`docker compose up` lance tout en local : API, worker, PostgreSQL, Redis (persistance activée) et un site cible volontairement mal configuré pour la démo. Le conteneur ZAP arrive avec `feat/scanner-zap`, dans le réseau isolé décrit dans `security.md`.

## k3s sur Proxmox (`feat/k8s`)

Cible : un cluster k3s dans des VM du Proxmox, sur un autre PC que le poste de développement.

| Machine | Rôle |
| --- | --- |
| PC de développement | Écrire le code, construire les images, piloter le cluster avec kubectl |
| PC Proxmox | Héberger des VM Linux qui forment le cluster k3s |
| GitHub Container Registry | Stocker les images entre les deux machines |

1. Sur le Proxmox, créer deux VM Linux sur le réseau local : un serveur k3s et un agent.
2. Installer k3s sur le serveur, puis rattacher l'agent au cluster.
3. Copier le kubeconfig du serveur sur le PC de développement et y remplacer `127.0.0.1` par l'IP de la VM.
4. Pousser les images (depuis le PC ou la CI) vers le registre.
5. `kubectl apply` sur les manifestes de `deploy/k8s` (Deployments, Services, Secrets).
6. Accès distant plus tard : VPN (WireGuard ou Tailscale), pas d'ouverture de ports.

## Scaling (`feat/k8s-keda`)

- Horizontal : on ajoute des pods worker, on ne grossit pas un pod.
- KEDA lit la longueur de la file Redis (ScaledObject) et ajuste le nombre de workers entre un minimum et un maximum. Le CPU est un mauvais signal : un scan attend surtout le réseau.
- Fiabilité : relance automatique des jobs en échec, persistance Redis activée.
