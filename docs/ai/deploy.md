# Déploiement : Docker Compose, k3s, KEDA

Ordre : tout faire marcher avec Docker Compose d'abord, puis passer à k3s, puis ajouter KEDA.

## Docker Compose (`chore/docker-compose`)

Depuis la racine : copier `.env.example` en `.env`, renseigner les deux secrets,
puis `docker compose up -d --wait` et `./scripts/demo.sh`. Python 3 suffit côté
hôte pour les appels HTTP et le JSON du script. `docker compose down` conserve les
données ; `docker compose down -v` efface les volumes. Le Compose de test reste
indépendant (`docker-compose.test.yml`).

- Une seule image backend multi-étapes, Python 3.12 et uv épinglés, dépendances
  verrouillées sans celles de développement, utilisateur non root. API par défaut,
  migrations Alembic et worker RQ par surcharge de commande. La CI construit l'image
  sans la publier.
- PostgreSQL 17 et Redis 7 (AOF) ont chacun un volume. `migrate` attend PostgreSQL
  sain et termine avant l'API et le worker. L'API attend aussi Redis et CoreDNS ;
  le worker attend Redis et le site HTTPS sain. Sa commande valide d'abord les
  réglages, puis lance RQ avec le scheduler pour les relances.
- `demo-ca` génère une CA et un certificat serveur avec SAN, puis termine.
  Les volumes séparent la clé de CA, le matériel serveur et la CA publique :
  seul le générateur voit la clé de CA ; le worker ne monte que la CA publique,
  en lecture seule. Les lancements suivants réutilisent les certificats ; un
  certificat serveur expiré est renouvelé. Aucun matériel TLS n'entre dans le dépôt.
- `demo-site` utilise nginx HTTPS sans HSTS ni X-Content-Type-Options, avec CSP
  `unsafe-inline` et cookie sans attributs de protection. Seul le scanner d'en-têtes
  existe à ce stade ; il ne vérifie pas encore les attributs des cookies.
- `demo-dns` utilise CoreDNS épinglé dans Alpine pour disposer des outils de sonde.
  Sa zone `scanner.test` vit dans un volume. Le script y écrit le TXT avec remplacement
  atomique et incrément du numéro SOA ; le plugin `file` recharge sous 2 s, sans
  redémarrage ni modification d'un fichier du dépôt. Aucun DNS public n'est utilisé.

Seule l'API rejoint `edge`, le seul réseau non interne : Docker ne publie un port que
sur un tel réseau. Tous les autres sont `internal: true` : `api-data` relie API, migrations,
PostgreSQL et Redis ; `worker-data` relie worker, PostgreSQL et Redis ; `targets`
relie uniquement worker et nginx (alias `demo.scanner.test`). API et worker n'ont
aucun réseau commun. Le réseau `dns` relie uniquement API et CoreDNS ; son sous-réseau
fixé `172.30.53.0/24` donne `172.30.53.53` au résolveur TXT (`DNS_NAMESERVERS`).
En cas de conflit avec un réseau local, changer ensemble le sous-réseau, l'IP et
ses références dans Compose, la zone et le script. Le worker résout la cible via
l'alias Docker ; CoreDNS ne fournit que la preuve TXT à l'API.

Seul `127.0.0.1:8000` est publié. Le worker n'a aucun accès à Internet : ce montage
ne scanne que le site de démo. Le mode `APP_ENV=development` active explicitement l'exception
anti-SSRF pour le seul nom de démo et ajoute sa CA publique au contexte TLS du
worker. Hors développement, ces réglages font échouer la validation au démarrage
(voir `security.md`). `DNS_NAMESERVERS` accepte des IP explicites dans tous les
environnements et ne relâche aucune validation HTTP.

Le conteneur ZAP arrivera avec `feat/scanner-zap`, dans le réseau isolé décrit
dans `security.md`. Le Compose actuel ne constitue pas le filtrage de sortie
nécessaire aux outils externes : leurs adaptateurs et règles réseau restent à faire.

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
