# Déploiement : Docker Compose, k3s, KEDA

Ordre : tout faire marcher avec Docker Compose d'abord, puis passer à k3s, puis ajouter KEDA.

## Docker Compose (`chore/docker-compose`)

Depuis la racine : copier `.env.example` en `.env`, renseigner les trois secrets
(`JWT_SECRET`, `POSTGRES_PASSWORD`, `ZAP_API_KEY`),
puis `docker compose up -d --wait` et `./scripts/demo.sh`. Python 3 suffit côté
hôte pour les appels HTTP et le JSON du script. `docker compose down` conserve les
données ; `docker compose down -v` efface les volumes. Le Compose de test reste
indépendant (`docker-compose.test.yml`).

- Une seule image backend multi-étapes, Python 3.12 et uv épinglés, dépendances
  verrouillées sans celles de développement, utilisateur non root. API par défaut,
  migrations Alembic et worker RQ par surcharge de commande. La CI construit l'image
  sans la publier.
- Le frontend est construit avec `node:24.15.0-alpine`, puis servi par
  `nginx:1.28.0-alpine3.21` sans root sur 8080. Il attend l’API saine.
  Le réseau interne `web` ne relie que frontend et API ; `/api/` est relayé vers
  `http://api:8000/`. Les autres chemins retombent sur `index.html` pour les routes SPA.
  Le HTML n’est pas mis en cache : un nonce nginx par réponse autorise les styles
  Angular sous une CSP stricte (voir `security.md`).
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
  `unsafe-inline` et cookie sans attributs de protection. Les scanners `headers`
  et `tls`, ainsi que `ratelimit` et `waf`, sont activés. La démo n'a ni limitation
  de débit ni WAF.
  Elle accepte volontairement TLS 1.1 en plus de TLS 1.2/1.3,
  avec `@SECLEVEL=0` ; 3DES est proposé si OpenSSL de l'image le fournit encore.
  Ces réglages ne conviennent qu'à cette cible de démonstration isolée.
- `demo-dns` utilise CoreDNS épinglé dans Alpine pour disposer des outils de sonde.
  Sa zone `scanner.test` vit dans un volume. Le script y écrit le TXT avec remplacement
  atomique et incrément du numéro SOA ; le plugin `file` recharge sous 2 s, sans
  redémarrage ni modification d'un fichier du dépôt. Aucun DNS public n'est utilisé.

L’API et le frontend rejoignent `edge`, le seul réseau non interne : Docker ne publie un port que
sur un tel réseau. Tous les autres sont `internal: true` : `api-data` relie API, migrations,
PostgreSQL et Redis ; `worker-data` relie worker, PostgreSQL et Redis ; `targets`
relie uniquement worker et nginx (alias `demo.scanner.test`). API et worker n'ont
aucun réseau commun. Le réseau `dns` relie uniquement API et CoreDNS ; son sous-réseau
fixé `172.30.53.0/24` donne `172.30.53.53` au résolveur TXT (`DNS_NAMESERVERS`).
En cas de conflit avec un réseau local, changer ensemble le sous-réseau, l'IP et
ses références dans Compose, la zone et le script. Le worker résout la cible via
l'alias Docker ; CoreDNS ne fournit que la preuve TXT à l'API.

Le frontend publie `127.0.0.1:4200` et l’API conserve `127.0.0.1:8000`. Le worker n'a aucun accès à Internet : ce montage
ne scanne que le site de démo. Le mode `APP_ENV=development` active explicitement l'exception
anti-SSRF pour le seul nom de démo et ajoute sa CA publique au contexte TLS du
worker. Hors développement, ces réglages font échouer la validation au démarrage
(voir `security.md`). `DNS_NAMESERVERS` accepte des IP explicites dans tous les
environnements et ne relâche aucune validation HTTP.

Le conteneur `zap` (`zaproxy/zap-stable:2.16.1`) tourne en démon sur `0.0.0.0:8080`
sans port publié sur l'hôte, avec clé `ZAP_API_KEY`, mémoire bornée (`mem_limit: 1g`)
et `start_period: 60s` pour absorber son démarrage lent (30–60 s) avant que le worker
ne démarre. Il n'est relié qu'aux réseaux internes `zap-control` (avec le worker) et
`targets` (avec `demo-site`), sans accès à PostgreSQL, Redis, l'API, CoreDNS ni Internet.
Le Compose actuel ne constitue pas le filtrage de sortie
nécessaire aux outils externes vers Internet : leurs règles de sortie restent à faire.
Le scanner TLS épingle l'IP validée et utilise la CA publique de démo uniquement
en développement, via les arguments de validation de certificat de sslyze.

La note dépend des protocoles et suites réellement acceptés par l'image nginx et des
alertes passives de ZAP hors exclusions d'en-têtes.
`DEMO_EXPECTED_GRADE=E ./scripts/demo.sh` active une vérification facultative de la
note ; sans cette variable, le script affiche le résultat. Le même réglage surcharge
l'attente Playwright (`E` par défaut), qui vérifie aussi les catégories `TLS`,
`Limitation de débit`, `Pare-feu applicatif` et `Analyse passive (ZAP)`. Note mesurée sur la
pile Docker avec les 5 scanners : **E, 12/100**. ZAP ajoute 3 constats (en-tête
anti-clickjacking absent, version du serveur divulguée, directives de cache) sans doublon
avec le scanner d'en-têtes ; son analyse prend environ 3 s sur la démo.

Après avoir modifié un fichier de `deploy/demo/` (par exemple `nginx.conf`), recréer le
conteneur : `docker compose up -d --force-recreate demo-site`. Ces fichiers sont montés un par
un ; un éditeur qui remplace le fichier laisse le conteneur sur l'ancienne version, et un
simple `docker compose restart` échoue.

## Lab Proxmox : Juice Shop (`docker-compose.lab.yml`)

Sur Debian01, l'override `docker-compose.lab.yml` permet de scanner Juice Shop
(Debian02, `http://10.10.10.30:3000`) sous le nom `juiceshop.lab`, servi par `demo-dns`.
Pare-feu `DOCKER-USER`, persistance systemd et effet de l'erreur TLS sur la note :
`deploy/lab/README.md`.

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
