# web-vuln-scanner

Projet portfolio et d'apprentissage : scanner les vulnérabilités d'un site dont
l'utilisateur a prouvé la propriété, puis produire un rapport noté de A à E.

> ⚠️ À utiliser uniquement sur des cibles pour lesquelles vous disposez d'une autorisation explicite.

## Structure

```text
backend/
  app/
    config.py   Réglages lus depuis l'environnement
    api/        Routes et schémas de l'API
    domain/     Entités, règles métier et notation
    scanners/   Scanners et registre
    security/   Garde anti-SSRF et vérification DNS
    infra/      Accès PostgreSQL et clients Redis et ZAP
    workers/    Points d'entrée des jobs
  config/       Barème de notation et règles des scanners (YAML)
  migrations/   Migrations Alembic
  tests/        Tests du backend
frontend/       Interface Angular à venir
deploy/         Configuration du site et du DNS de démonstration
docs/ai/        Architecture et feuille de route
```

## Tests et lint

Prérequis : Python 3.12 ou supérieur, `uv` et Docker (pour PostgreSQL et Redis de test).

```sh
# PostgreSQL sur le port 5433 et Redis sur le port 6380, jetables
docker compose -f docker-compose.test.yml up -d --wait

cd backend
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Les tests d'intégration échouent avec un message explicite si un service est injoignable.
`TEST_DATABASE_URL` et `TEST_REDIS_URL` permettent de changer leurs adresses ; la base Redis
de test (par défaut `redis://localhost:6380/0`) est vidée avant et après chaque test qui l'utilise.
Arrêter les services, depuis la racine : `docker compose -f docker-compose.test.yml down`.

## Démonstration Docker Compose

Prérequis : Docker Compose v2 et Python 3 sur le poste hôte.

```sh
cp .env.example .env
# Renseigner JWT_SECRET (32 caractères minimum) et POSTGRES_PASSWORD dans .env.
# Utiliser un mot de passe PostgreSQL hexadécimal pour l'inclure dans DATABASE_URL.
docker compose up -d --wait
./scripts/demo.sh
docker compose down
```

Le script crée un compte unique, publie sa preuve TXT dans le volume CoreDNS,
vérifie la propriété puis affiche la note et les constats du scan HTTPS.
Il attend au maximum 360 s pour le scan (`DEMO_TIMEOUT_SECONDS` pour changer ce délai).
L'API est accessible sur http://127.0.0.1:8000/docs ; le site de démo et les services
de données ne publient aucun port. Après modification du code :
`docker compose up -d --build --wait`.

PostgreSQL, Redis (AOF), la zone DNS et les certificats persistent dans des volumes.
La CA et le certificat avec SAN `demo.scanner.test` sont générés au premier lancement ;
aucune clé ni aucun certificat n'est stocké dans le dépôt. Pour tout effacer :
`docker compose down -v` (comptes, scans et certificats compris).

Ce Compose utilise `APP_ENV=development` : seul `demo.scanner.test` peut être joint
sur une IP privée et sa CA est ajoutée au client du worker. Les autres protections
restent actives ; ces exceptions empêchent le démarrage en production et en test.
Le worker n'a pas accès à Internet : cette démo scanne uniquement le site local.
Les services de test (`docker-compose.test.yml`) forment un projet Docker séparé,
`web-vuln-scanner-test` : arrêter la démo ne touche pas aux bases de test.

## Lancer l'API en local sans Docker Compose

Il faut PostgreSQL à l'adresse de `DATABASE_URL` et Redis à celle de `REDIS_URL`.
`SCAN_TIMEOUT_SECONDS` borne la durée d'un scan (300 s par défaut, de 1 à 3600 s),
`SCAN_COOLDOWN_SECONDS` espace deux scans d'une même cible (600 s par défaut).
`backend/.env.example` vise `localhost:5432/scanner` (services à fournir séparément).
On peut réutiliser la base de test en mettant dans `backend/.env`
`DATABASE_URL=postgresql+psycopg://scanner:scanner@localhost:5433/scanner_test` ;
et `REDIS_URL=redis://localhost:6380/0` ; attention, pytest vide ces bases de test.

```sh
cd backend
cp .env.example .env          # puis remplacer JWT_SECRET (et DATABASE_URL si besoin)
uv run alembic upgrade head   # crée les tables dans la base de DATABASE_URL
uv run uvicorn app.api.main:create_app --factory --reload
```

Documentation interactive : http://127.0.0.1:8000/docs

Dans un autre terminal, depuis `backend/`, exporter `REDIS_URL` puis lancer le worker : `uv run rq worker scans --url "$REDIS_URL"`.
Ajouter `--with-scheduler` à cette commande pour activer les relances différées (10 puis 30 s).
