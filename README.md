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
deploy/         Configuration de déploiement à venir
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

## Lancer l'API en local

Il faut PostgreSQL à l'adresse de `DATABASE_URL` et Redis à celle de `REDIS_URL`.
`SCAN_TIMEOUT_SECONDS` borne la durée d'un scan (300 s par défaut, de 1 à 3600 s),
`SCAN_COOLDOWN_SECONDS` espace deux scans d'une même cible (600 s par défaut).
`.env.example` vise
`localhost:5432/scanner`, que fournira le Docker Compose de la branche `chore/docker-compose`.
En attendant, on peut réutiliser la base de test en mettant dans `.env`
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
