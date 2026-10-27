# web-vuln-scanner

Projet portfolio et d'apprentissage : scanner les vulnérabilités d'un site dont
l'utilisateur a prouvé la propriété, puis produire un rapport noté de A à E.

> ⚠️ À utiliser uniquement sur des cibles pour lesquelles vous disposez d'une autorisation explicite.

## Structure

```text
backend/
  app/
    api/        Routes et schémas de l'API
    domain/     Entités, règles métier et notation
    scanners/   Scanners et registre
    security/   Garde anti-SSRF et vérification DNS
    infra/      Accès PostgreSQL et clients Redis et ZAP
    workers/    Points d'entrée des jobs
  tests/        Tests du backend
frontend/       Interface Angular à venir
deploy/         Configuration de déploiement à venir
docs/ai/        Architecture et feuille de route
```

## Tests et lint

Prérequis : Python 3.12 ou supérieur, `uv` et Docker (pour la base de test).

```sh
# Base PostgreSQL jetable sur le port 5433 (données en mémoire)
docker compose -f docker-compose.test.yml up -d --wait

cd backend
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Les tests qui touchent la base échouent avec un message explicite si elle n'est pas lancée.
Arrêter la base : `docker compose -f docker-compose.test.yml down`.

## Lancer l'API en local

```sh
cd backend
cp .env.example .env          # puis remplacer JWT_SECRET
uv run alembic upgrade head   # crée les tables dans la base de DATABASE_URL
uv run uvicorn app.api.main:create_app --factory --reload
```

Documentation interactive : http://127.0.0.1:8000/docs
