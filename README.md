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

Prérequis : Python 3.12 ou supérieur et `uv`.

```sh
cd backend
uv sync
uv run pytest
uv run ruff check .
```

À ce stade, aucun test n'existe : pytest affiche `no tests ran` (code de sortie 5).
