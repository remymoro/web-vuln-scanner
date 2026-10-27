# CLAUDE.md

Scanner de vulnérabilités web (projet portfolio et d'apprentissage). Un utilisateur prouve qu'il possède son site, lance un scan, puis reçoit un rapport noté de A à E.
Document d'architecture source : https://claude.ai/artifact/GP1hjHSp4fKNqjSTHDnxJ6

## Règles de travail

- Projet d'apprentissage : avant chaque changement, expliquer en français ce qui va être fait et pourquoi, nommer le pattern utilisé, puis attendre la validation de Rémy.
- Une branche par ligne du planning ; ne jamais committer sur `main`.
- Petits commits au format Conventional Commits (`feat:`, `fix:`, `test:`, `chore:`, `docs:`).
- Écrire les tests avant ou avec le code ; une branche n'est terminée que si pytest et le lint passent.
- Ne pas ajouter de dépendance hors de la stack décidée sans le demander.
- Le dossier `domain/` n'importe jamais FastAPI, SQLAlchemy, Redis ni requests.
- Toute requête sortante vers un site cible passe par la garde anti-SSRF (`security/`).

## Stack décidée

Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2 + Alembic, PostgreSQL, Redis + RQ, httpx, sslyze, wafw00f, pytest, ruff, Angular, Docker Compose, k3s, KEDA.

## Stratégie Git

GitHub Flow : `main` protégée (CI verte obligatoire), une branche courte par fonctionnalité, fusion par pull request.

## Quoi lire selon la tâche

Ne lire que le fichier utile à la branche en cours.

| Fichier | Contenu | À lire pour |
| --- | --- | --- |
| `docs/ai/roadmap.md` | Planning des 13 branches, critères de fin, dépendances autorisées par branche | Toute nouvelle branche (commencer par là) |
| `docs/ai/architecture.md` | Briques, parcours d'un scan, API, modèle de données, arborescence du code | `chore/init`, `feat/api-base`, `feat/targets-dns`, `feat/queue-workers` |
| `docs/ai/domain.md` | `Finding`, `Severity`, contrat `Scanner`, scanners prévus, notation | `feat/domain-*`, `feat/scanner-*` |
| `docs/ai/security.md` | Preuve de propriété, anti-SSRF, limites, isolation réseau | `feat/security-ssrf`, `feat/targets-dns`, tout scanner |
| `docs/ai/deploy.md` | Docker Compose, k3s sur Proxmox, KEDA | `chore/docker-compose`, `feat/k8s*` |
