# Roadmap : branches, critères de fin, dépendances

Une branche à la fois, dans l'ordre. Une branche est terminée quand son critère est rempli **et** que pytest et ruff passent.

## Planning des branches

| # | Branche | Contenu | Terminé quand |
| --- | --- | --- | --- |
| 1 | `chore/init` | Arborescence `backend/`, `frontend/`, `deploy/` ; `pyproject.toml` ; README | pytest s'exécute (zéro test) et ruff passe |
| 2 | `chore/ci` | Workflow GitHub Actions : ruff + pytest sur chaque PR | La CI tourne sur une PR de test |
| 3 | `feat/domain-finding` | `Severity`, `Finding` (dataclass gelée), voir `domain.md` | Tests de création et d'immutabilité |
| 4 | `feat/domain-scoring` | Barème sur 100 lu depuis la config, seuils A à E, note par catégorie et globale | Chaque score de 0 à 100 donne une lettre ; détail des points retirés |
| 5 | `feat/scanner-headers` | Contrat `Scanner`, registre, `HeadersScanner` avec règles en config (présence et valeur) | Tests avec réponses HTTP simulées, aucun appel réseau réel |
| 6 | `feat/security-ssrf` | Résolution DNS, refus des IP privées et réservées, contrôle à la connexion, redirections revérifiées | Tests : 127.0.0.1, 10.x, 169.254.x, ::1, redirection vers IP privée |
| 7 | `feat/api-base` | FastAPI, modèles SQLAlchemy, migrations Alembic, repositories, auth JWT | Tests d'API avec base de test |
| 8 | `feat/targets-dns` | `POST /targets`, jeton, `POST /targets/{id}/verify` par enregistrement TXT | Une cible non vérifiée ne peut pas être scannée |
| 9 | `feat/queue-workers` | `POST /scans` (202), job RQ, worker, états pending/running/done/failed, verrou une cible = un scan actif, relances, délai maximum par scan | Test de bout en bout avec Redis de test ; un scan qui dépasse le délai passe à `failed` |
| 10 | `chore/docker-compose` | Dockerfiles API et worker, compose avec PostgreSQL, Redis (persistance activée), site cible de démo mal configuré | `docker compose up` puis un scan complet de la démo |
| 11 | `feat/frontend` | Angular : déclaration de cible, vérification, suivi, rapport | Parcours complet dans le navigateur |
| 12 | `feat/scanner-plugins`, `feat/scanner-tls`, `feat/scanner-waf`, `feat/scanner-ratelimit`, `feat/scanner-zap` | Plugins configurables, exécutions isolées et rapports partiels ; adaptateurs sslyze et wafw00f, rate-limit maison, ZAP en scan passif (conteneur, exploration limitée au domaine vérifié, réseau isolé : voir `security.md`) | Plugins autorisés uniquement par configuration ; un scanner en échec laisse un rapport partiel ; chacun renvoie des `Finding` testés ; ZAP ne joint ni la base, ni Redis, ni les plages privées |
| 13 | `feat/k8s`, puis `feat/k8s-keda` | Manifestes dans `deploy/k8s` (Deployments, Services, Secrets), puis ScaledObject KEDA sur la file Redis | Déploiement sur k3s ; les workers montent et descendent selon la file |

## Dépendances autorisées par branche

Chaque branche n'ajoute que ce dont elle a besoin. Les contraintes de version sont déclarées dans `backend/pyproject.toml` ; les versions exactes sont verrouillées dans `backend/uv.lock`, vérifié par `uv sync --locked` en CI.

| Branche | Bibliothèques | À quoi elles servent |
| --- | --- | --- |
| `chore/init` | pytest, ruff | Lancer les tests ; vérifier style et erreurs courantes |
| `feat/domain-finding` | aucune | Le domaine n'utilise que la bibliothèque standard |
| `feat/domain-scoring` | PyYAML | Lire le barème depuis un fichier de config |
| `feat/scanner-headers` | httpx, respx | Faire les requêtes HTTP ; les simuler dans les tests |
| `feat/security-ssrf` | httpcore (déjà installé par httpx, déclaré car utilisé directement) ; `ipaddress` et `socket` de la bibliothèque standard | Injecter le backend réseau qui valide et épingle l'IP à la connexion ; classer les IP et résoudre les noms |
| `feat/api-base` | fastapi, uvicorn, pydantic-settings, sqlalchemy, alembic, psycopg, PyJWT, argon2-cffi | API, serveur, configuration, base, migrations, pilote PostgreSQL, jetons, hachage des mots de passe |
| `feat/targets-dns` | dnspython | Lire l'enregistrement TXT de preuve de propriété |
| `feat/queue-workers` | redis, rq | Parler à Redis ; gérer la file et les workers |
| `feat/scanner-plugins` | aucune ; `importlib.metadata` | Découvrir les fabriques des plugins installés, sans importer ceux absents de la liste d’autorisation |
| `feat/scanner-tls` | sslyze | Analyser la configuration TLS |
| `feat/scanner-waf` | wafw00f | Détecter le WAF |
| `feat/scanner-ratelimit` | aucune (httpx déjà présent) | Envoyer une rafale contrôlée |
| `feat/scanner-zap` | aucune en Python (API REST de ZAP via httpx) ; image Docker officielle de ZAP | Piloter ZAP en scan passif |
| `feat/frontend` | Angular CLI (côté Node) | Créer et construire le front |
| `feat/k8s` | aucune (manifestes YAML) | Déployer sur k3s |
| `feat/k8s-keda` | KEDA (dans le cluster, pas en Python) | Scaler les workers selon la file Redis |

Pour les tests d'intégration (branches 7 et 9), une base PostgreSQL et un Redis de test sont lancés via Docker.
