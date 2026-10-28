# Architecture

## Briques (une par conteneur Docker)

| Brique | Rôle | Techno |
| --- | --- | --- |
| Front | Saisie de l'URL, suivi du scan, affichage du rapport | Angular |
| API | Reçoit les demandes, valide, crée les jobs, sert les rapports | FastAPI |
| File de tâches | Transporte les jobs de scan vers les workers | Redis + RQ |
| Workers | Exécutent les scanners, calculent la note, enregistrent le résultat | Python |
| Base de données | Utilisateurs, cibles, scans, constats | PostgreSQL |

ZAP tourne en plus dans son propre conteneur, piloté par les workers via son API (branche `feat/scanner-zap`, réseau isolé : voir `security.md`).

## Parcours d'un scan

1. Le front envoie `POST /targets` avec l'URL.
2. L'API renvoie un jeton à placer dans un enregistrement DNS TXT.
3. Le front appelle `POST /targets/{id}/verify` ; l'API vérifie le DNS.
4. Le front appelle `POST /scans`. L'API vérifie que la cible appartient à l'utilisateur, que sa propriété est prouvée et qu'aucun scan n'est actif dessus. Elle crée le scan à l'état `pending`, valide la transaction, pousse un job (juste l'id du scan) dans Redis et répond `202 Accepted` avec l'id. Un index unique partiel sur `scans.target_id` pour les états `pending` et `running` garantit l'exclusion, même entre requêtes concurrentes.
5. Un seul worker libre prend le job, passe le scan à `running` et lance chaque scanner du registre. Chaque requête sortante passe d'abord par la garde anti-SSRF.
6. Chaque scanner traduit ce qu’il voit en `Finding`. Le worker isole ses exceptions et enregistre un `ScannerRun` (`ok` ou `error`, type d’exception seulement). Une tentative remplace les constats et runs précédents. Au moins un scanner réussi donne `done` ; un mélange de succès et d’échecs donne un rapport partiel, noté sur les catégories évaluées. Tous en échec (ou aucun scanner) donnent `failed`, sans relance. Une panne hors scanners autorise deux relances (10 puis 30 s, worker avec `--with-scheduler`). Le délai RQ (`SCAN_TIMEOUT_SECONDS`, 300 s par défaut) donne `failed` avec `timeout`, sans relance. Chaque démarrage incrémente `attempts`, y compris une relance depuis `running` ; `done` et `failed` sont idempotents.
7. Le front interroge `GET /scans/{id}` à intervalle régulier (bonus : Server-Sent Events) et affiche le rapport une fois `done`.

## API

| Méthode | Route | Rôle |
| --- | --- | --- |
| POST | `/auth/register`, `/auth/login` | Compte et JWT (login en JSON) |
| GET | `/auth/me` | Utilisateur du jeton |
| GET | `/health` | État de l'API et de la base (sondes) |
| POST | `/targets` | Déclarer un site, recevoir le jeton DNS |
| GET | `/targets` | Lister les cibles de l'utilisateur |
| GET | `/targets/{id}` | Consulter une de ses cibles |
| GET | `/targets/{id}/scans` | Vingt derniers scans, du plus récent au plus ancien (id décroissant à date égale), même format que `/scans/{id}` ; 404 si cible absente ou étrangère |
| POST | `/targets/{id}/verify` | Vérifier la propriété |
| POST | `/scans` | Authentifié, corps `target_id`, 202 avec id/status ; 404 cible absente ou étrangère, 409 non vérifiée ou scan actif, 429 avec `Retry-After` si un scan de la cible date de moins de `SCAN_COOLDOWN_SECONDS` (600 s), 503 file indisponible |
| GET | `/scans/{id}` | Authentifié, état, dates, note, erreur, `partial` et `scanners` ; 404 absent ou étranger |
| GET | `/scans/{id}/report` | Authentifié, note enregistrée à la fin du scan, catégories et déductions recalculées avec le barème actuel, constats, `partial` et `scanners` ; 409 avant `done`, 404 absent ou étranger |

`GET /scans/{id}`, son rapport et `GET /targets/{id}/scans` exposent tous
`partial: bool` (présence de runs `ok` et `error`) et
`scanners: [{name, category, status, error, findings_count}]`.
Le rapport contient aussi les catégories non évaluées : `score` et `grade` valent
`null`, les déductions sont vides. Une catégorie propre évaluée vaut 100/100.
Les anciens scans sans runs conservent leur détail historique issu des constats,
avec `partial: false` et une liste `scanners` vide.

## Modèle de données

- `users` : id, email, mot de passe haché, créé le.
- `targets` : id, user_id, domaine, jeton de vérification, créée le, vérifiée le ;
  unicité (user_id, domaine), suppression en cascade avec le compte.
- `scans` : id UUID, target_id (FK indexée), status, created_at, started_at, finished_at,
  score, grade, error, attempts ; index unique partiel `uq_scans_active_target`.
- `findings` : id UUID, scan_id (FK indexée), rule_id (id métier du constat, non unique),
  scanner, category, severity, title, description, evidence, recommendation.
- `scanner_runs` : id UUID, scan_id (FK indexée), scanner, category, status, error,
  findings_count, started_at, finished_at ; unicité (scan_id, scanner).
  Supprimer une cible supprime ses scans, constats et runs en cascade.
  La migration `0004_create_scanner_runs.py` crée cette table ; le repository
  remplace et relit les runs sans jamais valider la transaction.

Redis ne sert pas de stockage : il transporte les jobs, et éventuellement un cache court.

## Organisation du code (back)

```
app/
  config.py     réglages lus depuis l'environnement (pydantic-settings)
  api/          fabrique create_app, routes FastAPI, schémas Pydantic, JWT
  domain/       entités (User, Target, Scan, Finding), règles métier, notation,
                ports.py (interfaces des repositories)
  scanners/     un module par scanner + registre
  security/     garde anti-SSRF, vérification DNS
  infra/        modèles SQLAlchemy, repositories PostgreSQL, hachage argon2,
                chargeurs de configuration YAML, client Redis, client ZAP
  workers/      point d'entrée des jobs
config/         barème de notation et règles des scanners (YAML)
migrations/     migrations Alembic
tests/
```

Le domaine ne dépend ni de FastAPI ni de PostgreSQL : c'est ce qui le rend testable.
Il déclare ses besoins sous forme de ports (`Protocol`) ; `infra/` fournit les adaptateurs.
`domain/targets.py` contient `RegisteredTarget`, la normalisation des domaines et les
cas d'usage de déclaration/vérification ; `domain/ports.py` déclare `TargetRepository`
et `TxtRecordResolver`. `infra/target_repository.py` adapte le stockage PostgreSQL,
`security/dns_verification.py` adapte dnspython et `api/targets.py` expose les routes
authentifiées. La migration `0002_create_targets_table.py` crée la table `targets`.
La fabrique `create_app` accepte un `txt_resolver` injectable, conservé dans `app.state`.
Une requête HTTP correspond à une transaction : le repository ne fait jamais `commit`,
la dépendance `SessionDep` valide avant l'envoi de la réponse ou annule en cas d'erreur.

`domain/scans.py` porte la machine à états et les cas d'usage ; `domain/ports.py`
déclare `ScanRepository`, `ScanQueue` et `Scanner` (réexporté par `scanners/base.py`).
`infra/scan_repository.py`, `infra/scan_queue.py`, `workers/jobs.py` et `api/scans.py`
fournissent les adaptateurs et la composition. La migration
`0003_create_scans_and_findings.py` crée les deux tables et l'index partiel.
`create_app` accepte `scan_queue` et `scoring_policy`, conservés dans `app.state` ;
le barème du rapport est chargé une fois et le détail recalculé depuis les constats stockés.
Le worker compose moteur, sessions, client anti-SSRF et scanners configurés par processus ;
`build_worker_runtime` / `get_worker_runtime` permettent d'injecter les composants en test.
`python -m app.workers.jobs` valide la configuration et les fabriques avant de
lancer RQ avec son scheduler ; le Compose et les instructions locales utilisent ce
point d’entrée. Les noms autorisés proviennent de `config/scanners.yaml`, les
fabriques intégrées d’un dictionnaire et les plugins d’entry points stdlib. Le
contexte gelé fournit client HTTP anti-SSRF, dossier de configuration et options.
Une enveloppe dans l’adaptateur worker laisse le délai RQ traverser l’isolation
des scanners sans importer RQ dans le domaine.

`POST /scans` fait deux écritures : commit PostgreSQL puis envoi Redis. Si Redis échoue,
une compensation marque le scan `failed` (`queue unavailable`) avant le 503.
Un arrêt entre les deux écritures peut laisser un `pending` sans job : une transactional
outbox fiabiliserait cet envoi en production. Pour que la cible ne reste pas bloquée, une
nouvelle demande marque `failed` (`abandoned`) un `pending` de plus de
`SCAN_PENDING_TIMEOUT_SECONDS` (3600 s) ou un `running` de plus que le délai du scan + 60 s.

Deux scans d'une même cible sont espacés d'au moins `SCAN_COOLDOWN_SECONDS` (600 s), comptés
depuis la création du précédent. Les échecs dus à notre infrastructure (`queue unavailable`,
`abandoned`, `worker error`) ne déclenchent pas ce délai ; les échecs liés à la cible, si.

## Qualité

- Tests unitaires sur la notation et chaque scanner (réponses HTTP simulées).
- Tests dédiés à la garde anti-SSRF : IP privées, redirections, rebinding.
- Exceptions métier dédiées. Plus tard : logs structurés.
- CI GitHub Actions : `uv sync --locked`, ruff (lint et format) et pytest avec PostgreSQL et Redis 7 de service. Tests de bout en bout avec `SimpleWorker`, scanners factices et timeout réel ; aucun accès Internet. Un job séparé construit l'image Docker backend sans la publier.

## Frontend Angular

Angular 22 utilise des composants standalone, des signaux et des routes chargées
à la demande. `core/` contient les contrats API typés, l’authentification, la garde
et l’intercepteur fonctionnels ; `features/` regroupe connexion/inscription, liste
et détail des sites, suivi et rapport ; `shared/` fournit les badges et messages.
Les formulaires utilisent Signal Forms ; les lectures utilisent `httpResource`.
Le suivi recharge après 2 s, réessaie après une erreur réseau et s’arrête en état
`done`/`failed` ou à la destruction. Le rapport se charge seulement après `done`.
Les constats sont triés high → medium → low → info. Le suivi affiche le badge
« Rapport partiel » et le résultat textuel de chaque scanner (« Évalué » ou
« Non évalué : motif »). Les catégories non évaluées apparaissent sans note.

Tous les appels utilisent `/api/` : le proxy `ng serve` et nginx retirent ce préfixe.
La CI a un job frontend séparé (`npm ci`, Vitest, build), sans Playwright.
