# Architecture

## Briques (une par conteneur Docker)

| Brique | Rôle | Techno |
| --- | --- | --- |
| Front | Saisie de l'URL, suivi du scan, affichage du rapport | Angular |
| API | Reçoit les demandes, valide, crée les jobs, sert les rapports | FastAPI |
| File de tâches | Transporte les jobs de scan vers les workers | Redis + RQ |
| Workers | Exécutent les scanners, calculent la note, enregistrent le résultat | Python |
| Base de données | Utilisateurs, cibles, scans, constats | PostgreSQL |

ZAP tourne en plus dans son propre conteneur, piloté par les workers via son API.

## Parcours d'un scan

1. Le front envoie `POST /targets` avec l'URL.
2. L'API renvoie un jeton à placer dans un enregistrement DNS TXT.
3. Le front appelle `POST /targets/{id}/verify` ; l'API vérifie le DNS.
4. Le front appelle `POST /scans`. L'API vérifie que la cible appartient à l'utilisateur, que sa propriété est prouvée et qu'aucun scan n'est actif dessus. Elle crée le scan à l'état `pending`, pousse un job (juste l'id du scan) dans Redis et répond `202 Accepted` avec l'id.
5. Un seul worker libre prend le job, passe le scan à `running` et lance chaque scanner du registre. Chaque requête sortante passe d'abord par la garde anti-SSRF.
6. Chaque scanner traduit ce qu'il voit en `Finding`. Le worker enregistre les findings, calcule la note et passe le scan à `done` (ou `failed`, avec relance si prévu).
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
| POST | `/targets/{id}/verify` | Vérifier la propriété |
| POST | `/scans` | Lancer un scan (202 Accepted) |
| GET | `/scans/{id}` | État et progression |
| GET | `/scans/{id}/report` | Rapport complet |

## Modèle de données

- `users` : id, email, mot de passe haché.
- `targets` : id, user_id, domaine, jeton de vérification, créée le, vérifiée le ;
  unicité (user_id, domaine), suppression en cascade avec le compte.
- `scans` : id, target_id, état (pending, running, done, failed), créé le, terminé le, note globale.
- `findings` : id, scan_id, scanner, catégorie, sévérité, titre, preuve, recommandation.

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
                client Redis, client ZAP
migrations/     migrations Alembic
  workers/      point d'entrée des jobs
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

## Qualité

- Tests unitaires sur la notation et chaque scanner (réponses HTTP simulées).
- Tests dédiés à la garde anti-SSRF : IP privées, redirections, rebinding.
- Logs structurés et exceptions métier dédiées.
- CI GitHub Actions : lint, tests, build des images.
