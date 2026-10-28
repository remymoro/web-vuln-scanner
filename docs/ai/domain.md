# Domaine : Finding, scanners, notation

`domain/` n'utilise que la bibliothèque standard.

## Finding

Un `Finding` est un constat : une chose précise observée sur le site. Tous les scanners renvoient ce format, quelle que soit leur origine.

| Champ | Type | Rôle | Exemple (HSTS absent) |
| --- | --- | --- | --- |
| `id` | texte | Identifiant stable de la règle | `headers.hsts` |
| `scanner` | texte | Qui a produit le constat | `headers` |
| `category` | texte | Catégorie du rapport | en-têtes HTTP |
| `severity` | info, low, medium, high | Gravité, utilisée par la notation | `medium` |
| `title` | texte | Résumé en une ligne | Protection HSTS insuffisante |
| `description` | texte | Pourquoi c'est un problème | Le navigateur peut utiliser HTTP si HSTS est absent ou trop court. |
| `evidence` | texte | Ce qui a été réellement observé | En-tête Strict-Transport-Security absent |
| `recommendation` | texte | Correction à appliquer | Ajouter Strict-Transport-Security avec un max-age d'au moins un an. |

```python
from dataclasses import dataclass
from enum import StrEnum

class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

@dataclass(frozen=True)
class Finding:
    id: str
    scanner: str
    category: str
    severity: Severity
    title: str
    description: str
    evidence: str
    recommendation: str
```

`frozen=True` rend le constat non modifiable : un constat est un fait, on ne le retouche pas après coup.

## Contrat Scanner

```python
class Scanner(Protocol):
    name: str
    category: str
    def run(self, target: Target) -> list[Finding]: ...
```

Chaque scanner expose un nom unique et une catégorie de rapport non vide. Chaque outil externe est enveloppé dans un adaptateur qui traduit sa sortie en `Finding`. Le scanner respecte son propre délai (requêtes HTTP, sous-processus, etc.) : l’orchestrateur ne l’interrompt pas individuellement. Le délai global RQ du scan reste le filet de sécurité et entraîne `failed` avec `timeout`, sans relance.

`Target` est une dataclass gelée contenant uniquement `url: str` pour le moment. Le registre est une instance explicite, conserve l’ordre d’enregistrement et refuse les noms dupliqués.

`HeadersScanner` reçoit son client HTTP par injection et ne suit pas les redirections. En production, ce client est créé par `create_safe_client()` (`security/ssrf.py`). Les règles sont dans `backend/config/header_rules.yaml`. Les constats de cookies ont les ids `headers.cookie.secure`, `headers.cookie.httponly` et `headers.cookie.samesite` ; plusieurs cookies peuvent partager un id. Leur evidence contient uniquement le nom du cookie, jamais sa valeur.

## Exécutions et rapport partiel

`ScannerRun` (`domain/scanner_run.py`) est une dataclass gelée : `scanner` (nom),
`category`, `status` (`ok` ou `error`), `error` (type d’exception ou `None`),
`findings_count`, `started_at`, `finished_at` (dates avec fuseau).

`execute_scan` isole chaque appel à `run` : une exception de cible ou un bug de
plugin donne un run `error`, sans message interne ni trace dans le rapport, puis
les scanners suivants continuent. Les constats d’un scanner en échec sont écartés.
Au moins un run `ok` donne un scan `done` ; un mélange `ok`/`error` donne
`partial: true`, calculé depuis les runs, sans nouvel état ni colonne de scan.
Tous en échec donnent `failed` avec `all scanners failed` ; aucun scanner donne
`failed` avec `no scanners configured`. Un scan totalement en échec n’est pas un
rapport partiel et son rapport reste inaccessible (409).

Les erreurs hors scanners (base, Redis, etc.) remontent pour les relances RQ.
Une tentative efface les anciens constats et runs dès le passage à `running`, puis
remplace les deux ensembles avec son résultat final dans la même transaction.
Les scans terminaux restent idempotents.

## Configuration et plugins

`backend/config/scanners.yaml` définit la liste d’autorisation, dans l’ordre
d’exécution. Elle doit être non vide, ses noms uniques et ses clés connues :

```yaml
scanners:
  - name: headers
    options:
      rules: header_rules.yaml
```

Les clés d’une entrée sont `name` et `options` (mapping facultatif, vide par défaut).
Les options spécifiques sont validées par la fabrique ; `headers` accepte seulement
`rules`, un chemin résolu depuis le dossier de configuration. `tls` accepte `rules`
(`tls_rules.yaml` par défaut), `network_timeout` (entier de 1 à 10 secondes, défaut 3)
et `network_max_retries` (entier de 0 à 2, défaut 0).
`ratelimit` accepte `rules` (`ratelimit_rules.yaml` par défaut), `max_requests`
(entier de 5 à 100, défaut 30) et `max_duration` (entier de 1 à 10 secondes,
défaut 3). Les booléens sont refusés pour ces options numériques.

Les fabriques intégrées sont dans `BUILTIN_FACTORIES` (`scanners/plugins.py`).
La découverte externe utilise exclusivement la stdlib :
`importlib.metadata.entry_points(group="web_vuln_scanner.scanners")`.
Lire ces métadonnées n’importe pas les modules : seuls les noms autorisés par le
YAML font l’objet d’un `entry_point.load()` et d’un appel de fabrique. Aucun plugin
installé mais absent du fichier n’est importé par ce chargeur.

Pour écrire un plugin, exposer une fabrique dans les métadonnées de son paquet :

```toml
[project.entry-points."web_vuln_scanner.scanners"]
example = "example_scanner:build_scanner"
```

```python
from app.scanners.plugins import ScannerContext


def build_scanner(context: ScannerContext):
    return ExampleScanner(context.client, context.options)
```

`ExampleScanner` doit déclarer `name = "example"`, une `category: str` non vide et
`run(target: Target) -> list[Finding]`. Ses constats portent le même nom de scanner
et sa catégorie. Ajouter ensuite `{name: example, options: {}}` au YAML.
Le contexte gelé fournit `client` (client anti-SSRF créé par le worker), `config_dir`
(`Path`), `options` (mapping copié, non modifiable au premier niveau), `allowed_hosts`
(`frozenset` copié) et `extra_ca_file` (`Path | None`). Les deux derniers champs sont
vides hors développement et servent aux outils qui ouvrent leurs propres connexions.
Un scanner HTTP ne crée
pas de client HTTP ; il réutilise celui du contexte et respecte ses protections.
Les valeurs imbriquées des options doivent être traitées comme de la configuration,
sans les modifier.

Un nom inconnu, un doublon d’entry points, un conflit entre intégré et plugin, une
fabrique non appelable ou un contrat invalide (nom différent, catégorie absente,
méthode `run` incompatible) arrête le démarrage du worker. Les conflits de noms
sont refusés dès la découverte des métadonnées, même si le plugin n’est pas activé.
Le point d’entrée `uv run python -m app.workers.jobs` valide ces composants avant
l’écoute RQ ; le Compose utilise aussi ce point d’entrée.

## Scanners prévus

- `HeadersScanner` : présence et valeur des en-têtes (HSTS avec max-age suffisant, CSP sans `unsafe-inline`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookies Secure/HttpOnly/SameSite). Règles lues depuis un fichier de config, comme les modèles de Nuclei.
- `TlsScanner` : intégré sous le nom `tls`, catégorie `TLS` (détails ci-dessous).
- `WafScanner` : wafw00f (bibliothèque importée) — requêtes de test inoffensives et analyse des réponses.
- `RateLimitScanner` : intégré sous le nom `ratelimit`, catégorie `Limitation de débit` (détails ci-dessous).
- `ZapPassiveScanner` (branche `feat/scanner-zap`) : scan passif ZAP uniquement (pas de scan actif par défaut).

Écartés : API hébergées (SSL Labs, Mozilla Observatory : quotas, c'est leur serveur qui scanne), testssl.sh (doublon de sslyze), Nikto (bruyant, daté). Wapiti et Nuclei : plus tard, sites vérifiés uniquement.

### Scanner TLS

Deux couches : `SslyzeProbe` (`scanners/sslyze_probe.py`, seul import de sslyze) traduit
les résultats en `TlsReport`, `TlsCertificate` et `TlsWeakCipher` gelés ;
`analyze_tls(report, rules)` est pure, avec la date d'observation dans le rapport.
`TlsScanner` résout et valide toutes les IP avant la sonde, puis scanne uniquement
la première IP validée, sur le port 443 du nom extrait de `Target.url`, même en HTTP.

`config/tls_rules.yaml` définit 13 contrôles et leurs identifiants stables `tls.*` :
SSL 2.0/3.0 (high), TLS 1.0/1.1 (medium), absence de TLS 1.3 (low), suites RC4/3DES/
NULL/EXPORT/anonymes ou clés symétriques < 128 bits (high), certificat expiré,
nom incorrect, chaîne non validée (high), expiration dans strictement moins de
30 jours (medium), Heartbleed, ROBOT (oracle faible ou fort) et CCS injection (high).
Un certificat expiré ne reçoit pas aussi le constat d'expiration prochaine.

Un constat par règle : les suites faibles sont regroupées avec leurs protocoles,
preuve limitée à 1 000 caractères ; pour les certificats multiples, le premier
déploiement fautif est cité. Le nom est contrôlé dans les SAN (joker complet sur
une étiquette, aucun repli sur CN). La validation de chaîne de sslyze inclut aussi
le nom et la date : un certificat expiré ou de mauvais nom peut donc produire
également `tls.certificate.untrusted`.

Une connexion impossible, un contrôle sslyze en erreur, l'absence de certificat ou
un résultat ROBOT indéterminé produisent `TlsProbeError`, donc un run `error`, sans
constats ni pénalité TLS. Cela évite de noter une analyse incomplète comme saine.
Le délai réseau et les relances bornent chaque connexion ; le délai global RQ
reste la limite de durée de l'ensemble du scan.

### Scanner de limitation de débit

La collecte `collect_burst` renvoie un `BurstResult` gelé (nombre de requêtes,
durée monotone et signe détecté) ; `analyze_ratelimit` est pure. La rafale envoie
des GET séquentiels vers `Target.url`, sans redirection ni lecture du corps.
Elle s'arrête au premier 429, 503 avec `Retry-After`, ou en-tête présent parmi
`RateLimit-Limit`, `RateLimit-Policy`, `RateLimit` (brouillons IETF),
`X-RateLimit-Limit`, `X-RateLimit-Remaining`, quelle que soit sa valeur.
Un signe suffit à ne produire aucun constat ; il ne prouve pas l'efficacité
de la protection. Un 503 sans `Retry-After` n'est pas un signe à lui seul.

Sans signe au terme du nombre maximal ou du budget de durée, un seul constat
`ratelimit.absent` est émis, avec nombre et durée observés. Sa gravité `low`, son
texte et sa recommandation viennent de `config/ratelimit_rules.yaml`, validé au
démarrage avec cet identifiant unique. Seule la page d'accueil (URL de la cible)
est testée : d'autres routes, méthodes, identités ou fenêtres de temps peuvent être
protégées. L'absence de signe dans cette courte rafale ne prouve pas une absence
générale de limitation. Toute erreur réseau remonte : scanner non évalué, sans pénalité.

## Notation

La notation est séparée des scanners : les scanners constatent, le moteur de notation juge.

- Chaque sévérité retire des points sur 100 (par exemple haute −25, moyenne −10, faible −3).
- Seuils couvrant tout l'intervalle : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E sinon.
- Une note par catégorie et une note globale, calculées sur les seuls scanners `ok`.
- Une catégorie évaluée sans constat vaut 100/100 et reçoit sa lettre.
- Une catégorie sans scanner réussi reste présente avec `score: null`, `grade: null`
  et aucune déduction : elle est non évaluée. Un échec ne retire aucun point.
- Si plusieurs scanners partagent une catégorie, un seul succès suffit à lui donner
  une note ; le rapport reste partiel dès qu’un autre scanner échoue.
- La note globale conserve le calcul existant : 100 moins les pénalités de tous les
  constats retenus, avec un plancher de zéro (ce n’est pas une moyenne des catégories).
- `score(findings, policy, scanner_runs)` accepte les runs sans modifier `ScoringPolicy`.
  Sans runs (anciens scans), le calcul historique depuis les constats reste disponible.
- Le barème est dans un fichier de configuration (YAML) et chaque point retiré est traçable dans le rapport.
