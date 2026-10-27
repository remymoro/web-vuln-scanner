# Domaine : Finding, scanners, notation

`domain/` n'utilise que la bibliothèque standard.

## Finding

Un `Finding` est un constat : une chose précise observée sur le site. Tous les scanners renvoient ce format, quelle que soit leur origine.

| Champ | Type | Rôle | Exemple (HSTS absent) |
| --- | --- | --- | --- |
| `id` | texte | Identifiant stable de la règle | `headers.hsts.missing` |
| `scanner` | texte | Qui a produit le constat | `headers` |
| `category` | texte | Catégorie du rapport | en-têtes HTTP |
| `severity` | info, low, medium, high | Gravité, utilisée par la notation | `medium` |
| `title` | texte | Résumé en une ligne | En-tête HSTS absent |
| `description` | texte | Pourquoi c'est un problème | Le navigateur peut être forcé en HTTP |
| `evidence` | texte | Ce qui a été réellement observé | Aucun en-tête Strict-Transport-Security dans la réponse |
| `recommendation` | texte | Correction à appliquer | Ajouter HSTS avec un max-age d'au moins un an |

```python
from dataclasses import dataclass
from enum import Enum

class Severity(str, Enum):
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
    def run(self, target: Target) -> list[Finding]: ...
```

Ajouter un scanner = écrire une classe et l'enregistrer dans le registre. Rien d'autre ne change. Chaque outil externe est enveloppé dans un adaptateur qui traduit sa sortie en `Finding`.

## Scanners prévus

- `HeadersScanner` : présence et valeur des en-têtes (HSTS avec max-age suffisant, CSP sans `unsafe-inline`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookies Secure/HttpOnly/SameSite). Règles lues depuis un fichier de config, comme les modèles de Nuclei.
- `TlsScanner` : sslyze (bibliothèque importée) — versions de protocole, suites de chiffrement, certificat.
- `WafScanner` : wafw00f (bibliothèque importée) — requêtes de test inoffensives et analyse des réponses.
- `RateLimitScanner` : code maison, rafale contrôlée et limitée, détection des réponses 429.
- `ZapPassiveScanner` : scan passif ZAP uniquement (pas de scan actif par défaut).

Écartés : API hébergées (SSL Labs, Mozilla Observatory : quotas, c'est leur serveur qui scanne), testssl.sh (doublon de sslyze), Nikto (bruyant, daté). Wapiti et Nuclei : plus tard, sites vérifiés uniquement.

## Notation

La notation est séparée des scanners : les scanners constatent, le moteur de notation juge.

- Chaque sévérité retire des points sur 100 (par exemple haute −25, moyenne −10, faible −3).
- Seuils couvrant tout l'intervalle : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E sinon.
- Une note par catégorie et une note globale.
- Le barème est dans un fichier de configuration (YAML) et chaque point retiré est traçable dans le rapport.
