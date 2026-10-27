# Sécurité de l'outil lui-même

Point le plus important : un scanner mal protégé devient une arme.

## Preuve de propriété

Aucun scan sans enregistrement DNS TXT validé. Chaque cible reçoit un jeton propre,
à publier sous la forme exacte `scanner-verify=<jeton>` sur le nom d'hôte déclaré
(normalisé en minuscules et IDNA, sans point final). Prouver `example.com` n'autorise
pas `www.example.com` : chaque nom doit être déclaré et vérifié séparément.

Les fragments d'un même TXT sont concaténés, puis décodés en UTF-8. Après suppression
des espaces aux extrémités (`strip()`), la valeur complète est comparée strictement,
en temps constant (`hmac.compare_digest`) : aucun préfixe, suffixe ou changement de
casse n'est accepté. Une cible déjà vérifiée conserve sa date sans nouvelle requête
DNS. `RegisteredTarget.scan_target()` refuse toute cible non vérifiée ; les routes
masquent les cibles des autres utilisateurs avec un 404.

## Anti-SSRF (`security/`)

- Seuls les schémas `http` et `https` et les ports 80/443 sont autorisés ; les URL avec userinfo (`user:pass@`) sont refusées.
- Résoudre le nom de domaine et refuser toute IP non globale, privée, locale, réservée, multicast ou non spécifiée : `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `::1`, etc. Si une seule IP résolue est interdite, refuser toute la destination. Une résolution impossible ou vide est également refusée.
- Démasquer les IPv4 encapsulées dans IPv6 : IPv4 mapped, 6to4, Teredo (serveur et client), NAT64 `64:ff9b::/96` ; vérifier aussi les IPv4 intérieures.
- Vérifier **au moment de la connexion** avec `GuardedNetworkBackend`, pour bloquer le DNS rebinding : résoudre à nouveau, valider toutes les adresses, puis connecter le backend à une IP validée, jamais au nom d'hôte. Le nom d'origine reste utilisé pour TLS (SNI et vérification du certificat). Les sockets Unix sont refusées.
- Quand résoudre : `safe_get()` contrôle l'URL et résout le nom avant chaque requête ; un appel direct `client.get()` contrôle l'URL à chaque requête et résout le nom à chaque **nouvelle connexion TCP**. Une connexion réutilisée (keep-alive) reste reliée à une IP déjà validée.
- `create_safe_client()` est le **seul** moyen de créer un client HTTP (httpx) vers une cible : vérification TLS activée, aucun proxy, `trust_env=False` pour ignorer notamment `HTTP_PROXY` et `HTTPS_PROXY`, redirections automatiques désactivées.
- Utiliser `safe_get` pour suivre les redirections une par une (cinq au maximum par défaut), revérifier chaque destination avant la requête et fermer chaque réponse intermédiaire. La garde à la connexion reste active en complément du contrôle d'URL.
- Tests obligatoires sans réseau ni DNS réels : 127.0.0.1, 10.x, 169.254.x, ::1, redirection vers une IP privée, rebinding.

### Outils qui ouvrent leurs propres connexions (sslyze, wafw00f, ZAP)

Ces outils ne peuvent pas utiliser `create_safe_client()`. Appeler `check_url()` juste avant ne suffit pas : l'outil refait sa propre résolution DNS, ce qui rouvre le DNS rebinding. Chaque adaptateur doit donc :

- résoudre la cible avec `resolve_and_check()` et donner à l'outil l'IP validée quand il le permet, en gardant le nom d'origine pour TLS ;
- s'exécuter dans le réseau isolé décrit plus bas, qui bloque les plages privées même si l'outil se trompe ;
- pour ZAP en plus : limiter l'exploration au domaine vérifié et n'utiliser que le scan passif.

## Limites

- `feat/queue-workers` : un seul scan actif par cible (verrou en base) et délai maximum par scan (le scan passe à `failed` au-delà).
- Plus tard : quota de scans par utilisateur, limite d'appels à `POST /targets/{id}/verify` (chaque appel déclenche une requête DNS), preuve de propriété alternative par fichier dans `/.well-known/`.

## Isolation réseau

- Les workers accèdent à PostgreSQL (états, constats, notes) et à Redis (file), jamais à l'API.
- Le trafic vers les cibles (workers vers Internet, conteneur ZAP) sort par un réseau qui bloque les plages privées et réservées.
- ZAP n'a accès ni à PostgreSQL, ni à Redis, ni à l'API : seuls les workers le pilotent.
