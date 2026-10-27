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

### Exceptions de démonstration (développement uniquement)

`APP_ENV` vaut `production` par défaut (`development`, `test`, `production` acceptés).
La configuration refuse de démarrer avec `DEV_SSRF_ALLOWED_HOSTS` non vide ou
`DEV_EXTRA_CA_FILE` renseigné si `APP_ENV` n'est pas `development`. Le worker
valide les réglages avant de lancer RQ et sa fabrique ne transmet ces exceptions
qu'en développement. Aucune exception n'est activée par défaut.

- `DEV_SSRF_ALLOWED_HOSTS` est une liste JSON de noms exacts en minuscules ASCII,
  sans joker, URL ni point final. Pour ces seuls noms, la garde autorise les plages
  RFC 1918 et `fc00::/7`. Loopback, link-local (dont `169.254.169.254`), multicast,
  adresses réservées, non spécifiées et autres plages non publiques restent bloqués,
  ainsi que les IPv4 privées encapsulées en IPv6. Toute réponse DNS contenant une
  adresse interdite fait échouer la destination entière. La liste s'applique à
  chaque contrôle de `safe_get` et à chaque connexion TCP : une redirection vers
  un autre nom privé reste bloquée, comme le rebinding vers une adresse interdite.
- `DEV_EXTRA_CA_FILE` ajoute la CA locale au contexte TLS existant : autorités
  habituelles conservées, certificat et nom vérifiés, SNI d'origine conservé,
  aucun proxy ni réglage TLS lu dans l'environnement. Le worker ne reçoit que
  le certificat public de CA ; les clés restent dans les volumes du générateur
  et du serveur de démonstration.
- Le résolveur TXT de la démo est CoreDNS dans un réseau interne, sans DNS public.
  `DNS_NAMESERVERS` (liste JSON d'IP ou absent) choisit les résolveurs dnspython ;
  c'est un réglage DNS autorisé dans tous les environnements, pas une exception
  anti-SSRF. Il ne change pas la résolution à la connexion du client HTTP.

La preuve de propriété reste obligatoire. Aucun outil externe ne bénéficie de
ces exceptions : il devra respecter les règles d'épinglage et d'isolation ci-dessus.

## Limites

- `feat/queue-workers` : un seul scan actif par cible (verrou en base) et délai maximum par scan (le scan passe à `failed` au-delà).
- Plus tard : quota de scans par utilisateur, limite d'appels à `POST /targets/{id}/verify` (chaque appel déclenche une requête DNS), preuve de propriété alternative par fichier dans `/.well-known/`.

## Isolation réseau

- Les workers accèdent à PostgreSQL (états, constats, notes) et à Redis (file), jamais à l'API.
- Le trafic vers les cibles (workers vers Internet, conteneur ZAP) sort par un réseau qui bloque les plages privées et réservées.
- ZAP n'a accès ni à PostgreSQL, ni à Redis, ni à l'API : seuls les workers le pilotent.

Le Compose de démo sépare API et worker sur deux réseaux de données internes,
avec PostgreSQL et Redis sur les deux. Un réseau interne supplémentaire relie
uniquement worker et site de démo ; un autre relie uniquement API et CoreDNS.
Seule l'API publie un port, sur la boucle locale de l'hôte, via le seul réseau non
interne (`edge`), qu'elle ne partage avec aucun autre service. Le worker n'a aucun
accès à Internet. Le filtrage de sortie des futurs outils externes reste
à implémenter avant leur activation.
