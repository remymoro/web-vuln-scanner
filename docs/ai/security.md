# Sécurité de l'outil lui-même

Point le plus important : un scanner mal protégé devient une arme.

## Preuve de propriété

Aucun scan sans enregistrement DNS TXT validé (par exemple `scanner-verify=<jeton>`). Alternative : un fichier à déposer dans `/.well-known/`.

## Anti-SSRF (`security/`)

- Seuls les schémas `http` et `https` et les ports 80/443 sont autorisés ; les URL avec userinfo (`user:pass@`) sont refusées.
- Avant chaque requête sortante, résoudre le nom de domaine et refuser toute IP non globale, privée, locale, réservée, multicast ou non spécifiée : `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `::1`, etc. Si une seule IP résolue est interdite, refuser toute la destination. Une résolution impossible ou vide est également refusée.
- Démasquer les IPv4 encapsulées dans IPv6 : IPv4 mapped, 6to4, Teredo (serveur et client), NAT64 `64:ff9b::/96` ; vérifier aussi les IPv4 intérieures.
- Vérifier **au moment de la connexion** avec `GuardedNetworkBackend`, pour bloquer le DNS rebinding : résoudre à nouveau, valider toutes les adresses, puis connecter le backend à une IP validée, jamais au nom d'hôte. Le nom d'origine reste utilisé pour TLS (SNI et vérification du certificat). Les sockets Unix sont refusées.
- `create_safe_client()` est le **seul** moyen de créer un client vers une cible : vérification TLS activée, aucun proxy, `trust_env=False` pour ignorer notamment `HTTP_PROXY` et `HTTPS_PROXY`, redirections automatiques désactivées.
- Utiliser `safe_get` pour suivre les redirections une par une (cinq au maximum par défaut), revérifier chaque destination avant la requête et fermer chaque réponse intermédiaire. La garde à la connexion reste active en complément du contrôle d'URL.
- Tests obligatoires sans réseau ni DNS réels : 127.0.0.1, 10.x, 169.254.x, ::1, redirection vers une IP privée, rebinding.

## Limites

Quota de scans par utilisateur, délai maximum par scan, un seul scan actif par cible (verrou en base).

## Isolation réseau

Les workers et ZAP sont dans un réseau Docker qui n'a pas accès à la base de données ni à l'API interne.
