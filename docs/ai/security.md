# Sécurité de l'outil lui-même

Point le plus important : un scanner mal protégé devient une arme.

## Preuve de propriété

Aucun scan sans enregistrement DNS TXT validé (par exemple `scanner-verify=<jeton>`). Alternative : un fichier à déposer dans `/.well-known/`.

## Anti-SSRF (`security/`)

- Avant chaque requête sortante, résoudre le nom de domaine et refuser toute IP privée, locale ou réservée : `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, etc.
- Vérifier **au moment de la connexion**, pas seulement à la saisie, pour bloquer le DNS rebinding.
- Suivre les redirections une par une et revérifier chacune.
- Tests obligatoires : 127.0.0.1, 10.x, 169.254.x, ::1, redirection vers une IP privée, rebinding.

## Limites

Quota de scans par utilisateur, délai maximum par scan, un seul scan actif par cible (verrou en base).

## Isolation réseau

Les workers et ZAP sont dans un réseau Docker qui n'a pas accès à la base de données ni à l'API interne.
