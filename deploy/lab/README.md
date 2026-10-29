# Lab Proxmox : scanner Juice Shop

Le scanner tourne sur Debian01 (10.10.10.20) avec Docker Compose. Il scanne Juice Shop,
installé sur Debian02 et servi en HTTP sur `10.10.10.30:3000`. La propriété se prouve
comme pour la démo, par un TXT publié dans `demo-dns` sous le nom `juiceshop.lab`.

Tout ce qui suit est réservé au développement (`APP_ENV=development`) : la configuration
refuse de démarrer avec `DEV_SSRF_ALLOWED_HOSTS` ou `DEV_TARGET_ORIGINS` dans un autre
environnement, et `docker-compose.yml` seul ne change pas.

## Ce que change `docker-compose.lab.yml`

| Élément | Effet |
| --- | --- |
| `DEV_SSRF_ALLOWED_HOSTS` | `juiceshop.lab` peut résoudre vers une IP RFC 1918 (10.10.10.30) |
| `DEV_TARGET_ORIGINS` | Les scanners visent `http://juiceshop.lab:3000/` au lieu de `https://juiceshop.lab/` ; le port 3000 n'est accepté que pour ce nom |
| `dns: [172.30.53.53]` + réseau `dns` | Le worker et ZAP résolvent `juiceshop.lab` par demo-dns ; les noms de conteneurs restent résolus par Docker, les autres noms sont refusés |
| Réseau `lab` (bridge `br-scanner-lab`) | Seule sortie du worker et de ZAP, filtrée par `scripts/lab-firewall.sh` |

## Lancer un scan

```bash
sudo scripts/lab-firewall.sh
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build --wait
./scripts/lab-juice.sh
```

`lab-juice.sh` vérifie d'abord que le worker et ZAP résolvent `juiceshop.lab` en
10.10.10.30 et que le worker joint le port 3000. Il crée ensuite un compte, publie le TXT
dans `/zones/juiceshop.lab.zone`, vérifie la cible, lance le scan et affiche la note,
l'état de chaque scanner et chaque catégorie. Cette zone est séparée de
`scanner.test.zone`, que `demo.sh` réécrit entièrement.

Par défaut, le compte est jetable (e-mail aléatoire, mot de passe jamais affiché). Pour
retrouver le scan dans le frontend, fournir un compte : il est créé au premier lancement,
puis réutilisé avec sa cible déjà vérifiée. Deux scans de la même cible doivent être
espacés de `SCAN_COOLDOWN_SECONDS` (10 minutes par défaut), sinon l'API répond 429.

```bash
read -rsp "Mot de passe : " LAB_PASSWORD && export LAB_PASSWORD
LAB_EMAIL=remy@scanner.test ./scripts/lab-juice.sh
```

Le frontend n'écoute que sur `127.0.0.1:4200` de Debian01. Depuis un autre poste, passer
par un tunnel SSH plutôt que d'ouvrir le port :
`ssh -N -L 4200:127.0.0.1:4200 <utilisateur>@10.10.10.20`, puis `http://localhost:4200`.

## Pare-feu (`scripts/lab-firewall.sh`)

Le réseau `lab` n'est pas interne : sans filtrage, ZAP et le worker joindraient tout le LAN
et Internet. Le script ajoute dans `DOCKER-USER` (chaîne que Docker crée et ne vide
jamais) une chaîne `SCANNER-LAB` pour le trafic entrant par `br-scanner-lab` :

1. réponses des connexions établies : acceptées ;
2. nouvelle connexion TCP vers `10.10.10.30:3000` : acceptée ;
3. tout le reste : rejeté immédiatement (`REJECT`).

`sudo scripts/lab-firewall.sh status` affiche les compteurs, `remove` retire les règles.
Le réseau Docker est en IPv4 seulement ; aucune règle `ip6tables` n'est donc nécessaire.

### Persistance après redémarrage

Les règles iptables sont perdues au redémarrage. `iptables-persistent` les sauvegarderait
avec les chaînes de Docker, qu'il recrée lui-même ; une unité systemd liée à Docker est
plus sûre. Le script est copié hors du dépôt : un `git pull` ne modifie pas ce que root
exécute sans relecture.

```bash
sudo install -m 0755 -o root -g root scripts/lab-firewall.sh /usr/local/sbin/scanner-lab-firewall
sudo install -m 0644 deploy/lab/scanner-lab-firewall.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scanner-lab-firewall.service
```

`WantedBy=docker.service` lance l'unité avec Docker, et `PartOf=docker.service` la
relance si Docker redémarre. Vérifier après un redémarrage :
`sudo scanner-lab-firewall status`. Après une modification du script, refaire la commande
`install` puis `sudo systemctl restart scanner-lab-firewall`.

## Scanner TLS et note

Juice Shop n'a pas de HTTPS. Le scanner TLS teste toujours le port 443 du nom :
le pare-feu rejette la connexion, sslyze renvoie une erreur de connectivité et le scanner
finit en `error` (`TlsProbeError`). Dans le rapport :

- `scanners` : `tls` a `status: error` et 0 constat ;
- `categories` : `TLS` a `score: null`, affichée « non évaluée » ;
- `partial: true` ;
- la note globale ne compte que les constats des scanners `ok` : l'absence de HTTPS
  n'enlève aucun point. La note est donc plus favorable que la réalité sur ce point.
