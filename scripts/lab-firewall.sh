#!/usr/bin/env bash
# Pare-feu du lab : le bridge br-scanner-lab (réseau `lab` de docker-compose.lab.yml,
# relié uniquement au worker et à ZAP) ne peut joindre que Juice Shop.
#
# Usage, sur Debian01 :
#   sudo scripts/lab-firewall.sh          # pose ou remet les règles (idempotent)
#   sudo scripts/lab-firewall.sh remove   # retire les règles
#   sudo scripts/lab-firewall.sh status   # affiche la chaîne
#
# Cible modifiable : LAB_TARGET_IP=10.10.10.30 LAB_TARGET_PORT=3000.
# Persistance après redémarrage : deploy/lab/README.md (unité systemd).
set -euo pipefail

BRIDGE=br-scanner-lab
CHAIN=SCANNER-LAB
TARGET_IP=${LAB_TARGET_IP:-10.10.10.30}
TARGET_PORT=${LAB_TARGET_PORT:-3000}

if [[ $EUID -ne 0 ]]; then
    echo "Lancer ce script avec sudo." >&2
    exit 1
fi

# DOCKER-USER est créée par Docker et vue par tout le trafic routé vers ou depuis
# un conteneur, avant les règles de Docker ; Docker ne la vide jamais.
if ! iptables -n -L DOCKER-USER >/dev/null 2>&1; then
    echo "Chaîne DOCKER-USER absente : démarrer Docker d'abord." >&2
    exit 1
fi

jump=(DOCKER-USER -i "$BRIDGE" -j "$CHAIN")

case "${1:-apply}" in
    apply)
        # Chaîne dédiée : la vider puis la remplir rend le script rejouable sans doublon.
        iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
        # Réponses aux connexions déjà acceptées.
        iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
        # Seule destination autorisée : Juice Shop en HTTP.
        iptables -A "$CHAIN" -p tcp -d "$TARGET_IP" --dport "$TARGET_PORT" \
            -m conntrack --ctstate NEW -j RETURN
        # Tout le reste (LAN, box, Internet, port 443 de Debian02) est refusé tout de suite :
        # REJECT plutôt que DROP pour que le scanner TLS échoue sans attendre son délai.
        iptables -A "$CHAIN" -p tcp -j REJECT --reject-with tcp-reset
        iptables -A "$CHAIN" -j REJECT --reject-with icmp-port-unreachable
        # Brancher la chaîne en tête de DOCKER-USER, une seule fois.
        iptables -C "${jump[@]}" 2>/dev/null || iptables -I "${jump[@]}"
        echo "Règles posées : $BRIDGE -> $TARGET_IP:$TARGET_PORT uniquement."
        ;;
    remove)
        while iptables -D "${jump[@]}" 2>/dev/null; do :; done
        iptables -F "$CHAIN" 2>/dev/null || true
        iptables -X "$CHAIN" 2>/dev/null || true
        echo "Règles retirées."
        ;;
    status)
        iptables -n -v -L DOCKER-USER --line-numbers
        iptables -n -v -L "$CHAIN" --line-numbers
        ;;
    *)
        echo "Usage : $0 [apply|remove|status]" >&2
        exit 1
        ;;
esac
