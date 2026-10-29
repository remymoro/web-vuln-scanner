#!/usr/bin/env bash
# Scan de Juice Shop (Debian02) depuis le scanner de Debian01, preuve DNS comprise.
# Prérequis : sudo scripts/lab-firewall.sh, puis
#   docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build
set -euo pipefail

if [[ ! -f docker-compose.lab.yml ]]; then
    echo "Lancer ce script depuis la racine du dépôt." >&2
    exit 1
fi

python3 - <<'PY'
import json
import os
import re
import secrets
import subprocess
import sys
import time
import uuid
import urllib.error
import urllib.request

api = "http://127.0.0.1:8000"
domain = "juiceshop.lab"
target_ip = os.environ.get("LAB_TARGET_IP", "10.10.10.30")
compose = ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.lab.yml"]
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
token = None


def request(method, path, body=None, retry_statuses=()):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(api + path, data=data, headers=headers, method=method)
    try:
        with http.open(req, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code in retry_statuses:
            return None
        raise RuntimeError(f"{method} {path} : HTTP {exc.code} : {exc.read().decode()}") from exc


def run_in(service, *command, stdin=None):
    return subprocess.run(
        [*compose, "exec", "-T", service, *command],
        input=stdin, check=True, capture_output=True, text=True, timeout=15,
    ).stdout


def check_network():
    # Le worker et ZAP doivent obtenir l'IP du lab par demo-dns, pas par le DNS de l'hôte.
    for service in ("worker", "zap"):
        answer = run_in(service, "getent", "hosts", domain).split()
        if not answer or answer[0] != target_ip:
            raise RuntimeError(f"{service} résout {domain} en {answer[:1]}, attendu {target_ip}")
        print(f"{service} : {domain} -> {answer[0]} (demo-dns)", flush=True)
    status = run_in(
        "worker", "python", "-c",
        "import urllib.request;"
        f"print(urllib.request.urlopen('http://{domain}:3000/', timeout=5).status)",
    ).strip()
    print(f"worker : http://{domain}:3000/ répond {status}", flush=True)


def publish_txt(value):
    old_zone = run_in("demo-dns", "cat", f"/zones/{domain}.zone")
    serial = (int(re.search(r"\(\s*(\d+)", old_zone).group(1)) + 1) % (2**32)
    zone = (
        f"$ORIGIN {domain}.\n$TTL 1\n"
        f"@ IN SOA ns.scanner.test. hostmaster.scanner.test. ({serial} 60 60 3600 1)\n"
        "@ IN NS ns.scanner.test.\n"
        f"@ IN A {target_ip}\n"
        f'@ IN TXT "{value}"\n'
    )
    run_in(
        "demo-dns", "/bin/sh", "-ec",
        f"cat > /zones/{domain}.zone.tmp; mv /zones/{domain}.zone.tmp /zones/{domain}.zone",
        stdin=zone,
    )


def main():
    global token
    timeout = int(os.environ.get("LAB_TIMEOUT_SECONDS", "420"))
    if not 1 <= timeout <= 3600:
        raise ValueError("LAB_TIMEOUT_SECONDS doit être compris entre 1 et 3600")
    check_network()
    credentials = {
        "email": f"lab-{uuid.uuid4().hex}@scanner.test",
        "password": secrets.token_urlsafe(32),
    }
    request("POST", "/auth/register", credentials)
    token = request("POST", "/auth/login", credentials)["access_token"]
    target = request("POST", "/targets", {"url": domain})
    print(f"Compte créé ; cible déclarée : {target['domain']}", flush=True)

    value = target["dns_record"]["value"]
    if re.fullmatch(r"scanner-verify=[A-Za-z0-9_-]+", value) is None:
        raise ValueError("Jeton DNS inattendu")
    publish_txt(value)
    deadline = time.monotonic() + 30
    while True:
        verified = request("POST", f"/targets/{target['id']}/verify", retry_statuses=(400, 503))
        if verified is not None and verified["verified"]:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError("Le TXT n'a pas été pris en compte dans les 30 secondes")
        time.sleep(1)
    print("Propriété vérifiée par DNS ; lancement du scan.", flush=True)

    scan = request("POST", "/scans", {"target_id": target["id"]})
    deadline = time.monotonic() + timeout
    while True:
        state = request("GET", f"/scans/{scan['id']}")
        if state["status"] == "done":
            break
        if state["status"] == "failed":
            raise RuntimeError(f"Scan échoué : {state['error']}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Scan non terminé après {timeout} secondes")
        time.sleep(2)
    report = request("GET", f"/scans/{scan['id']}/report")
    partial = " (rapport partiel)" if report["partial"] else ""
    print(f"Note : {report['grade']} — {report['score']}/100{partial}")
    for scanner in report["scanners"]:
        detail = f"erreur {scanner['error']}" if scanner["status"] == "error" else "ok"
        print(f"  scanner {scanner['name']} : {detail}, {scanner['findings_count']} constat(s)")
    for category in report["categories"]:
        note = "non évaluée" if category["score"] is None else f"{category['score']}/100"
        print(f"  catégorie {category['category']} : {note}")
    for finding in report["findings"]:
        print(f"- [{finding['severity']}] {finding['title']}")
        print(f"  {finding['evidence']}")


try:
    main()
except Exception as exc:
    print(f"Scan du lab interrompu : {exc}", file=sys.stderr)
    sys.exit(1)
PY
