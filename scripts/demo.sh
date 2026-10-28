#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f docker-compose.yml ]]; then
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
# Note mesurée sur la pile Docker avec les 5 scanners : E, 12/100.
DEFAULT_EXPECTED_GRADE = "E"
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


def main():
    global token
    timeout = int(os.environ.get("DEMO_TIMEOUT_SECONDS", "420"))
    if not 1 <= timeout <= 3600:
        raise ValueError("DEMO_TIMEOUT_SECONDS doit être compris entre 1 et 3600")
    # Facultatif : DEMO_EXPECTED_GRADE=E ./scripts/demo.sh (par défaut DEFAULT_EXPECTED_GRADE).
    expected_grade = os.environ.get("DEMO_EXPECTED_GRADE", "")
    if expected_grade and expected_grade not in ("A", "B", "C", "D", "E"):
        raise ValueError("DEMO_EXPECTED_GRADE doit être une lettre de A à E")
    credentials = {
        "email": f"demo-{uuid.uuid4().hex}@scanner.test",
        "password": secrets.token_urlsafe(32),
    }
    request("POST", "/auth/register", credentials)
    token = request("POST", "/auth/login", credentials)["access_token"]
    target = request("POST", "/targets", {"url": "demo.scanner.test"})
    print(f"Compte créé ; cible déclarée : {target['domain']}", flush=True)

    compose = ["docker", "compose", "exec", "-T", "demo-dns"]
    old_zone = subprocess.run(
        [*compose, "cat", "/zones/scanner.test.zone"],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout
    previous_serial = int(re.search(r"\(\s*(\d+)", old_zone).group(1))
    serial = (previous_serial + 1) % (2**32)
    value = target["dns_record"]["value"]
    if re.fullmatch(r"scanner-verify=[A-Za-z0-9_-]+", value) is None:
        raise ValueError("Jeton DNS inattendu")
    zone = (
        "$ORIGIN scanner.test.\n$TTL 1\n"
        f"@ IN SOA ns.scanner.test. hostmaster.scanner.test. ({serial} 60 60 3600 1)\n"
        "@ IN NS ns.scanner.test.\nns IN A 172.30.53.53\n"
        f'demo IN TXT "{value}"\n'
    )
    subprocess.run(
        [*compose, "/bin/sh", "-ec",
         "cat > /zones/scanner.test.zone.tmp; mv /zones/scanner.test.zone.tmp /zones/scanner.test.zone"],
        input=zone, text=True, check=True, timeout=15,
    )
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
        time.sleep(1)
    report = request("GET", f"/scans/{scan['id']}/report")
    print(f"Note : {report['grade']} — {report['score']}/100")
    if expected_grade and report["grade"] != expected_grade:
        raise AssertionError(f"Note attendue : {expected_grade}, reçue : {report['grade']}")
    for finding in report["findings"]:
        print(f"- [{finding['severity']}] {finding['title']}")
        print(f"  {finding['evidence']}")


try:
    main()
except Exception as exc:
    print(f"Démo interrompue : {exc}", file=sys.stderr)
    sys.exit(1)
PY
