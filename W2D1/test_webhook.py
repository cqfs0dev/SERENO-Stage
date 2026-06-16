import urllib.request
import json

WEBHOOK = " Test Webhook URL" # Metre URL Webhook Discord pour les tests (Secret)
payload = {
    "content": "confirmation de Test"
}

data = json.dumps(payload).encode("utf-8")
req = urllib.request.Request(
    WEBHOOK,
    data=data,
    headers={
        "Content-Type": "application/json",
        "User-Agent": "scan.py"
    }, 
    method="POST",
)

try:
    with urllib.request.urlopen(req, timeout=10) as r:
        print(f"Statut : {r.status}")
        print("OK Message envoye sur Discord !")
except Exception as e:
    print(f"Erreur : {e}")