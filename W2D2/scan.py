import sys
import subprocess
import re
import urllib.request
import urllib.error
import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
import os

load_dotenv()

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

#Titrage des niveaux de vulnérabilité valides
VALID_LEVELS = ["critical", "high", "medium", "low", "unknown"]


SEVERITY_COLORS = {
    "critical": 0xE74C3C,
    "high":     0xE67E22,
    "medium":   0xF1C40F,
    "low":      0x2ECC71,
    "unknown":  0x95A5A6,
}


def parse_args():
    image = None
    levels = None
    webhook_url = None
    project = "default unset project"

    for arg in sys.argv[1:]:
        if arg.startswith("--image="):
            image = arg[len("--image="):]
        elif arg == "--image":
            image = ""
        elif arg.startswith("--level="):
            levels = arg[len("--level="):]
        elif arg.startswith("--discord-webhook="):
            webhook_url = arg[len("--discord-webhook="):]
        elif arg.startswith("--project="):
            project = arg[len("--project="):]

    if image is None or image == "":
        print("Erreur : image est obligatoire")
        print("Usage : python scan.py --image=<nom_de_l_image> [--level=critical,high,...]")
        sys.exit(1)

    if levels is not None:
        levels = [l.strip().lower() for l in levels.split(",")]
        for l in levels:
            if l not in VALID_LEVELS:
                print(f"error: {l} is not a CVE valid level")
                sys.exit(1)
    
    return image, levels, webhook_url, project


def run_trivy(image):
    try:
        result = subprocess.run(
            ["trivy", "image", image],
            capture_output=True,
            text=True
        )
        return result.stdout + result.stderr
    except FileNotFoundError:
        print("Erreur : la commande 'trivy' est introuvable. Vérifiez qu'elle est installée et dans votre PATH.")
        sys.exit(1)


def parse_vulnerabilities(output):
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    summary_match = re.search(r"Total:\s*\d+\s*\((.+?)\)", output)
    if summary_match:
        summary = summary_match.group(1)
        for match in re.finditer(r"(\w+):\s*(\d+)", summary):
            level = match.group(1).lower()
            count = int(match.group(2))
            if level in counts:
                counts[level] = count

    return counts

def send_discord_notification(webhook_url, message):

     # payload = build_discord_embed(image, counts, display_levels)
    data = json.dumps({"content": message}).encode("utf-8")

    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "scan.py"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status in (200, 204):
                print("✅ Notification Discord envoyée avec succès.")
            else:
                print(f"⚠️  Discord a répondu avec le statut {response.status}.")
    except urllib.error.HTTPError as e:
        print(f"⚠️  Erreur HTTP Discord : {e.code} – {e.reason}")
    except urllib.error.URLError as e:
        print(f"⚠️  Impossible de joindre le webhook Discord : {e.reason}")


def main():
    image, levels, webhook_url, project = parse_args()

    output = run_trivy(image)
    counts = parse_vulnerabilities(output)

    display_levels = levels if levels is not None else VALID_LEVELS

    result = ""
    for level in display_levels:
        result += f"{level}: {counts[level]}\n"
   
    print(f"SCAN REPORT: {project}")
    print("-------------------------")
    print(result)

    
   # send_discord_notification(DISCORD_WEBHOOK_URL, result)


if __name__ == "__main__":
    main()