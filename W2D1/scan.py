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

    for arg in sys.argv[1:]:
        if arg.startswith("--image="):
            image = arg[len("--image="):]
        elif arg == "--image":
            image = ""
        elif arg.startswith("--level="):
            levels = arg[len("--level="):]
        elif arg.startswith("--discord-webhook="):
            webhook_url = arg[len("--discord-webhook="):]

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

    return image, levels, webhook_url


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


def build_discord_embed(image, counts, display_levels):
    embed_color = 0x2ECC71
    for level in ["critical", "high", "medium", "low", "unknown"]:
        if level in display_levels and counts.get(level, 0) > 0:
            embed_color = SEVERITY_COLORS[level]
            break

    level_emojis = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🟢",
        "unknown":  "⚪",
    }

    fields = [
        {
            "name": f"{level_emojis.get(level, '')} {level.upper()}",
            "value": str(counts.get(level, 0)),
            "inline": True,
        }
        for level in display_levels
    ]

    total = sum(counts.get(l, 0) for l in display_levels)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "username": "Trivy Scanner",
        "embeds": [
            {
                "title": "🔍 Scan Trivy terminé",
                "description": f"**Image :** `{image}`\n**Total vulnérabilités :** {total}",
                "color": embed_color,
                "fields": fields,
                "footer": {"text": "Trivy Security Scanner"},
                "timestamp": timestamp,
            }
        ],
    }
    return payload


def send_discord_notification(webhook_url, image, counts, display_levels):

    payload = build_discord_embed(image, counts, display_levels)
    data = json.dumps({"content": "hello from scan"}).encode("utf-8")

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
    image, levels, webhook_url = parse_args()
    output = run_trivy(image)
    counts = parse_vulnerabilities(output)

    display_levels = levels if levels is not None else VALID_LEVELS

    result = " ".join(f"{level}: {counts[level]}" for level in display_levels)
    print(result)

    
    send_discord_notification(DISCORD_WEBHOOK_URL, image, counts, display_levels)


if __name__ == "__main__":
    main()