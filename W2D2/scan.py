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

def parse_sections(output, display_levels):
    section_pattern = re.compile(r'^(.+?)\n=+\n', re.MULTILINE)
    sections = []
    matches = list(section_pattern.finditer(output))

    for i, match in enumerate(matches):
        raw_header = match.group(1).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(output)
        block = output[start:end]

        header_match = re.match(r'^.+?\((.+?)\)$', raw_header)
        header = header_match.group(1).strip() if header_match else raw_header

        counts = {lvl: 0 for lvl in VALID_LEVELS}
        total_match = re.search(r'Total:\s*\d+\s*\((.+?)\)', block)
        if total_match:
            for m in re.finditer(r'(\w+):\s*(\d+)', total_match.group(1)):
                lvl = m.group(1).lower()
                if lvl in counts:
                    counts[lvl] = int(m.group(2))

        packages = {lvl: [] for lvl in VALID_LEVELS}
        for row in re.finditer(r'│\s*(\S+)\s*│\s*\S+\s*│\s*(\w+)\s*│', block):
            pkg = row.group(1).strip()
            severity = row.group(2).strip().lower()
            if severity in packages:
                packages[severity].append(pkg)

        if any(counts[lvl] > 0 for lvl in display_levels):
            sections.append({"header": header, "counts": counts, "packages": packages})

    return sections


def format_discord_message(image, project, sections, display_levels):
    lines = [
        f"> SCAN REPORT: {project}",
        "> -------------------------",
        f"> Docker Image: {image}",
        "> Vuln(s) found:",
    ]
    for section in sections:
        lines.append(f"> {section['header']}")
        for level in display_levels:
            count = section["counts"].get(level, 0)
            if count == 0:
                continue
            lines.append(f"> {level}: {count}")
            for pkg in section["packages"].get(level, []):
                lines.append(f"> -  {pkg}")
    lines.append("> -------------------------")
    return "\n".join(lines)

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

    display_levels = sorted(levels, key=lambda l: VALID_LEVELS.index(l)) if levels is not None else VALID_LEVELS
    result = ""
    for level in display_levels:
        result += f"{level}: {counts[level]}\n"
   
    print(f"SCAN REPORT: {project}")
    print("-------------------------")
    print(result)

    sections = parse_sections(output, display_levels)
    message = format_discord_message(image, project, sections, display_levels)
    send_discord_notification(webhook_url or DISCORD_WEBHOOK_URL, message)
   
   # send_discord_notification(DISCORD_WEBHOOK_URL, result)

if __name__ == "__main__":
    main()