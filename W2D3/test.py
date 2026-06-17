import sys
import subprocess
import re
import urllib.request
import urllib.error
import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv

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

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "unknown":  "⚪",
}


def parse_args():
    images = []
    levels = None
    webhook_url = None
    project = "default unset project"

    for arg in sys.argv[1:]:
        if arg.startswith("--image="):
            images.append(arg[len("--image="):])
        elif arg.startswith("--level="):
            levels = arg[len("--level="):]
        elif arg.startswith("--discord-webhook="):
            webhook_url = arg[len("--discord-webhook="):]
        elif arg.startswith("--project="):
            project = arg[len("--project="):]

    if not images:
        print("Erreur : au moins une image est obligatoire")
        print("Usage : python scan.py --image=<image1> [--image=<image2>] [--level=critical,high,...] [--project=<name>]")
        sys.exit(1)

    if levels is not None:
        levels = [l.strip().lower() for l in levels.split(",")]
        for l in levels:
            if l not in VALID_LEVELS:
                print(f"error: {l} is not a valid CVE level")
                sys.exit(1)

    return images, levels, webhook_url, project


def run_trivy(image):
    try:
        result = subprocess.run(
            ["trivy", "image", image],
            capture_output=True,
            text=True,
        )
        return result.stdout + result.stderr
    except FileNotFoundError:
        print("Erreur : 'trivy' est introuvable. Vérifiez qu'il est installé et dans votre PATH.")
        sys.exit(1)


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
        for row in re.finditer(r'│\s*(\S+)\s*│\s*(\S+)\s*│\s*(\w+)\s*│', block):
            pkg = row.group(1).strip()
            cve = row.group(2).strip()
            severity = row.group(3).strip().lower()
            if severity in packages:
                packages[severity].append((pkg, cve))

        if any(counts[lvl] > 0 for lvl in display_levels):
            sections.append({
                "header": header,
                "counts": counts,
                "packages": packages,
            })

    return sections


def print_report(project, image_reports):
    print(f"SCAN REPORT: {project}")
    print("-------------------------")
    print()

    for image, sections, display_levels in image_reports:
        print(f"Docker Image: {image}")
        print("Vuln(s) found:")
        print()

        for section in sections:
            print(section["header"])
            for level in display_levels:
                count = section["counts"].get(level, 0)
                if count == 0:
                    continue
                print(f"{level}: {count}")
                for pkg, _cve in section["packages"].get(level, []):
                    print(f"- {pkg}")
            print()

        print("-------------------------")
        print()


def build_embed(image, project, sections, display_levels):
    embed_color = SEVERITY_COLORS["unknown"]
    for level in VALID_LEVELS:
        if level not in display_levels:
            continue
        if any(s["counts"].get(level, 0) > 0 for s in sections):
            embed_color = SEVERITY_COLORS[level]
            break

    target_names = [s["header"] for s in sections]
    description = "Scan completed · " + " · ".join(target_names) if target_names else "No vulnerabilities in selected levels."
    timestamp = datetime.now(timezone.utc).isoformat()

    fields = []
    for section in sections:
        active_levels = [l for l in display_levels if section["counts"].get(l, 0) > 0]
        for level in active_levels:
            count = section["counts"].get(level, 0)
            emoji = SEVERITY_EMOJI.get(level, "")
            fields.append({
                "name": f"{emoji} {level.upper()}",
                "value": str(count),
                "inline": True,
            })

        remainder = len(active_levels) % 3
        if remainder != 0:
            for _ in range(3 - remainder):
                fields.append({"name": "\u200b", "value": "\u200b", "inline": True})

        pkg_lines = []
        for level in display_levels:
            for pkg, cve in section["packages"].get(level, []):
                cve_label = f"  `{cve}`" if cve and cve.startswith("CVE-") else ""
                pkg_lines.append(f"• {pkg}{cve_label}")

        fields.append({
            "name": section["header"],
            "value": "\n".join(pkg_lines) if pkg_lines else "—",
            "inline": False,
        })

    return {
        "title": f"🛡️  Vulnerabilities found — {image}",
        "description": description,
        "color": embed_color,
        "fields": fields,
        "footer": {"text": f"scan.py · {project}"},
        "timestamp": timestamp,
    }


def send_discord_embed(webhook_url, embed):
    payload = json.dumps({"embeds": [embed]}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
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
    images, levels, webhook_url, project = parse_args()

    display_levels = (
        sorted(levels, key=lambda l: VALID_LEVELS.index(l))
        if levels is not None
        else VALID_LEVELS
    )

    effective_webhook = webhook_url or DISCORD_WEBHOOK_URL
    image_reports = []

    for image in images:
        output = run_trivy(image)
        sections = parse_sections(output, display_levels)
        image_reports.append((image, sections, display_levels))

    print_report(project, image_reports)

    for image, sections, display_levels in image_reports:
        embed = build_embed(image, project, sections, display_levels)
        send_discord_embed(effective_webhook, embed)


if __name__ == "__main__":
    main()