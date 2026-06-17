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
DISCORD_EMBED_CHAR_LIMIT = 5800
HIGH_DETAIL_MAX = 5

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


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

def parse_args():
    images = []
    levels = None
    webhook_url = None
    project = "default unset project"
    pipeline_url = None

    for arg in sys.argv[1:]:
        if arg.startswith("--image="):
            images.append(arg[len("--image="):])
        elif arg.startswith("--level="):
            levels = arg[len("--level="):]
        elif arg.startswith("--discord-webhook="):
            webhook_url = arg[len("--discord-webhook="):]
        elif arg.startswith("--project="):
            project = arg[len("--project="):]
        elif arg.startswith("--pipeline-url="):
            pipeline_url = arg[len("--pipeline-url="):]

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

    return images, levels, webhook_url, project, pipeline_url


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------

def run_trivy(image):
    try:
        result = subprocess.run(
            ["trivy", "image", image],
            capture_output=True,
            text=True,
        )
        return result.stdout + result.stderr
    except FileNotFoundError:
        print("Erreur : 'trivy' est introuvable.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

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


def aggregate_by_level(image_reports):
    """
    Regroupe TOUTES les vulnérabilités de toutes les images par niveau.
    Retourne : { level: [ (pkg, cve, image, section_header), ... ] }
    et les compteurs globaux : { level: int }
    """
    aggregated = {lvl: [] for lvl in VALID_LEVELS}
    counts = {lvl: 0 for lvl in VALID_LEVELS}

    for image, sections, display_levels in image_reports:
        for section in sections:
            for level in display_levels:
                for pkg, cve in section["packages"].get(level, []):
                    aggregated[level].append((pkg, cve, image, section["header"]))
                counts[level] += section["counts"].get(level, 0)

    return aggregated, counts


# ---------------------------------------------------------------------------
# Sortie 1 : Terminal
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Sortie 2 : Fichier .txt complet (généré uniquement si nécessaire,
# c'est-à-dire si l'embed Discord est trop long pour tout afficher)
# ---------------------------------------------------------------------------

def build_txt_report(project, image_reports, pipeline_url):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"SCAN REPORT : {project}",
    ]
    if pipeline_url:
        lines.append(f"Pipeline    : {pipeline_url}")
    lines.append(f"Date        : {now}")
    lines.append("=" * 60)
    lines.append("")
    for image, sections, display_levels in image_reports:
        lines.append(f"IMAGE : {image}")
        lines.append("-" * 40)
        for section in sections:
            lines.append(f"  [ {section['header']} ]")
            for level in display_levels:
                count = section["counts"].get(level, 0)
                if count == 0:
                    continue
                lines.append(f"    {level.upper()} ({count})")
                for pkg, cve in section["packages"].get(level, []):
                    lines.append(f"      • {pkg}  {cve}")
            lines.append("")
        lines.append("")
    return "\n".join(lines)


def save_txt_report(project, image_reports, pipeline_url):
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    safe_project = project.replace(" ", "-").lower()
    filename = f"scan_{safe_project}_{date_str}.txt"
    content = build_txt_report(project, image_reports, pipeline_url)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"📄 Rapport txt sauvegardé : {filename}")
    return filename, content


# ---------------------------------------------------------------------------
# Sortie 3 : Discord Embed — trié par sévérité (proposition B)
# ---------------------------------------------------------------------------

def build_embed_b(project, image_reports, display_levels, pipeline_url):
    aggregated, counts = aggregate_by_level(image_reports)

    # Couleur et statut global
    has_critical = counts.get("critical", 0) > 0
    has_high     = counts.get("high", 0) > 0
    if has_critical:
        embed_color = SEVERITY_COLORS["critical"]
        status = "🔴 ACTION REQUISE"
    elif has_high:
        embed_color = SEVERITY_COLORS["high"]
        status = "🟠 À TRAITER"
    else:
        embed_color = SEVERITY_COLORS["low"]
        status = "🟢 RAS"

    images_scanned = [ir[0] for ir in image_reports]
    timestamp = datetime.now(timezone.utc).isoformat()

    fields = []

    for level in display_levels:
        entries = aggregated.get(level, [])
        total = counts.get(level, 0)
        emoji = SEVERITY_EMOJI.get(level, "")

        if total == 0:
            continue

        if level == "critical":
            # Détail complet
            lines = [f"• `{pkg}` {cve}  _[{img}]_" for pkg, cve, img, _ in entries]
            value = "\n".join(lines)

        elif level == "high":
            # Tronqué à HIGH_DETAIL_MAX
            shown = entries[:HIGH_DETAIL_MAX]
            lines = [f"• `{pkg}` {cve}  _[{img}]_" for pkg, cve, img, _ in shown]
            if len(entries) > HIGH_DETAIL_MAX:
                lines.append(f"_... et {len(entries) - HIGH_DETAIL_MAX} autres — voir rapport joint_")
            value = "\n".join(lines)

        else:
            # Juste le compteur
            value = f"{total} vulnérabilité(s) — détail dans le rapport joint"

        fields.append({
            "name": f"{emoji} {level.upper()}  ({total})",
            "value": value,
            "inline": False,
        })

    author = {"name": f"⚠️  Project — {project}"}
    if pipeline_url:
        author["url"] = pipeline_url

    description = f"🛡️  Scan terminé · {len(images_scanned)} image(s)"
    if pipeline_url:
        description += f" · [voir pipeline]({pipeline_url})"

    embed = {
        "author": author,
        "title": f"{status} — {', '.join(images_scanned)}",
        "description": description,
        "color": embed_color,
        "fields": fields,
        "footer": {"text": f"scan.py · {project}"},
        "timestamp": timestamp,
    }
    return embed


def embed_char_count(embed):
    total = len(embed.get("title", "")) + len(embed.get("description", ""))
    total += len(embed.get("author", {}).get("name", ""))
    for field in embed.get("fields", []):
        total += len(field.get("name", "")) + len(field.get("value", ""))
    total += len(embed.get("footer", {}).get("text", ""))
    return total


def send_discord(webhook_url, embed, txt_filename=None, txt_content=None):
    attach_file = txt_content is not None
    too_long = embed_char_count(embed) > DISCORD_EMBED_CHAR_LIMIT

    if attach_file:
        if too_long:
            # Allège encore les champs pour respecter la vraie limite de Discord
            for field in embed["fields"]:
                if not field.get("inline") and "rapport joint" not in field["value"]:
                    field["value"] = "_voir rapport joint_"
        embed["description"] += "\n📎 *Rapport complet en pièce jointe*"

        payload_json = json.dumps({"embeds": [embed]})
        boundary = "----DiscordBoundary"
        fname = os.path.basename(txt_filename)
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="payload_json"\r\n\r\n'
            f"{payload_json}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="files[0]"; filename="{fname}"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"{txt_content}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "scan.py",
        }
    else:
        body = json.dumps({"embeds": [embed]}).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "scan.py"}

    req = urllib.request.Request(webhook_url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status in (200, 204):
                suffix = " (+ fichier joint)" if attach_file else ""
                print(f"✅ Notification Discord envoyée{suffix}.")
            else:
                print(f"⚠️  Discord a répondu avec le statut {response.status}.")
    except urllib.error.HTTPError as e:
        print(f"⚠️  Erreur HTTP Discord : {e.code} – {e.reason}")
    except urllib.error.URLError as e:
        print(f"⚠️  Impossible de joindre Discord : {e.reason}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    images, levels, webhook_url, project, pipeline_url = parse_args()

    display_levels = (
        sorted(levels, key=lambda l: VALID_LEVELS.index(l))
        if levels is not None
        else VALID_LEVELS
    )

    effective_webhook = webhook_url or DISCORD_WEBHOOK_URL

    # Scan toutes les images
    image_reports = []
    for image in images:
        output = run_trivy(image)
        sections = parse_sections(output, display_levels)
        image_reports.append((image, sections, display_levels))

    # ── Sortie 1 : Terminal ────────────────────────────────────────────────
    print_report(project, image_reports)

    # ── Sortie 3 : Discord (un seul embed global trié par sévérité) ────────
    embed = build_embed_b(project, image_reports, display_levels, pipeline_url)

    # ── Sortie 2 : Fichier .txt — généré dès que l'embed renvoie vers un
    # "rapport joint" (HIGH tronqué, ou MEDIUM/LOW/UNKNOWN non vides),
    # ou si l'embed dépasse la limite brute de caractères Discord
    needs_report = embed_char_count(embed) > DISCORD_EMBED_CHAR_LIMIT or any(
        "rapport joint" in field["value"] for field in embed["fields"]
    )
    if needs_report:
        txt_filename, txt_content = save_txt_report(project, image_reports, pipeline_url)
    else:
        txt_filename, txt_content = None, None

    send_discord(effective_webhook, embed, txt_filename, txt_content)


if __name__ == "__main__":
    main()