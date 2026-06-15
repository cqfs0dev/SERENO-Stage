import sys
import subprocess
import re
import requests

VALID_LEVELS = ["critical", "high", "medium", "low", "unknown"]

# Remplace par ton webhook Discord
WEBHOOK_URL = "https://discord.com/api/webhooks/1516024083102568512/AFAkgP5OTju8LsmIXPFEcEm2G1JY_zRw-22JGSjXe64R81uHIGvQUnQlzy4w9dv_IxFp"


def parse_args():
    """Récupère les arguments --image= et --level= depuis les arguments CLI."""
    image = None
    levels = None

    for arg in sys.argv[1:]:
        if arg.startswith("--image="):
            image = arg[len("--image="):]
        elif arg == "--image":
            image = ""
        elif arg.startswith("--level="):
            levels = arg[len("--level="):]

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

    return image, levels


def run_trivy(image):
    """Exécute `trivy image <image>` et retourne la sortie."""
    try:
        result = subprocess.run(
            ["trivy", "image", image],
            capture_output=True,
            text=True
        )
        return result.stdout + result.stderr

    except FileNotFoundError:
        print(
            "Erreur : la commande 'trivy' est introuvable. "
            "Vérifiez qu'elle est installée et dans votre PATH."
        )
        sys.exit(1)


def parse_vulnerabilities(output):
    """
    Extrait les compteurs depuis la ligne de résumé de trivy.
    Format :
    Total: 151 (UNKNOWN: 1, LOW: 93, MEDIUM: 44, HIGH: 11, CRITICAL: 2)
    """

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


def send_discord_webhook(image, counts):
    """Envoie les résultats du scan vers Discord."""

    payload = {
        "content": (
            f"🔍 Scan Trivy terminé pour `{image}`\n\n"
            f"🚨 Critical: {counts['critical']}\n"
            f"⚠️ High: {counts['high']}\n"
            f"📋 Medium: {counts['medium']}\n"
            f"📝 Low: {counts['low']}\n"
            f"❓ Unknown: {counts['unknown']}"
        )
    }

    try:
        response = requests.post(
            WEBHOOK_URL,
            json=payload,
            timeout=10
        )

        if response.status_code in (200, 204):
            print("Webhook Discord envoyé avec succès")
        else:
            print(
                f"Erreur Discord : "
                f"{response.status_code} - {response.text}"
            )

    except requests.RequestException as e:
        print(f"Erreur webhook : {e}")


def main():
    image, levels = parse_args()

    output = run_trivy(image)
    counts = parse_vulnerabilities(output)

    display_levels = levels if levels is not None else VALID_LEVELS

    result = " ".join(
        f"{level}: {counts[level]}"
        for level in display_levels
    )

    print(result)

    send_discord_webhook(image, counts)


if __name__ == "__main__":
    main()