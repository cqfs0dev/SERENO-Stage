import sys
import subprocess
import re


def parse_args():
    """Récupère la valeur de l'argument --image= depuis les arguments CLI."""
    image = None
    for arg in sys.argv[1:]:
        if arg.startswith("--image="):
            image = arg[len("--image="):]
            break
        elif arg == "--image":
            image = ""
            break

    if image is None or image == "":
        print("Erreur : image est obligatoire")
        print("Usage : python scan.py --image=<nom_de_l_image>")
        sys.exit(1)

    return image


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
        print("Erreur : la commande 'trivy' est introuvable. Vérifiez qu'elle est installée et dans votre PATH.")
        sys.exit(1)


def parse_vulnerabilities(output):
    """Extrait les compteurs de vulnérabilités depuis la sortie de trivy."""
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    patterns = {
        "critical": r"CRITICAL[:\s]+(\d+)",
        "high":     r"HIGH[:\s]+(\d+)",
        "medium":   r"MEDIUM[:\s]+(\d+)",
        "low":      r"LOW[:\s]+(\d+)",
        "unknown":  r"UNKNOWN[:\s]+(\d+)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            counts[key] = int(match.group(1))

    return counts


def main():
    image = parse_args()
    output = run_trivy(image)
    counts = parse_vulnerabilities(output)

    print(
        f"critical: {counts['critical']} "
        f"high: {counts['high']} "
        f"medium: {counts['medium']} "
        f"low: {counts['low']} "
        f"unknown: {counts['unknown']}"
    )


if __name__ == "__main__":
    main()
