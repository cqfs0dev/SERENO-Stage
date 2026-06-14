import sys
import subprocess
import re

VALID_LEVELS = ["critical", "high", "medium", "low", "unknown"]


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
    image, levels = parse_args()
    output = run_trivy(image)
    counts = parse_vulnerabilities(output)

    # Si --level n'est pas renseigné, on affiche tous les niveaux
    display_levels = levels if levels is not None else VALID_LEVELS

    result = " ".join(f"{level}: {counts[level]}" for level in display_levels)
    print(result)


if __name__ == "__main__":
    main()
