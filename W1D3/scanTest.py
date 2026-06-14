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
    """Extrait les compteurs depuis la ligne de résumé de trivy.
    Format : Total: 151 (UNKNOWN: 1, LOW: 93, MEDIUM: 44, HIGH: 11, CRITICAL: 2)
    """
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    # Cherche la ligne de résumé
    summary_match = re.search(r"Total:\s*\d+\s*\((.+?)\)", output)
    if summary_match:
        summary = summary_match.group(1)
        # Extrait chaque niveau et son chiffre depuis le résumé
        # ex: "UNKNOWN: 1, LOW: 93, MEDIUM: 44, HIGH: 11, CRITICAL: 2"
        for match in re.finditer(r"(\w+):\s*(\d+)", summary):
            level = match.group(1).lower()
            count = int(match.group(2))
            if level in counts:
                counts[level] = count

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
