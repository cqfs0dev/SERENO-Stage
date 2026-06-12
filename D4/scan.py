import sys
import subprocess
import json

VALID_LEVELS = ["critical", "high", "medium", "low", "unknown"]

# Mapping du "Type"/"Class" trivy vers le libellé de groupe affiché
TYPE_LABELS = {
    "debian": "debian",
    "ubuntu": "ubuntu",
    "alpine": "alpine",
    "node-pkg": "node-pkg",
    "npm": "node-pkg",
    "python-pkg": "python-pkg",
    "pip": "python-pkg",
}


def parse_args():
    """Récupère les arguments --image= (répétable) et --level= depuis les arguments CLI."""
    images = []
    levels = None

    for arg in sys.argv[1:]:
        if arg.startswith("--image="):
            value = arg[len("--image="):]
            if value:
                images.append(value)
        elif arg == "--image":
            pass
        elif arg.startswith("--level="):
            levels = arg[len("--level="):]

    if not images:
        print("Erreur : image est obligatoire")
        print("Usage : python scan.py --image=<nom_de_l_image> [--image=<autre_image> ...] [--level=critical,high,...]")
        sys.exit(1)

    if levels is not None:
        levels = [l.strip().lower() for l in levels.split(",")]
        for l in levels:
            if l not in VALID_LEVELS:
                print(f"error: {l} is not a CVE valid level")
                sys.exit(1)

    return images, levels


def run_trivy_json(image):
    """Exécute `trivy image <image>` en JSON et retourne les données parsées."""
    try:
        result = subprocess.run(
            ["trivy", "image", "--format", "json", "--quiet", image],
            capture_output=True,
            text=True
        )
    except FileNotFoundError:
        print("Erreur : la commande 'trivy' est introuvable. Vérifiez qu'elle est installée et dans votre PATH.")
        sys.exit(1)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"Erreur : impossible de parser la sortie trivy pour '{image}'")
        print(result.stderr)
        sys.exit(1)


def extract_vulns(data, levels):
    """
    Extrait les vulnérabilités depuis le JSON trivy, regroupées par type de package.

    Retourne :
        {
            "debian": {"critical": ["perl-base", "perl-base"], "high": [...], ...},
            "node-pkg": {...},
            ...
        }
    """
    groups = {}

    for result_entry in data.get("Results", []):
        pkg_type = result_entry.get("Type", "unknown")
        group_name = TYPE_LABELS.get(pkg_type, pkg_type)

        for v in result_entry.get("Vulnerabilities") or []:
            severity = v.get("Severity", "UNKNOWN").lower()
            if levels is not None and severity not in levels:
                continue

            pkg_name = v.get("PkgName", "")

            if group_name not in groups:
                groups[group_name] = {}
            groups[group_name].setdefault(severity, []).append(pkg_name)

    return groups


def render_groups(groups, levels):
    """
    Construit les lignes de rapport pour un ensemble de groupes.
    Affiche, pour chaque groupe et chaque niveau présent (ou demandé via --level),
    le nombre et la liste des packages.
    """
    lines = []

    display_levels = levels if levels is not None else VALID_LEVELS

    blocks = []
    for group_name, severities in groups.items():
        relevant_levels = [lvl for lvl in display_levels if severities.get(lvl)]
        if not relevant_levels:
            continue

        block = [group_name]
        for lvl in relevant_levels:
            pkgs = severities.get(lvl, [])
            block.append(f"{lvl}: {len(pkgs)}")
            for pkg in pkgs:
                block.append(f"- {pkg}")
        blocks.append(block)

    if not blocks:
        lines.append("Vuln(s) found: none")
        return lines

    lines.append("Vuln(s) found:")
    for block in blocks:
        lines.append("")
        lines.extend(block)

    return lines


def main():
    images, levels = parse_args()

    if len(images) == 1:
        # Mode simple : une seule image
        data = run_trivy_json(images[0])
        groups = extract_vulns(data, levels)
        for line in render_groups(groups, levels):
            print(line)
    else:
        # Mode multi-images : rapport global
        print("SCAN REPORT:")
        print("-" * 25)

        for image in images:
            data = run_trivy_json(image)
            groups = extract_vulns(data, levels)

            print()
            print(f"Docker Image: {image}")
            for line in render_groups(groups, levels):
                print(line)
            print()
            print("-" * 25)


if __name__ == "__main__":
    main()