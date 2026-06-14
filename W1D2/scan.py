import sys
import subprocess
import re

VALID_LEVELS = ["critical", "high", "medium", "low", "unknown"]

def parse_args():
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
        sys.exit(1)
    if levels is not None:
        levels = [l.strip().lower() for l in levels.split(",")]
        for l in levels:
            if l not in VALID_LEVELS:
                print(f"error: {l} is not a CVE valid level")
                sys.exit(1)
    return image, levels

def run_trivy(image):
    try:
        result = subprocess.run(["trivy", "image", image], capture_output=True, text=True)
        return result.stdout + result.stderr
    except FileNotFoundError:
        print("Erreur : trivy est introuvable.")
        sys.exit(1)

def parse_vulnerabilities(output):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for line in output.splitlines():
        if "Total:" in line:
            summary = re.search(r'\((.+?)\)', line)
            if summary:
                for match in re.finditer(r'(\w+):\s*(\d+)', summary.group(1)):
                    level = match.group(1).lower()
                    if level in counts:
                        counts[level] = int(match.group(2))
    return counts

def main():
    image, levels = parse_args()
    output = run_trivy(image)
    counts = parse_vulnerabilities(output)
    display_levels = levels if levels is not None else VALID_LEVELS
    print(" ".join(f"{level}: {counts[level]}" for level in display_levels))

if __name__ == "__main__":
    main()
