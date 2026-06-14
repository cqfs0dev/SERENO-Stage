#!/usr/bin/env python3
"""Wrap `trivy image` to scan one or more images and report vulnerabilities
grouped by target, filtered by severity level."""

import argparse
import json
import subprocess
import sys

ALL_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def parse_args():
    parser = argparse.ArgumentParser(description="Scan one or more container images with Trivy.")
    # action="append" -> at least one --image, repeatable
    parser.add_argument(
        "--image",
        action="append",
        dest="images",
        required=True,
        metavar="IMAGE:TAG",
        help="Image to scan (repeat for multiple, e.g. --image=a --image=b)",
    )
    # comma-separated severities, normalised to upper-case
    parser.add_argument(
        "--levels",
        default=",".join(ALL_LEVELS),
        help="Comma-separated severities (default: all). e.g. --levels=critical,high",
    )
    args = parser.parse_args()
    args.levels = [lvl.strip().upper() for lvl in args.levels.split(",") if lvl.strip()]
    return args


def run_trivy(image, levels):
    """Run trivy on one image, return parsed JSON (dict)."""
    cmd = [
        "trivy",
        "image",
        "--severity",
        ",".join(levels),
        "-f",
        "json",
        "--quiet",
        image,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        sys.exit("error: trivy not found on PATH")
    except subprocess.CalledProcessError as e:
        sys.exit(f"error: trivy failed on {image}:\n{e.stderr}")

    return json.loads(result.stdout or "{}")


def extract(report, levels):
    """Yield (target, severity_counts, libraries) per result block that has hits.

    severity_counts: dict like {"CRITICAL": 2}
    libraries: list of library names (one per vuln, duplicates kept)
    """
    for res in report.get("Results", []):
        vulns = res.get("Vulnerabilities") or []
        if not vulns:
            continue
        # Trivy already filtered by --severity, but double-check against levels
        vulns = [v for v in vulns if v.get("Severity", "").upper() in levels]
        if not vulns:
            continue

        target = res.get("Target", "unknown")
        counts = {}
        libs = []
        for v in vulns:
            sev = v.get("Severity", "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
            libs.append(v.get("PkgName", "?"))
        yield target, counts, libs


def main():
    args = parse_args()
    print("> Vuln(s) found:\n")

    any_found = False
    for image in args.images:
        report = run_trivy(image, args.levels)
        for target, counts, libs in extract(report, args.levels):
            any_found = True
            print(f"> {target}")
            # print counts in canonical severity order
            for sev in ALL_LEVELS:
                if sev in counts:
                    print(f"> {sev.lower()}: {counts[sev]}")
            for lib in libs:
                print(f"- {lib}")
            print()  # blank line between blocks

    if not any_found:
        print("> none")


if __name__ == "__main__":
    main()

# 1) BUILD YOUR IMAGES FROM D4
#
# docker buildx build -f ./D4/Dockerfile.python -t hello-py:vuln .
# docker buildx build -f ./D4/Dockerfile.node -t hello-node:vuln .
#
# 2) RUN YOUR SCANNER ON TARGETED IMAGES SEARCHING FOR A CRITICAL SEVERITY
#
# python3 D5/scan_one_possible_solution_d5.py --image hello-node:vuln --image hello-py:vuln --level critical
#
# Congrats: End of Week 1
