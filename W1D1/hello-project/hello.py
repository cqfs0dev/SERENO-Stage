import argparse
import re
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--name", default="Sereno")
args = parser.parse_args()

if not re.match(r'^\w[a-zA-Z-]*[a-zA-Z\d]+$', args.name):
    print("Error: invalid format. Your name must start with a letter")
    sys.exit(1)

print(f"Hello {args.name}!")
