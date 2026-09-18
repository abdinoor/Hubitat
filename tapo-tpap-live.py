#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read device status using the actual Groovy TPAP driver; never change power."""
import argparse
import getpass
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--host", required=True)
parser.add_argument("--username", required=True)
args = parser.parse_args()
password = getpass.getpass("Tapo password (not saved): ")
if "\n" in password or "\r" in password:
    sys.exit("This harness cannot pass a password containing a newline.")
result = subprocess.run(
    ["groovy", "tapo-tpap-tests.groovy", "--live", args.host, args.username, "--password-stdin"],
    cwd=Path(__file__).resolve().parent, input=password + "\n", text=True,
)
sys.exit(result.returncode)
