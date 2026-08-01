"""Vendor Atomic Red Team YAML definitions at the reviewed pinned revision.

Only ``atomics/**/*.yaml`` files are retained: this platform generates
telemetry from command definitions and must never vendor or execute Atomic
payloads. Run this deliberately when refreshing the snapshot; application
startup only reads the already-vendored files.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path


REPOSITORY = "https://github.com/redcanaryco/atomic-red-team.git"
PINNED_COMMIT = "1ba1dd8d9ce6f74700f7aec2e60de5632f667f03"
BACKEND_ROOT = Path(__file__).resolve().parents[1]
TARGET_ROOT = BACKEND_ROOT / "vendor" / "atomic-red-team"

LICENSE_TEXT = """The MIT License

Copyright (c) 2018 Red Canary, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""


def vendor_atomics(*, force: bool = False) -> int:
    """Fetch the pinned revision and write the YAML-only vendored snapshot."""
    if TARGET_ROOT.exists():
        if not force:
            raise FileExistsError(f"{TARGET_ROOT} already exists; use --force to replace it")
        shutil.rmtree(TARGET_ROOT)

    with tempfile.TemporaryDirectory(prefix="atomic-red-team-") as temp_dir:
        checkout = Path(temp_dir) / "atomic-red-team"
        subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:none", REPOSITORY, str(checkout)],
            check=True,
        )
        subprocess.run(["git", "-C", str(checkout), "checkout", PINNED_COMMIT], check=True)

        source_atomics = checkout / "atomics"
        target_atomics = TARGET_ROOT / "atomics"
        for yaml_file in source_atomics.rglob("*.yaml"):
            destination = target_atomics / yaml_file.relative_to(source_atomics)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(yaml_file, destination)

    (TARGET_ROOT / "LICENSE.txt").write_text(LICENSE_TEXT, encoding="utf-8")
    (TARGET_ROOT / "PROVENANCE.md").write_text(
        "# Atomic Red Team provenance\n\n"
        f"- Upstream: {REPOSITORY}\n"
        f"- Pinned commit: `{PINNED_COMMIT}`\n"
        "- Vendored content: `atomics/**/*.yaml` only; payloads are intentionally excluded.\n"
        "- License file: `LICENSE.txt` (MIT License)\n"
        "- Upstream license: https://github.com/redcanaryco/atomic-red-team/blob/"
        f"{PINNED_COMMIT}/LICENSE.txt\n\n"
        "## License text\n\n```text\n"
        f"{LICENSE_TEXT}```\n",
        encoding="utf-8",
    )
    return len(list((TARGET_ROOT / "atomics").rglob("*.yaml")))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="replace an existing snapshot")
    args = parser.parse_args()
    count = vendor_atomics(force=args.force)
    print(f"Vendored {count} Atomic Red Team YAML files at {PINNED_COMMIT}.")


if __name__ == "__main__":
    main()
