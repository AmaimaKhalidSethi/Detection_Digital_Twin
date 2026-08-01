"""Vendor a pinned, engine-supported SigmaHQ rule snapshot.

The snapshot deliberately contains only the logsource categories currently
accepted by ``app.detection_engine.rule_manager``. It is refreshed manually;
the application never fetches SigmaHQ at runtime.
"""
from __future__ import annotations

import argparse
import json
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, urlopen


REPOSITORY = "https://github.com/SigmaHQ/sigma.git"
PINNED_COMMIT = "1aacbedf7fc04067e6b1b2594c4b7c1c2ff649a9"
TREE_URL = f"https://api.github.com/repos/SigmaHQ/sigma/git/trees/{PINNED_COMMIT}?recursive=1"
RAW_URL = "https://raw.githubusercontent.com/SigmaHQ/sigma/{commit}/{path}"
BACKEND_ROOT = Path(__file__).resolve().parents[1]
TARGET_ROOT = BACKEND_ROOT / "vendor" / "sigmahq"

# Equal-ish allocation gives the library useful platform/category breadth while
# keeping the successfully importable corpus within the 200--300 target.
SOURCE_LIMITS = {
    "rules/windows/process_creation/": 120,
    "rules/linux/process_creation/": 80,
    "rules/windows/registry/": 50,
    "rules/windows/network_connection/": 45,
    "rules/linux/network_connection/": 5,
}


def _request(url: str):
    return Request(url, headers={"User-Agent": "detection-digital-twin-vendor"})


def _selected_paths() -> list[str]:
    with urlopen(_request(TREE_URL), timeout=30) as response:
        tree = json.load(response)["tree"]
    all_paths = sorted(
        entry["path"]
        for entry in tree
        if entry["type"] == "blob" and entry["path"].endswith(".yml")
    )
    selected: list[str] = []
    for prefix, limit in SOURCE_LIMITS.items():
        paths = [path for path in all_paths if path.startswith(prefix)]
        if len(paths) < limit:
            raise RuntimeError(f"Only {len(paths)} rules found below {prefix}; expected at least {limit}")
        selected.extend(paths[:limit])
    return selected


def vendor_rules(*, force: bool = False) -> int:
    if TARGET_ROOT.exists():
        if not force:
            raise FileExistsError(f"{TARGET_ROOT} already exists; use --force to replace it")
        shutil.rmtree(TARGET_ROOT)

    target_rules = TARGET_ROOT / "rules"

    def download(path: str) -> None:
        with urlopen(_request(RAW_URL.format(commit=PINNED_COMMIT, path=path)), timeout=30) as response:
            content = response.read()
        destination = target_rules / Path(path).relative_to("rules")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    paths = _selected_paths()
    try:
        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(download, paths))
    except Exception:
        shutil.rmtree(TARGET_ROOT, ignore_errors=True)
        raise

    (TARGET_ROOT / "ATTRIBUTION.md").write_text(
        "# SigmaHQ attribution and license\n\n"
        f"This snapshot contains 300 rules from [SigmaHQ/sigma]({REPOSITORY.rstrip('.git')}) "
        f"at pinned commit [`{PINNED_COMMIT}`]({REPOSITORY.rstrip('.git')}/tree/{PINNED_COMMIT}).\n\n"
        "The rules are licensed under [Detection Rule License (DRL) 1.1]"
        "(https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md). "
        "The author supplied in every rule is retained in the stored YAML, database metadata, "
        "and alert output.\n",
        encoding="utf-8",
    )
    return len(paths)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="replace an existing snapshot")
    args = parser.parse_args()
    print(f"Vendored {vendor_rules(force=args.force)} SigmaHQ rules at {PINNED_COMMIT}.")


if __name__ == "__main__":
    main()
