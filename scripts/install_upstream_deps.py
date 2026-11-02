"""Installe les dépendances du code upstream CnamSign sans casser celles de l'application.

L'upstream épingle parfois des versions incompatibles avec nos dépendances
(ex. `python-dotenv==1.0.1` alors que `pydantic-settings` exige `>=1.2.2`).
Les paquets déjà épinglés dans notre requirements.txt sont donc retirés de la liste
upstream avant installation : notre version fait foi, le reste suit l'upstream.

Usage : python scripts/install_upstream_deps.py vendor/CnamSign/requirements.txt
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

APP_REQUIREMENTS = Path(__file__).resolve().parent.parent / "requirements.txt"
_NAME = re.compile(r"^\s*([A-Za-z0-9_.-]+)")


def _package_names(lines: list[str]) -> set[str]:
    names = set()
    for line in lines:
        match = _NAME.match(line.split("#", 1)[0])
        if match:
            names.add(re.sub(r"[-_.]+", "-", match.group(1)).lower())  # normalisation PEP 503
    return names


def main(upstream_requirements: str) -> int:
    ours = _package_names(APP_REQUIREMENTS.read_text(encoding="utf-8").splitlines())
    kept, skipped = [], []
    for line in Path(upstream_requirements).read_text(encoding="utf-8").splitlines():
        (skipped if _package_names([line]) & ours else kept).append(line)
    for line in skipped:
        print(f"[upstream-deps] ignoré (version de l'application prioritaire) : {line.strip()}")

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
        tmp.write("\n".join(kept) + "\n")
    try:
        return subprocess.call([sys.executable, "-m", "pip", "install", "-r", tmp.name])
    finally:
        Path(tmp.name).unlink(missing_ok=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
