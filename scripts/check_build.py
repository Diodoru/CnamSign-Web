"""Contrôle d'intégrité de l'image : fichiers et templates nécessaires au rendu de l'application et de /admin.

Exécuté au build Docker (une image incomplète échoue au build au lieu de s'afficher cassée en prod)
et utilisable en local : python scripts/check_build.py

Ne nécessite aucun secret : n'importe pas app.config, se contente de charger ce que l'app chargera.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"

REQUIRED_FILES = [
    "app/templates/base.html",
    "app/templates/dashboard.html",
    "app/templates/login.html",
    "app/templates/admin/sqladmin/base.html",
    "app/templates/admin/sqladmin/layout.html",
    "app/templates/admin/sqladmin/filters/lookup_filter.html",
    "app/admin_i18n/fr.po",
    "app/services/cnam_worker.py",
]
SQLADMIN_STATICS = ["css/tabler.min.css", "css/tabler-icons.min.css", "css/fontawesome-all.min.css",
                    "css/select2.min.css", "css/flatpickr.min.css", "css/main.css", "js/jquery.min.js",
                    "js/tabler.min.js", "js/select2.full.min.js", "js/flatpickr.min.js", "js/main.js"]


def main() -> int:
    errors: list[str] = []

    errors += [f"fichier manquant : {p}" for p in REQUIRED_FILES if not (ROOT / p).is_file()]

    # Ressources servies par SQLAdmin sur /admin/statics (référencées par notre base.html d'admin)
    import sqladmin
    statics = Path(sqladmin.__file__).parent / "statics"
    errors += [f"ressource SQLAdmin manquante : statics/{p}" for p in SQLADMIN_STATICS if not (statics / p).is_file()]

    # Catalogue français : même compilation qu'au démarrage (app/admin.py)
    from babel.messages.mofile import write_mo
    from babel.messages.pofile import read_po
    with (APP / "admin_i18n" / "fr.po").open("rb") as po:
        catalog = read_po(po, locale="fr", domain="admin")
    write_mo(io.BytesIO(), catalog)

    # Templates d'admin : mêmes chargeurs que SQLAdmin (surcharges puis originaux) -> erreurs de syntaxe
    # ou héritage cassé détectés ici, pas en production.
    from jinja2 import ChoiceLoader, Environment, FileSystemLoader, PackageLoader, PrefixLoader
    env = Environment(loader=ChoiceLoader([
        FileSystemLoader(str(APP / "templates" / "admin")),
        PrefixLoader({"sqladmin_original": PackageLoader("sqladmin", "templates/sqladmin")}),
        PackageLoader("sqladmin", "templates"),
    ]), extensions=["jinja2.ext.i18n"])
    for name in ("sqladmin/base.html", "sqladmin/layout.html", "sqladmin/list.html", "sqladmin/filters/lookup_filter.html"):
        try:
            env.get_template(name)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"template {name} invalide : {exc}")
    if not env.get_template("sqladmin/base.html").filename.startswith(str(APP)):
        errors.append("la surcharge sqladmin/base.html n'est pas prise en compte")

    for error in errors:
        print(f"[check_build] ERREUR : {error}", file=sys.stderr)
    print(f"[check_build] {'ÉCHEC' if errors else 'OK'} ({len(REQUIRED_FILES)} fichiers, {len(SQLADMIN_STATICS)} ressources, "
          f"{len(catalog)} traductions, templates d'admin chargés)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
