#!/usr/bin/env python3
"""
yara_worker.py – Processus d'analyse YARA exécuté DANS le sandbox (voir sandbox.py).

Le GUI ne charge ni ne compile jamais de règles et n'ouvre aucun fichier du
support : tout est fait ici, dans un processus jetable, sans réseau et avec le
support en lecture seule. Le worker communique avec l'hôte par lignes JSON sur
stdout ; l'hôte traite ces lignes comme NON FIABLES.

Usage : yara_worker.py <répertoire_règles> <cible> [<cible> …]
"""

import json
import os
import sys

TIMEOUT = 15
BATCH = 100          # taille des lots du repli (si la compilation groupée échoue)

# Variables externes déclarées à la compilation ET fournies à chaque analyse.
# « owner » est requis par certaines règles de signature-base (THOR).
EXTERNALS = {"filename": "", "filepath": "", "extension": "",
             "filetype": "", "owner": ""}


def emit(**kw) -> None:
    sys.stdout.write(json.dumps(kw, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def collect_rules(rules_dir):
    out = []
    for root, dirs, files in os.walk(rules_dir):
        # dossiers cachés ignorés (ex. reliquat d'une mise à jour interrompue)
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for f in sorted(files):
            if f.endswith((".yar", ".yara")) and not f.startswith("."):
                out.append(os.path.join(root, f))
    return out


def main() -> int:
    if len(sys.argv) < 3:
        emit(type="error", msg="arguments invalides")
        return 2
    rules_dir, targets = sys.argv[1], sys.argv[2:]

    try:
        import yara
    except ImportError:
        emit(type="error", msg="module yara absent dans le sandbox")
        return 3

    # 1) Validation fichier par fichier. L'objet compilé est libéré aussitôt :
    #    chaque yara.compile() réserve ~9 Mo de tables internes ; en garder ~750
    #    (signature-base complet) dépasse 6 Go et le noyau tue le worker (137).
    valid = {}
    for i, rf in enumerate(collect_rules(rules_dir)):
        try:
            yara.compile(filepath=rf, externals=EXTERNALS)
            valid[f"r{i}"] = rf                 # un namespace par fichier
        except yara.SyntaxError as e:
            emit(type="warn", msg=f"Règle ignorée ({os.path.basename(rf)}) : {e}")
        except Exception as e:
            emit(type="warn", msg=f"Erreur compilation ({os.path.basename(rf)}) : {e}")

    # 2) UN SEUL ensemble compilé (≈ 65 Mo pour signature-base complet) et une
    #    seule passe par fichier analysé.
    compiled = []
    n_files = 0
    if valid:
        try:
            compiled.append(yara.compile(filepaths=valid, externals=EXTERNALS))
            n_files = len(valid)
        except Exception as e:
            emit(type="warn", msg=f"Compilation groupée impossible ({e}) : repli par lots")
            items = list(valid.items())
            for k in range(0, len(items), BATCH):
                chunk = dict(items[k:k + BATCH])
                try:
                    compiled.append(yara.compile(filepaths=chunk, externals=EXTERNALS))
                    n_files += len(chunk)
                except Exception as e2:
                    emit(type="warn", msg=f"Lot de règles ignoré : {e2}")

    if not compiled:
        emit(type="error", msg="aucune règle valide après compilation")
        return 4
    emit(type="compiled", count=n_files)

    scanned = 0
    unreadable = 0

    def scan_file(fp: str) -> None:
        nonlocal scanned, unreadable
        try:
            ext = os.path.splitext(fp)[1].lstrip(".").lower()
            exts = {"filename": os.path.basename(fp), "filepath": fp,
                    "extension": ext, "filetype": ext.upper(), "owner": ""}
            for rules in compiled:
                for m in rules.match(fp, externals=exts, timeout=TIMEOUT):
                    emit(type="hit", path=fp, rule=m.rule)
        except Exception:
            # Fichier non analysé : le signaler (ne jamais le laisser passer pour sain)
            if not os.access(fp, os.R_OK):
                unreadable += 1
        finally:
            scanned += 1
            if scanned % 20 == 0:
                emit(type="progress", scanned=scanned, unreadable=unreadable)

    for target in targets:
        if os.path.isfile(target):
            scan_file(target)
        elif os.path.isdir(target):
            for dirpath, _, files in os.walk(target):
                for fname in files:
                    fp = os.path.join(dirpath, fname)
                    if os.path.isfile(fp) and not os.path.islink(fp):
                        scan_file(fp)

    emit(type="done", scanned=scanned, unreadable=unreadable)
    return 0


if __name__ == "__main__":
    sys.exit(main())