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


def emit(**kw) -> None:
    sys.stdout.write(json.dumps(kw, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def collect_rules(rules_dir):
    out = []
    for root, _, files in os.walk(rules_dir):
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

    compiled = []
    for rf in collect_rules(rules_dir):
        try:
            compiled.append(yara.compile(
                filepath=rf,
                externals={"filename": "", "filepath": "",
                           "extension": "", "filetype": ""}))
        except yara.SyntaxError as e:
            emit(type="warn", msg=f"Règle ignorée ({os.path.basename(rf)}) : {e}")
        except Exception as e:
            emit(type="warn", msg=f"Erreur compilation ({os.path.basename(rf)}) : {e}")

    if not compiled:
        emit(type="error", msg="aucune règle valide après compilation")
        return 4
    emit(type="compiled", count=len(compiled))

    scanned = 0
    unreadable = 0

    def scan_file(fp: str) -> None:
        nonlocal scanned, unreadable
        try:
            ext = os.path.splitext(fp)[1].lstrip(".").lower()
            exts = {"filename": os.path.basename(fp), "filepath": fp,
                    "extension": ext, "filetype": ext.upper()}
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