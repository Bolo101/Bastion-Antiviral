#!/usr/bin/env python3
"""
sandbox_selftest.py – Vérifie, sur la machine réelle, que le sandbox isole bien
chaque moteur ET que chaque moteur détecte toujours une menace dedans.

    sudo python3 sandbox_selftest.py

Pour chaque moteur installé (ClamAV, YARA, Avast) : un répertoire temporaire
contenant le fichier de test EICAR (inoffensif) est analysé DANS le sandbox ;
la détection doit être remontée. Un fichier EICAR illisible par « autres »
(propriétaire différent, droits 600) est aussi testé.

Code de retour : 0 = tout est conforme, 1 = au moins un contrôle a échoué.
"""

import os
import shutil
import sys
import tempfile

from config import AVAST_SANDBOX_MODE, SANDBOX_MODE
from sandbox import Sandbox
from scanner import ScanEngine
import scanner

# Fichier de test standard EICAR (inoffensif), assemblé pour ne pas être
# détecté tel quel dans le code source.
_EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

OK, KO, NA = "✅ OK ", "❌ ÉCHEC", "➖ n/a "


def _scan(engine: str, target: str):
    eng = ScanEngine()
    msgs = []
    r = eng.scan([target],
                 use_clamav=(engine == "clamav"),
                 use_avast=(engine == "avast"),
                 use_yara=(engine == "yara"),
                 remove_infected=False,
                 progress_cb=lambda m, t: msgs.append(m),
                 file_count_cb=None)
    return r, msgs


def main() -> int:
    failures = 0
    print(Sandbox.status_summary())
    print(f"Mode demandé : {SANDBOX_MODE} | Avast : {AVAST_SANDBOX_MODE}\n")
    if not Sandbox.self_test():
        print(f"{KO} sandbox indisponible : {Sandbox.unavailable_reason()}")
        return 1

    work = tempfile.mkdtemp(prefix="bastion_selftest_")
    try:
        os.chmod(work, 0o755)
        plain = os.path.join(work, "plain.com")
        hidden = os.path.join(work, "hidden.com")
        for p in (plain, hidden):
            with open(p, "w") as f:
                f.write(_EICAR)
        os.chmod(plain, 0o644)
        os.chown(hidden, 1234, 1234)          # propriétaire étranger…
        os.chmod(hidden, 0o600)               # …et illisible par les autres

        # Règle YARA temporaire (indépendante des règles installées)
        rules = os.path.join(work, "rules")
        os.makedirs(rules)
        with open(os.path.join(rules, "eicar.yar"), "w") as f:
            f.write('rule SelfTest_Eicar { strings: $a = "EICAR-STANDARD-ANTIVIRUS" '
                    'condition: $a }\n')
        scan_dir = os.path.join(work, "key")
        os.makedirs(scan_dir)
        shutil.move(plain, scan_dir)
        shutil.move(hidden, scan_dir)

        saved_rules = scanner.YARA_RULES_DIR
        scanner.YARA_RULES_DIR = rules
        try:
            ee = ScanEngine()
            engines = [
                ("clamav", ee.is_clamav_installed()),
                ("yara",   ee.detect_yara()[0]),
                ("avast",  ee.is_avast_installed()),
            ]
            for name, available in engines:
                if not available:
                    print(f"{NA} {name:<7} non installé")
                    continue
                r, msgs = _scan(name, scan_dir)
                found = {os.path.basename(t.path) for t in r.threats}
                good = {"plain.com", "hidden.com"} <= found
                if good:
                    print(f"{OK} {name:<7} détecte EICAR (lisible ET illisible-par-autres)")
                else:
                    failures += 1
                    print(f"{KO} {name:<7} détectés : {sorted(found) or 'rien'}")
                    for e in r.errors[:3]:
                        print(f"          → {e}")
        finally:
            scanner.YARA_RULES_DIR = saved_rules
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\nRésultat :", "tout est conforme." if not failures
          else f"{failures} contrôle(s) en échec.")
    return 1 if failures else 0


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("À lancer avec sudo.", file=sys.stderr)
        sys.exit(2)
    sys.exit(main())