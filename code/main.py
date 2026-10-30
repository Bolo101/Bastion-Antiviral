#!/usr/bin/env python3
"""
main.py – Point d'entrée du scanner antiviral USB.
Nécessite les droits root (sudo).
"""

import os
import sys
import tkinter as tk
from tkinter import messagebox

from log_handler import log_error, log_info
from scanner import ScanEngine


def main() -> None:

    # ── Vérification root ─────────────────────────────────────────────────────
    if os.geteuid() != 0:
        print("Ce programme doit être lancé avec sudo.", file=sys.stderr)
        sys.exit(1)

    # ── Vérification ClamAV ───────────────────────────────────────────────────
    eng = ScanEngine()
    if not eng.is_clamav_installed():
        try:
            _root = tk.Tk()
            _root.withdraw()
            messagebox.showerror(
                "ClamAV manquant",
                "ClamAV n'est pas installé sur ce système.\n\n"
                "Installez-le avec :\n"
                "  sudo apt install clamav clamav-daemon clamav-freshclam\n\n"
                "Puis mettez à jour la base :\n"
                "  sudo freshclam"
            )
            _root.destroy()
        except Exception:
            pass
        print("Erreur : ClamAV introuvable.", file=sys.stderr)
        sys.exit(1)

    # ── Sandbox d'analyse ────────────────────────────────────────────────────
    from config import SANDBOX_ENABLED, SANDBOX_REQUIRED
    from sandbox import Sandbox
    sandbox_ok = (not SANDBOX_ENABLED) or Sandbox.self_test()
    log_info(Sandbox.status_summary())
    if not sandbox_ok and SANDBOX_REQUIRED:
        reason = Sandbox.unavailable_reason()
        print(f"Sandbox indisponible : {reason}", file=sys.stderr)
        try:
            _root = tk.Tk()
            _root.withdraw()
            messagebox.showwarning(
                "Sandbox indisponible",
                "L'isolation des analyses ne peut pas démarrer :\n"
                f"  {reason}\n\n"
                "Par sécurité, AUCUNE analyse ne sera lancée tant que le "
                "sandbox n'est pas opérationnel.\n\n"
                "  sudo apt install bubblewrap python3-seccomp\n"
                "  sudo python3 sandbox_selftest.py"
            )
            _root.destroy()
        except Exception:
            pass

    # ── Informations YARA ────────────────────────────────────────────────────
    yara_ok, yara_method = eng.detect_yara()
    log_info("Démarrage du scanner antiviral USB")
    log_info(f"ClamAV : installé ({eng.is_clamav_installed()})")
    log_info(f"YARA   : {'disponible (' + yara_method + ')' if yara_ok else 'non disponible'}")
    if not yara_ok:
        print(
            "Info : YARA non disponible. "
            "Installez-le avec : sudo apt install python3-yara  "
            "ou  sudo pip3 install yara-python",
            file=sys.stderr
        )

    # ── Lancement de l'interface ──────────────────────────────────────────────
    from gui import VirusScannerGUI

    root = tk.Tk()
    try:
        app = VirusScannerGUI(root)   # noqa: F841
        root.mainloop()
    except Exception as e:
        msg = f"Erreur fatale : {e}"
        log_error(msg)
        print(msg, file=sys.stderr)
        try:
            messagebox.showerror("Erreur fatale", msg)
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()