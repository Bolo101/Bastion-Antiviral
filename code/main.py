#!/usr/bin/env python3
"""
main.py  –  Point d'entrée du scanner antiviral USB / disque dur.
Nécessite les droits root (lancez avec sudo ou en tant que root).
"""

import os
import sys
import tkinter as tk
from tkinter import messagebox

from gui import VirusScannerGUI
from log_handler import log_info, log_error
from antivirus_manager import AntivirusManager


def main() -> None:
    # ── root check ────────────────────────────────────────────────────────────
    if os.geteuid() != 0:
        print("Ce programme doit être lancé avec les droits root (sudo).",
              file=sys.stderr)
        sys.exit(1)

    # ── at least one engine must be available ─────────────────────────────────
    av = AntivirusManager()
    clamav_ok = av.is_clamav_installed()
    avast_ok  = av.is_avast_installed()

    if not clamav_ok and not avast_ok:
        # Try to show a Tk error dialog first
        try:
            _root = tk.Tk()
            _root.withdraw()
            messagebox.showerror(
                "Aucun antivirus installé",
                "Ni ClamAV ni Avast n'est installé sur ce système.\n\n"
                "• Pour ClamAV :\n"
                "  sudo apt install clamav clamav-daemon clamav-freshclam\n\n"
                "• Pour Avast (Business / Core Security) :\n"
                "  Téléchargez le paquet depuis https://www.avast.com/\n"
                "  puis : sudo dpkg -i avast_*.deb"
            )
            _root.destroy()
        except Exception:
            pass
        print("Erreur : aucun moteur antiviral disponible.", file=sys.stderr)
        sys.exit(1)

    log_info("Démarrage du scanner antiviral USB/disque dur")
    if clamav_ok:
        log_info("ClamAV détecté")
    if avast_ok:
        log_info("Avast détecté")

    # ── launch GUI ────────────────────────────────────────────────────────────
    root = tk.Tk()
    try:
        app = VirusScannerGUI(root)
        root.mainloop()
    except Exception as e:
        error_msg = f"Erreur fatale au démarrage : {e}"
        log_error(error_msg)
        print(error_msg, file=sys.stderr)
        try:
            messagebox.showerror("Erreur fatale", error_msg)
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()