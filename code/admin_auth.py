#!/usr/bin/env python3
"""admin_auth.py – Authentification et panneau d'administration.

Onglets du panneau :
🔧 Moteurs – sélection ClamAV / Avast / YARA, mode scan, suppression
📡 Supports – affichage exhaustif de tous les supports USB
🛡 ClamAV – mise à jour base (en ligne / USB) + signatures tierces
🔐 Avast – installation, licence, base VPS
🔍 YARA – règles signature-base (GitHub / USB)
⏰ Planification – crontab freshclam
📋 Journaux – export vers USB, purge des logs
🔑 Sécurité – changement du code admin
⏻ Arrêt – poweroff de la station
🚪 Quitter – fermeture propre de l'application
"""

import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, List, Optional, Tuple

from config import (
    ADMIN_CFG_DIR,
    ADMIN_CRED_PATH,
    DEFAULT_CODE,
    MIN_CODE_LENGTH,
)
from secure_credentials import SecureCredentialStore

# ── Commandes planifiées ──────────────────────────────────────────────────────
FRESHCLAM_CMD = (
    "freshclam --datadir=/var/lib/clamav "
    ">> /var/log/virusscanner_auto.log 2>&1"
)
THIRDPARTY_CMD = (
    "python3 -c \"from db_manager import DBManager; "
    "DBManager(None).download_third_party_sigs()\" "
    ">> /var/log/virusscanner_auto.log 2>&1"
)
AVAST_UPDATE_CMD = (
    "avast update "
    ">> /var/log/virusscanner_auto.log 2>&1"
)
YARA_UPDATE_CMD = (
    "python3 -c \"from db_manager import DBManager; "
    "DBManager(None).update_yara_online()\" "
    ">> /var/log/virusscanner_auto.log 2>&1"
)

_CRON_TASKS: dict = {
    "clamav": ("# virusscanner_clamav", FRESHCLAM_CMD),
    "thirdparty": ("# virusscanner_thirdparty", THIRDPARTY_CMD),
    "avast": ("# virusscanner_avast", AVAST_UPDATE_CMD),
    "yara": ("# virusscanner_yara", YARA_UPDATE_CMD),
}


# ══════════════════════════════════════════════════════════════════════════════
class AdminAuthManager:
    _CRON_TAG = "# virusscanner_auto"  # tag legacy (compatibilité)

    def __init__(self) -> None:
        os.makedirs(ADMIN_CFG_DIR, exist_ok=True)
        self._store = SecureCredentialStore(
            path=ADMIN_CRED_PATH,
            default_password=DEFAULT_CODE,
        )

    def verify(self, code: str) -> bool:
        ok, _wait = self._store.verify(code.strip())
        return ok

    def verify_with_wait(self, code: str) -> Tuple[bool, int]:
        return self._store.verify(code.strip())

    def is_default_code(self) -> bool:
        return self._store.is_default_password(DEFAULT_CODE)

    def change_code(self, old: str, new: str, confirm: str) -> Tuple[bool, str]:
        old = old.strip()
        new = new.strip()
        confirm = confirm.strip()

        if new != confirm:
            return False, "La confirmation ne correspond pas."
        if len(new) < MIN_CODE_LENGTH:
            return False, f"Le code doit comporter au moins {MIN_CODE_LENGTH} caractères."
        if new == DEFAULT_CODE:
            return False, f"'{DEFAULT_CODE}' est le code par défaut — choisissez-en un autre."

        return self._store.change_password(old, new)

    def get_cron_schedule(self) -> Optional[str]:
        """Retourne la planification ClamAV (legacy, pour compatibilité)."""
        return self.get_cron_task("clamav")

    def get_cron_task(self, task: str) -> Optional[str]:
        """Retourne l'expression cron d'une tâche, ou None si désactivée."""
        tag = _CRON_TASKS.get(task, (None, None))[0]
        if not tag:
            return None
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
            )
            for line in result.stdout.splitlines():
                if tag in line:
                    return line.split(tag)[0].strip()
        except Exception:
            pass
        return None

    def get_all_cron_tasks(self) -> dict:
        """Retourne un dict {task_key: cron_expr_or_None} pour toutes les tâches."""
        return {key: self.get_cron_task(key) for key in _CRON_TASKS}

    def set_cron_schedule(self, cron_expr: Optional[str]) -> Tuple[bool, str]:
        """Définit la planification ClamAV (legacy, pour compatibilité)."""
        return self.set_cron_task("clamav", cron_expr)

    def set_cron_task(self, task: str, cron_expr: Optional[str]) -> Tuple[bool, str]:
        """Définit ou supprime la planification d'une tâche."""
        entry = _CRON_TASKS.get(task)
        if not entry:
            return False, f"Tâche inconnue : {task}"

        tag, cmd = entry
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
            )
            existing = result.stdout if result.returncode == 0 else ""

            lines = [
                line
                for line in existing.splitlines()
                if tag not in line and self._CRON_TAG not in line
            ]

            if cron_expr:
                lines.append(f"{cron_expr} {cmd} {tag}")

            new_cron = "\n".join(lines) + "\n"

            proc = subprocess.run(
                ["crontab", "-"],
                input=new_cron,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                return True, (
                    "Planification définie."
                    if cron_expr
                    else "Planification supprimée."
                )
            return False, f"Erreur crontab : {proc.stderr.strip()}"
        except Exception as exc:
            return False, f"Impossible de modifier la crontab : {exc}"


# ══════════════════════════════════════════════════════════════════════════════
# Dialog saisie code
# ══════════════════════════════════════════════════════════════════════════════

def ask_admin_code(
    parent: tk.Misc,
    prompt: str = "Code administrateur :",
) -> Optional[str]:
    result: List[Optional[str]] = [None]

    dlg = tk.Toplevel(parent)
    dlg.title("🔒 Authentification")
    dlg.resizable(False, False)
    dlg.grab_set()
    dlg.transient(parent)

    w, h = 340, 190
    px = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
    py = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
    dlg.geometry(f"{w}x{h}+{px}+{py}")

    frm = ttk.Frame(dlg, padding=20)
    frm.pack(fill=tk.BOTH, expand=True)

    ttk.Label(
        frm,
        text=prompt,
        font=("Arial", 10, "bold"),
        wraplength=290,
        justify=tk.CENTER,
    ).pack(pady=(0, 10))

    code_var = tk.StringVar()
    entry = ttk.Entry(
        frm,
        textvariable=code_var,
        show="●",
        width=16,
        font=("Arial", 15),
        justify=tk.CENTER,
    )
    entry.pack(pady=4)
    entry.focus_set()

    def _ok(_=None) -> None:
        result[0] = code_var.get()
        dlg.destroy()

    def _cancel() -> None:
        dlg.destroy()

    row = ttk.Frame(frm)
    row.pack(pady=12)
    ttk.Button(row, text="✓ Valider", command=_ok, width=11).pack(
        side=tk.LEFT, padx=5
    )
    ttk.Button(row, text="✕ Annuler", command=_cancel, width=11).pack(
        side=tk.LEFT, padx=5
    )

    entry.bind("<Return>", _ok)
    dlg.protocol("WM_DELETE_WINDOW", _cancel)
    dlg.wait_window()
    return result[0]


# ══════════════════════════════════════════════════════════════════════════════
# Panneau d'administration
# ══════════════════════════════════════════════════════════════════════════════

class AdminPanel:
    """Panneau d'administration modal, accessible après saisie du code."""

    def __init__(
        self,
        parent: tk.Misc,
        auth: AdminAuthManager,
        use_clamav_var: tk.BooleanVar,
        use_avast_var: tk.BooleanVar,
        use_yara_var: tk.BooleanVar,
        scan_mode_var: tk.StringVar,
        remove_var: tk.BooleanVar,
        on_update_clamav_online: Callable,
        on_import_clamav_usb: Callable,
        on_download_third_party_sigs: Callable,
        on_install_avast: Callable,
        on_update_avast_vps_online: Callable,
        on_import_avast_vps_usb: Callable,
        on_import_avast_license_usb: Callable,
        on_import_avast_license_file: Callable,
        on_activate_avast_code: Callable,
        on_refresh_avast_status: Callable,
        on_update_yara_online: Callable,
        on_import_yara_usb: Callable,
        on_export_logs_usb: Callable,
        on_purge_logs: Callable,
        on_purge_threats: Callable,
        on_purge_counters: Callable,
        on_poweroff: Callable,
        on_quit: Callable,
        get_usb_partitions: Callable,
        refresh_usb: Callable,
        pdf_dir: str,
        on_pdf_reload_viewer: Callable,
        get_scan_stats: Callable,
    ) -> None:
        self._parent = parent
        self._auth = auth

        self._use_clamav = use_clamav_var
        self._use_avast = use_avast_var
        self._use_yara = use_yara_var
        self._scan_mode = scan_mode_var
        self._remove = remove_var

        self._cb = {
            "clamav_online": on_update_clamav_online,
            "clamav_usb": on_import_clamav_usb,
            "clamav_thirdparty": on_download_third_party_sigs,
            "avast_install": on_install_avast,
            "avast_vps_online": on_update_avast_vps_online,
            "avast_vps_usb": on_import_avast_vps_usb,
            "avast_license_usb": on_import_avast_license_usb,
            "avast_license_file": on_import_avast_license_file,
            "avast_activate": on_activate_avast_code,
            "avast_refresh": on_refresh_avast_status,
            "yara_online": on_update_yara_online,
            "yara_usb": on_import_yara_usb,
            "export_logs_usb": on_export_logs_usb,
            "purge_logs": on_purge_logs,
            "purge_threats": on_purge_threats,
            "purge_counters": on_purge_counters,
            "poweroff": on_poweroff,
            "quit": on_quit,
        }

        self._app_dir = os.path.dirname(os.path.abspath(__file__))
        self._get_usb_partitions = get_usb_partitions
        self._refresh_usb = refresh_usb
        self._pdf_dir = pdf_dir
        self._on_pdf_reload = on_pdf_reload_viewer
        self._get_scan_stats = get_scan_stats

    def show(self) -> None:
        code = ask_admin_code(
            self._parent,
            prompt="Entrez le code administrateur\npour accéder au panneau :",
        )
        if code is None:
            return

        ok, wait = self._auth.verify_with_wait(code)
        if wait > 0:
            messagebox.showerror(
                "Accès refusé",
                f"Trop de tentatives. Réessayez dans {wait} seconde(s).",
                parent=self._parent,
            )
            return

        if not ok:
            messagebox.showerror(
                "Accès refusé",
                "Code incorrect.",
                parent=self._parent,
            )
            return

        if self._auth.is_default_code():
            messagebox.showwarning(
                "Code par défaut",
                "⚠ Le code est toujours '0000'.\n"
                "Changez-le dans l'onglet 'Sécurité'.",
                parent=self._parent,
            )

        self._open()

    def _open(self) -> None:
        dlg = tk.Toplevel(self._parent)
        dlg.title("⚙ Panneau d'administration")
        dlg.attributes("-fullscreen", True)
        dlg.grab_set()
        dlg.transient(self._parent)

        top_bar = tk.Frame(dlg, bg="#0f3460", pady=6)
        top_bar.pack(fill=tk.X)

        tk.Label(
            top_bar,
            text="⚙ Panneau d'administration",
            font=("Arial", 13, "bold"),
            bg="#0f3460",
            fg="#e0e0e0",
        ).pack(side=tk.LEFT, padx=14)

        tk.Button(
            top_bar,
            text="✕ Fermer",
            command=dlg.destroy,
            bg="#e94560",
            fg="white",
            relief=tk.FLAT,
            font=("Arial", 10, "bold"),
            padx=14,
            pady=2,
            cursor="hand2",
        ).pack(side=tk.RIGHT, padx=10)

        nb = ttk.Notebook(dlg)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self._tab_engines(nb)
        self._tab_usb_detail(nb, dlg)
        self._tab_clamav(nb)
        self._tab_avast(nb)
        self._tab_yara(nb)
        self._tab_cron(nb)
        self._tab_pdf(nb, dlg)
        self._tab_logs(nb)
        self._tab_system(nb)
        self._tab_security(nb)
        self._tab_poweroff(nb, dlg)
        self._tab_quit(nb, dlg)