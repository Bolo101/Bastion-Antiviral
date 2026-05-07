#!/usr/bin/env python3
"""admin_auth.py – Authentification et panneau d'administration.

Onglets du panneau :
  🔧 Moteurs      – sélection ClamAV / Avast / YARA, mode scan, suppression
  📡 Supports     – affichage exhaustif de tous les supports USB
  🛡 ClamAV       – mise à jour base (en ligne / USB) + signatures tierces
  🔐 Avast        – installation, licence, base VPS
  🔍 YARA         – règles signature-base (GitHub / USB)
  ⏰ Planification – crontab freshclam
  📋 Journaux     – export vers USB, purge des logs
  🔑 Sécurité     – changement du code admin
  ⏻  Arrêt        – poweroff de la station
  🚪 Quitter      – fermeture propre de l'application
"""

import hashlib
import json
import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, List, Optional, Tuple

from config import ADMIN_CFG_DIR, ADMIN_CFG_PATH

DEFAULT_CODE    = "0000"
MIN_CODE_LENGTH = 4

# ── Commandes planifiées ──────────────────────────────────────────────────────
FRESHCLAM_CMD    = ("freshclam --datadir=/var/lib/clamav "
                    ">> /var/log/virusscanner_auto.log 2>&1")
THIRDPARTY_CMD   = ("python3 -c \"from db_manager import DBManager; "
                    "DBManager(None).download_third_party_sigs()\" "
                    ">> /var/log/virusscanner_auto.log 2>&1")
AVAST_UPDATE_CMD = ("avast update "
                    ">> /var/log/virusscanner_auto.log 2>&1")
YARA_UPDATE_CMD  = ("python3 -c \"from db_manager import DBManager; "
                    "DBManager(None).update_yara_online()\" "
                    ">> /var/log/virusscanner_auto.log 2>&1")

_CRON_TASKS: dict = {
    "clamav":     ("# virusscanner_clamav",     FRESHCLAM_CMD),
    "thirdparty": ("# virusscanner_thirdparty",  THIRDPARTY_CMD),
    "avast":      ("# virusscanner_avast",       AVAST_UPDATE_CMD),
    "yara":       ("# virusscanner_yara",        YARA_UPDATE_CMD),
}


# ══════════════════════════════════════════════════════════════════════════════
class AdminAuthManager:

    @staticmethod
    def _hash(code: str) -> str:
        return hashlib.sha256(code.strip().encode()).hexdigest()

    def __init__(self) -> None:
        self._ensure_config()

    def _ensure_config(self) -> None:
        if not os.path.exists(ADMIN_CFG_PATH):
            try:
                os.makedirs(ADMIN_CFG_DIR, exist_ok=True)
                self._save({"code_hash": self._hash(DEFAULT_CODE)})
            except Exception:
                pass

    def _load(self) -> dict:
        try:
            with open(ADMIN_CFG_PATH) as f:
                return json.load(f)
        except Exception:
            return {"code_hash": self._hash(DEFAULT_CODE)}

    def _save(self, data: dict) -> None:
        os.makedirs(ADMIN_CFG_DIR, exist_ok=True)
        with open(ADMIN_CFG_PATH, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(ADMIN_CFG_PATH, 0o600)

    def verify(self, code: str) -> bool:
        return self._hash(code) == self._load().get("code_hash", "")

    def is_default_code(self) -> bool:
        return self.verify(DEFAULT_CODE)

    def change_code(self, old: str, new: str, confirm: str) -> Tuple[bool, str]:
        if not self.verify(old):
            return False, "Code actuel incorrect."
        if len(new) < MIN_CODE_LENGTH:
            return False, f"Le code doit comporter au moins {MIN_CODE_LENGTH} caractères."
        if new != confirm:
            return False, "La confirmation ne correspond pas."
        if new == DEFAULT_CODE:
            return False, f"'{DEFAULT_CODE}' est le code par défaut — choisissez-en un autre."
        try:
            self._save({"code_hash": self._hash(new)})
            return True, "Code administrateur modifié avec succès."
        except Exception as e:
            return False, f"Erreur lors de la sauvegarde : {e}"

    _CRON_TAG = "# virusscanner_auto"   # tag legacy (compatibilité)

    def get_cron_schedule(self) -> Optional[str]:
        """Retourne la planification ClamAV (legacy, pour compatibilité)."""
        return self.get_cron_task("clamav")

    def get_cron_task(self, task: str) -> Optional[str]:
        """Retourne l'expression cron d'une tâche, ou None si désactivée."""
        tag = _CRON_TASKS.get(task, (None, None))[0]
        if not tag:
            return None
        try:
            r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
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
            r        = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            existing = r.stdout if r.returncode == 0 else ""
            # Supprimer aussi l'éventuelle entrée legacy
            lines    = [l for l in existing.splitlines()
                        if tag not in l and self._CRON_TAG not in l]
            if cron_expr:
                lines.append(f"{cron_expr} {cmd} {tag}")
            new_cron = "\n".join(lines) + "\n"
            proc = subprocess.run(["crontab", "-"], input=new_cron,
                                   capture_output=True, text=True)
            if proc.returncode == 0:
                return True, ("Planification définie." if cron_expr
                              else "Planification supprimée.")
            return False, f"Erreur crontab : {proc.stderr.strip()}"
        except Exception as e:
            return False, f"Impossible de modifier la crontab : {e}"


# ══════════════════════════════════════════════════════════════════════════════
# Dialog saisie code
# ══════════════════════════════════════════════════════════════════════════════

def ask_admin_code(parent: tk.Misc,
                   prompt: str = "Code administrateur :") -> Optional[str]:
    result: List[Optional[str]] = [None]

    dlg = tk.Toplevel(parent)
    dlg.title("🔒 Authentification")
    dlg.resizable(False, False)
    dlg.grab_set()
    dlg.transient(parent)

    w, h = 340, 190
    px = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
    py = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
    dlg.geometry(f"{w}x{h}+{px}+{py}")

    frm = ttk.Frame(dlg, padding=20)
    frm.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frm, text=prompt, font=("Arial", 10, "bold"),
              wraplength=290, justify=tk.CENTER).pack(pady=(0, 10))

    code_var = tk.StringVar()
    entry    = ttk.Entry(frm, textvariable=code_var, show="●",
                         width=16, font=("Arial", 15), justify=tk.CENTER)
    entry.pack(pady=4)
    entry.focus_set()

    def _ok(_=None) -> None:
        result[0] = code_var.get()
        dlg.destroy()

    def _cancel() -> None:
        dlg.destroy()

    row = ttk.Frame(frm)
    row.pack(pady=12)
    ttk.Button(row, text="✓ Valider",  command=_ok,     width=11).pack(side=tk.LEFT, padx=5)
    ttk.Button(row, text="✕ Annuler", command=_cancel,  width=11).pack(side=tk.LEFT, padx=5)

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
        auth:   AdminAuthManager,
        # Options moteurs (BooleanVar / StringVar partagées avec la GUI)
        use_clamav_var: tk.BooleanVar,
        use_avast_var:  tk.BooleanVar,
        use_yara_var:   tk.BooleanVar,
        scan_mode_var:  tk.StringVar,
        remove_var:     tk.BooleanVar,
        # ClamAV
        on_update_clamav_online:      Callable,
        on_import_clamav_usb:         Callable,
        on_download_third_party_sigs: Callable,
        # Avast
        on_install_avast:            Callable,
        on_update_avast_vps_online:  Callable,
        on_import_avast_vps_usb:     Callable,
        on_import_avast_license_usb:  Callable,
        on_import_avast_license_file: Callable,
        on_activate_avast_code:       Callable,
        on_refresh_avast_status:      Callable,
        # YARA
        on_update_yara_online: Callable,
        on_import_yara_usb:    Callable,
        # Journaux
        on_export_logs_usb: Callable,
        on_purge_logs:      Callable,
        on_purge_threats:   Callable,
        on_purge_counters:  Callable,
        # Système
        on_poweroff: Callable,
        on_quit:     Callable,
        # Supports exhaustifs
        get_usb_partitions: Callable,
        refresh_usb:        Callable,
        # PDFs
        pdf_dir:             str,
        on_pdf_reload_viewer: Callable,
        # Statistiques
        get_scan_stats:      Callable,
    ) -> None:
        self._parent = parent
        self._auth   = auth

        # Vars partagées
        self._use_clamav = use_clamav_var
        self._use_avast  = use_avast_var
        self._use_yara   = use_yara_var
        self._scan_mode  = scan_mode_var
        self._remove     = remove_var

        self._cb = {
            "clamav_online":      on_update_clamav_online,
            "clamav_usb":         on_import_clamav_usb,
            "clamav_thirdparty":  on_download_third_party_sigs,
            "avast_install":      on_install_avast,
            "avast_vps_online":   on_update_avast_vps_online,
            "avast_vps_usb":      on_import_avast_vps_usb,
            "avast_license_usb":  on_import_avast_license_usb,
            "avast_license_file": on_import_avast_license_file,
            "avast_activate":     on_activate_avast_code,
            "avast_refresh":      on_refresh_avast_status,
            "yara_online":        on_update_yara_online,
            "yara_usb":           on_import_yara_usb,
            "export_logs_usb":    on_export_logs_usb,
            "purge_logs":         on_purge_logs,
            "purge_threats":      on_purge_threats,
            "purge_counters":     on_purge_counters,
            "poweroff":           on_poweroff,
            "quit":               on_quit,
        }
        # Répertoire de l'application (pour résoudre db_manager et autres modules)
        self._app_dir = os.path.dirname(os.path.abspath(__file__))
        self._get_usb_partitions = get_usb_partitions
        self._refresh_usb        = refresh_usb
        self._pdf_dir            = pdf_dir
        self._on_pdf_reload      = on_pdf_reload_viewer
        self._get_scan_stats     = get_scan_stats

    def show(self) -> None:
        code = ask_admin_code(
            self._parent,
            prompt="Entrez le code administrateur\npour accéder au panneau :"
        )
        if code is None:
            return
        if not self._auth.verify(code):
            messagebox.showerror("Accès refusé", "Code incorrect.",
                                 parent=self._parent)
            return
        if self._auth.is_default_code():
            messagebox.showwarning(
                "Code par défaut",
                "⚠  Le code est toujours '0000'.\n"
                "Changez-le dans l'onglet 'Sécurité'.",
                parent=self._parent
            )
        self._open()

    def _open(self) -> None:
        dlg = tk.Toplevel(self._parent)
        dlg.title("⚙  Panneau d'administration")
        dlg.attributes("-fullscreen", True)
        dlg.grab_set()
        dlg.transient(self._parent)

        # ── Barre de titre avec bouton fermer ─────────────────────────────────
        top_bar = tk.Frame(dlg, bg="#0f3460", pady=6)
        top_bar.pack(fill=tk.X)
        tk.Label(top_bar, text="⚙  Panneau d'administration",
                 font=("Arial", 13, "bold"),
                 bg="#0f3460", fg="#e0e0e0").pack(side=tk.LEFT, padx=14)
        tk.Button(top_bar, text="✕  Fermer",
                  command=dlg.destroy,
                  bg="#e94560", fg="white", relief=tk.FLAT,
                  font=("Arial", 10, "bold"), padx=14, pady=2,
                  cursor="hand2").pack(side=tk.RIGHT, padx=10)

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

    # ── Onglet Moteurs ────────────────────────────────────────────────────────

    def _tab_engines(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="🔧 Moteurs")

        ttk.Label(tab, text="Configuration des moteurs d'analyse",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 10))

        # ── Moteurs actifs ────────────────────────────────────────────────────
        eng_frm = ttk.LabelFrame(tab, text="Moteurs actifs", padding=10)
        eng_frm.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            eng_frm,
            text="Sélectionnez les moteurs utilisés lors des analyses.\n"
                 "Les moteurs non installés ou non licenciés sont automatiquement désactivés.",
            foreground="#bbbbbb"
        ).pack(anchor=tk.W, pady=(0, 8))

        chk_row = ttk.Frame(eng_frm)
        chk_row.pack(anchor=tk.W)
        ttk.Checkbutton(chk_row, text="ClamAV  (recommandé)",
                        variable=self._use_clamav).pack(side=tk.LEFT, padx=8)
        ttk.Checkbutton(chk_row, text="Avast Business",
                        variable=self._use_avast).pack(side=tk.LEFT, padx=8)
        ttk.Checkbutton(chk_row, text="YARA  (règles personnalisées)",
                        variable=self._use_yara).pack(side=tk.LEFT, padx=8)

        # ── Mode de scan ──────────────────────────────────────────────────────
        mode_frm = ttk.LabelFrame(tab, text="Mode d'analyse", padding=10)
        mode_frm.pack(fill=tk.X, pady=(0, 10))

        mode_row = ttk.Frame(mode_frm)
        mode_row.pack(anchor=tk.W)
        ttk.Radiobutton(mode_row, text="Rapide  (analyse la partition sélectionnée)",
                        variable=self._scan_mode,
                        value="quick").pack(side=tk.LEFT, padx=8)
        ttk.Radiobutton(mode_row, text="Complet  (toutes les partitions du disque)",
                        variable=self._scan_mode,
                        value="deep").pack(side=tk.LEFT, padx=8)

        # ── Suppression automatique ────────────────────────────────────────────
        del_frm = ttk.LabelFrame(tab, text="Gestion des fichiers infectés", padding=10)
        del_frm.pack(fill=tk.X)

        ttk.Label(
            del_frm,
            text="⚠  DANGER — Activez uniquement si vous voulez que les fichiers\n"
                 "    infectés soient supprimés DÉFINITIVEMENT et automatiquement.",
            foreground="#ff6b6b"
        ).pack(anchor=tk.W, pady=(0, 6))

        ttk.Checkbutton(
            del_frm,
            text="Supprimer automatiquement les fichiers infectés",
            variable=self._remove
        ).pack(anchor=tk.W)

        # ── Statut courant ────────────────────────────────────────────────────
        ttk.Separator(tab, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        ttk.Label(tab, text="Configuration actuelle :",
                  font=("Arial", 9, "bold")).pack(anchor=tk.W)

        def _refresh_summary():
            engines = " + ".join(filter(None, [
                "ClamAV" if self._use_clamav.get() else None,
                "Avast"  if self._use_avast.get()  else None,
                "YARA"   if self._use_yara.get()   else None,
            ])) or "Aucun moteur sélectionné !"
            mode  = "Rapide" if self._scan_mode.get() == "quick" else "Complet"
            suppr = "Oui ⚠" if self._remove.get() else "Non"
            summary_var.set(
                f"Moteurs : {engines}\n"
                f"Mode    : {mode}\n"
                f"Suppression auto : {suppr}"
            )

        summary_var = tk.StringVar()
        ttk.Label(tab, textvariable=summary_var,
                  foreground="#7ec8e3", font=("Courier", 9)).pack(anchor=tk.W, pady=4)
        ttk.Button(tab, text="↺  Actualiser le résumé",
                   command=_refresh_summary, width=24).pack(anchor=tk.W)
        _refresh_summary()

        # Met à jour le résumé si une case change
        for var in (self._use_clamav, self._use_avast, self._use_yara,
                    self._scan_mode, self._remove):
            var.trace_add("write", lambda *_: _refresh_summary())

    # ── Onglet Supports (affichage exhaustif) ─────────────────────────────────

    def _tab_usb_detail(self, nb: ttk.Notebook, dlg: tk.Toplevel) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="📡 Supports")

        ttk.Label(
            tab,
            text="Affichage exhaustif de tous les supports (blkid)",
            font=("Arial", 11, "bold")
        ).pack(anchor=tk.W, pady=(0, 6))

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Usb.Treeview",
            background="#101533",
            foreground="#ffffff",
            fieldbackground="#101533",
            rowheight=24,
            borderwidth=1,
            relief="solid"
        )
        style.configure(
            "Usb.Treeview.Heading",
            background="#1e2a4a",
            foreground="#e0e0e0",
            font=("Arial", 9, "bold"),
            relief="raised"
        )
        style.map(
            "Usb.Treeview",
            background=[("selected", "#2e7d32")],
            foreground=[("selected", "#ffffff")]
        )

        # ── Créer le cadre AVANT le Treeview pour qu'il soit le parent direct ──
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        cols = ("device", "label", "size", "fstype", "uuid", "partuuid",
                "mountpoint", "status")
        tree = ttk.Treeview(
            tree_frame,           # ← parent = tree_frame (correction clé)
            columns=cols,
            show="headings",
            height=4,
            selectmode="browse",
            style="Usb.Treeview"
        )

        for cid, heading, width in [
            ("device",     "Périphérique",  140),
            ("label",      "Étiquette",      90),
            ("size",       "Taille",         70),
            ("fstype",     "FS",             70),
            ("uuid",       "UUID",          160),
            ("partuuid",   "PARTUUID",      160),
            ("mountpoint", "Point montage", 130),
            ("status",     "État",          140),
        ]:
            tree.heading(cid, text=heading)
            tree.column(cid, width=width, minwidth=40, anchor=tk.W)

        tree.tag_configure("system",  background="#3a2e00", foreground="#ffd666")
        tree.tag_configure("mounted", background="#0d3320", foreground="#88e0a0")
        tree.tag_configure("unmount", background="#1e1e2e", foreground="#a0a0c0")
        tree.tag_configure("disk",    background="#1a1a3e", foreground="#9090d0")

        sb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        detail_var = tk.StringVar()
        ttk.Label(
            tab,
            textvariable=detail_var,
            font=("Courier", 8),
            foreground="#7ec8e3",
            wraplength=660,
            justify=tk.LEFT
        ).pack(anchor=tk.W, pady=4)

        def _on_select(_=None):
            sel = tree.selection()
            if not sel:
                detail_var.set("")
                return
            v = tree.item(sel[0], "values")
            detail_var.set(
                f"Périphérique : {v[0].strip()}  |  Étiquette : {v[1]}  |  "
                f"Taille : {v[2]}  |  FS : {v[3]}\n"
                f"UUID : {v[4]}\n"
                f"PARTUUID : {v[5]}\n"
                f"Point montage : {v[6]}  |  État : {v[7]}"
            )

        tree.bind("<<TreeviewSelect>>", _on_select)

        def _blkid_info() -> dict:
            info: dict = {}
            try:
                r = subprocess.run(
                    ["blkid", "-o", "export"],
                    capture_output=True,
                    text=True
                )
                current: dict = {}
                dev_key = ""
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        if dev_key:
                            info[dev_key] = current
                        current, dev_key = {}, ""
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        if k == "DEVNAME":
                            dev_key = v
                        else:
                            current[k] = v
                if dev_key:
                    info[dev_key] = current
            except Exception:
                pass
            return info

        def _system_devices() -> set:
            devs: set = set()
            try:
                import re
                with open("/proc/mounts") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2 and parts[1] == "/":
                            dev = parts[0]
                            if dev.startswith("/dev/"):
                                devs.add(dev)
                                parent = "/dev/" + re.sub(r"p?\d+$", "", dev[5:])
                                if parent != dev:
                                    devs.add(parent)
            except Exception:
                pass
            return devs

        def _populate():
            for row in tree.get_children():
                tree.delete(row)

            import json as _json

            blkid = _blkid_info()
            system = _system_devices()

            try:
                r = subprocess.run(
                    ["lsblk", "-J", "-o",
                     "NAME,LABEL,SIZE,FSTYPE,UUID,MOUNTPOINT,TYPE"],
                    capture_output=True,
                    text=True
                )
                devices = _json.loads(r.stdout).get("blockdevices", [])
            except Exception as exc:
                tree.insert(
                    "",
                    tk.END,
                    values=("—", "—", "—", "—", "—", "—", "—",
                            f"Erreur lsblk : {exc}")
                )
                return

            if not devices:
                tree.insert(
                    "",
                    tk.END,
                    values=("—", "—", "—", "—", "—", "—", "—",
                            "Aucun support détecté")
                )
                return

            def _add(dev_info: dict, indent: int = 0) -> None:
                name = dev_info.get("name", "?")
                dpath = f"/dev/{name}"
                dtype = dev_info.get("type", "")

                label = dev_info.get("label") or "—"
                size = dev_info.get("size") or "—"
                fstype = dev_info.get("fstype") or "—"
                uuid = dev_info.get("uuid") or "—"
                mountpoint = dev_info.get("mountpoint") or "—"
                partuuid = blkid.get(dpath, {}).get("PARTUUID", "—")

                is_sys = dpath in system
                if dtype == "disk":
                    tag = "disk"
                    status = "💾 Disque"
                elif mountpoint == "/":
                    tag = "system"
                    status = "⚙ Système [racine]"
                elif is_sys:
                    tag = "system"
                    status = f"⚙ Système → {mountpoint}"
                elif mountpoint != "—":
                    tag = "mounted"
                    status = f"✅ Monté → {mountpoint}"
                else:
                    tag = "unmount"
                    status = "⏏ Non monté"

                prefix = "  " * indent
                tree.insert(
                    "",
                    tk.END,
                    values=(prefix + dpath, label, size, fstype,
                            uuid, partuuid, mountpoint, status),
                    tags=(tag,)
                )

                for child in dev_info.get("children", []):
                    _add(child, indent + 1)

            for dev in devices:
                _add(dev)

        btn_row = ttk.Frame(tab)
        btn_row.pack(anchor=tk.W, pady=4)
        ttk.Button(
            btn_row,
            text="↺  Actualiser",
            command=lambda: (self._refresh_usb(), _populate()),
            width=16
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            btn_row,
            text="▲  Monter RO",
            command=lambda: self._mount_selected(tree),
            width=16
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            btn_row,
            text="▼  Démonter",
            command=lambda: self._umount_selected(tree),
            width=16
        ).pack(side=tk.LEFT, padx=4)

        legend = ttk.Frame(tab)
        legend.pack(anchor=tk.W, pady=(2, 0))
        for color, text in [
            ("#ffd666", "⚙ Disque système"),
            ("#88e0a0", "✅ Monté"),
            ("#a0a0c0", "⏏ Non monté"),
            ("#9090d0", "💾 Disque physique"),
        ]:
            ttk.Label(
                legend,
                text=text,
                foreground=color,
                font=("Arial", 8)
            ).pack(side=tk.LEFT, padx=8)

        _populate()

    def _mount_selected(self, tree: ttk.Treeview) -> None:
        sel = tree.selection()
        if not sel:
            return
        dev = tree.item(sel[0], "values")[0].strip()
        if dev in ("—", "") or not dev.startswith("/dev/"):
            return
        from usb_manager import UsbManager
        usb = UsbManager()
        ok, msg = usb.mount(dev)
        if ok:
            messagebox.showinfo("Montage", msg)
        else:
            messagebox.showerror("Montage", msg)

    def _umount_selected(self, tree: ttk.Treeview) -> None:
        sel = tree.selection()
        if not sel:
            return
        dev = tree.item(sel[0], "values")[0].strip()
        if dev in ("—", "") or not dev.startswith("/dev/"):
            return
        from usb_manager import UsbManager
        usb = UsbManager()
        ok, msg = usb.umount(dev)
        if ok:
            messagebox.showinfo("Démontage", msg)
        else:
            messagebox.showerror("Démontage", msg)
            
    # ── Onglet ClamAV ──────────────────────────────────────────────────────────

    def _tab_clamav(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="🛡 ClamAV")

        ttk.Label(tab, text="Mise à jour de la base ClamAV",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 6))

        upd_frame = ttk.LabelFrame(tab, text="Base principale", padding=8)
        upd_frame.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(
            upd_frame,
            text="En ligne : freshclam contacte les serveurs ClamAV (Internet requis).\n"
                 "Hors-ligne : copiez main.cvd, daily.cvd, bytecode.cvd sur une clé USB.",
            justify=tk.LEFT, foreground="#cccccc"
        ).pack(anchor=tk.W, pady=(0, 6))
        btn_row1 = ttk.Frame(upd_frame)
        btn_row1.pack(anchor=tk.W)

        tp_frame = ttk.LabelFrame(tab, text="Signatures tierces", padding=8)
        tp_frame.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(
            tp_frame,
            text="URLhaus (abuse.ch), Sanesecurity, InterServer…\n"
                 "Installées dans /var/lib/clamav/ — Internet requis.",
            justify=tk.LEFT, foreground="#cccccc"
        ).pack(anchor=tk.W, pady=(0, 6))
        btn_row2 = ttk.Frame(tp_frame)
        btn_row2.pack(anchor=tk.W)

        # ── Terminal mini en bas à droite ─────────────────────────────────────
        _, _, _append, _clear, status_var, _after = self._mini_terminal(tab)

        # ── Wiring des boutons ────────────────────────────────────────────────
        all_btns: list = []

        def _set_btns(state):
            for b in all_btns:
                try:
                    b.configure(state=state)
                except Exception:
                    pass

        def _do_online():
            _clear()
            self._stream_to_terminal(
                ["freshclam", "--datadir=/var/lib/clamav"],
                "ClamAV — freshclam", _append, status_var,
                set_btns_fn=_set_btns, after_fn=_after
            )

        def _do_usb():
            _append("⚙ Lancement import USB ClamAV…", "info")
            self._cb["clamav_usb"]()

        def _do_thirdparty():
            _clear()
            cmd = [
                "python3", "-c",
                "import sys; sys.path.insert(0, " + repr(self._app_dir) + "); "
                "from db_manager import DBManager; "
                "db=DBManager(None); "
                "ok,msg=db.download_third_party_sigs(); "
                "print(msg); sys.exit(0 if ok else 1)"
            ]
            self._stream_to_terminal(cmd, "Signatures tierces",
                                      _append, status_var,
                                      set_btns_fn=_set_btns, after_fn=_after)

        b1 = ttk.Button(btn_row1, text="🌐  Mise à jour en ligne (freshclam)",
                        command=_do_online, width=36)
        b1.pack(side=tk.LEFT, padx=(0, 6))
        b2 = ttk.Button(btn_row1, text="🔌  Importer depuis clé USB",
                        command=_do_usb, width=26)
        b2.pack(side=tk.LEFT)
        b3 = ttk.Button(btn_row2,
                        text="🌐  Télécharger signatures tierces",
                        command=_do_thirdparty, width=36)
        b3.pack(side=tk.LEFT)
        all_btns.extend([b1, b2, b3])

    # ── Onglet Avast ───────────────────────────────────────────────────────────

    def _tab_avast(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="🔐 Avast")

        ttk.Label(tab, text="Gestion d'Avast Business for Linux",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 6))

        # ── Statut ────────────────────────────────────────────────────────────
        status_frame = ttk.LabelFrame(tab, text="Statut", padding=8)
        status_frame.pack(fill=tk.X, pady=(0, 6))
        self._avast_status_var = tk.StringVar(value="Vérification…")
        ttk.Label(status_frame, textvariable=self._avast_status_var,
                  foreground="#7ec8e3", font=("Courier", 9)).pack(anchor=tk.W)
        ttk.Button(status_frame, text="↺  Actualiser",
                   command=self._refresh_avast_status_display,
                   width=20).pack(anchor=tk.W, pady=(4, 0))
        self._refresh_avast_status_display()

        # ── Licence ───────────────────────────────────────────────────────────
        lic_frame = ttk.LabelFrame(tab, text="Licence Business", padding=8)
        lic_frame.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(lic_frame, text="A — Fichier .avastlic depuis USB :",
                  foreground="#cccccc").grid(row=0, column=0, columnspan=3,
                                           sticky=tk.W, pady=(0, 4))
        ttk.Button(lic_frame, text="🔌  Import depuis USB",
                   command=self._cb["avast_license_usb"],
                   width=22).grid(row=1, column=0, sticky=tk.W)
        ttk.Separator(lic_frame, orient=tk.HORIZONTAL).grid(
            row=2, column=0, columnspan=3, sticky=tk.EW, pady=6)

        ttk.Label(lic_frame, text="B — Fichier .avastlic depuis le système :",
                  foreground="#cccccc").grid(row=3, column=0, columnspan=3,
                                           sticky=tk.W, pady=(0, 4))
        self._avast_lic_path_var = tk.StringVar(value="Aucun fichier sélectionné")
        ttk.Label(lic_frame, textvariable=self._avast_lic_path_var,
                  foreground="#7ec8e3", font=("Courier", 8),
                  wraplength=360).grid(row=4, column=0, columnspan=2,
                                       sticky=tk.W, pady=2)

        def _browse():
            from tkinter import filedialog
            path = filedialog.askopenfilename(
                parent=tab.winfo_toplevel(),
                title="Sélectionner la licence Avast",
                filetypes=[("Licence Avast", "*.avastlic"), ("Tous", "*.*")],
                initialdir=os.path.expanduser("~"),
            )
            if path:
                self._avast_lic_path_var.set(path)

        def _import_browsed():
            path = self._avast_lic_path_var.get()
            if not path or path == "Aucun fichier sélectionné":
                messagebox.showwarning("Aucun fichier",
                                       "Utilisez 'Parcourir…' d'abord.",
                                       parent=tab.winfo_toplevel())
                return
            if not os.path.isfile(path):
                messagebox.showerror("Fichier introuvable",
                                     f"Le fichier n'existe pas :\n{path}",
                                     parent=tab.winfo_toplevel())
                return
            self._cb["avast_license_file"](path)

        btn_row2 = ttk.Frame(lic_frame)
        btn_row2.grid(row=5, column=0, columnspan=3, sticky=tk.W, pady=(2, 0))
        ttk.Button(btn_row2, text="📂  Parcourir…",
                   command=_browse, width=16).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_row2, text="⬇  Installer",
                   command=_import_browsed, width=16).pack(side=tk.LEFT)

        # ── Base VPS ──────────────────────────────────────────────────────────
        vps_frame = ttk.LabelFrame(tab, text="Base VPS (définitions)", padding=8)
        vps_frame.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(vps_frame,
                  text="En ligne : avast update (Internet requis).\n"
                       "Hors-ligne : copiez un fichier .vps/.vpz sur une clé USB.",
                  foreground="#cccccc").pack(anchor=tk.W, pady=(0, 6))
        vps_row = ttk.Frame(vps_frame)
        vps_row.pack(anchor=tk.W)

        # ── Terminal mini en bas à droite ─────────────────────────────────────
        _, _, _append, _clear, term_status, _after = self._mini_terminal(tab, height=50)

        # ── Wiring ────────────────────────────────────────────────────────────
        all_btns: list = []

        def _set_btns(state):
            for b in all_btns:
                try:
                    b.configure(state=state)
                except Exception:
                    pass

        # VPS en ligne
        def _do_vps_online():
            _clear()
            self._stream_to_terminal(
                ["avast", "update"],
                "Mise à jour VPS Avast", _append, term_status,
                set_btns_fn=_set_btns, after_fn=_after
            )

        def _do_vps_usb():
            _append("⚙ Lancement import VPS USB…", "info")
            self._cb["avast_vps_usb"]()

        b_vps_online = ttk.Button(vps_row, text="🌐  Mise à jour VPS en ligne",
                                   command=_do_vps_online, width=28)
        b_vps_online.pack(side=tk.LEFT, padx=(0, 6))
        b_vps_usb = ttk.Button(vps_row, text="🔌  Importer VPS depuis USB",
                                command=_do_vps_usb, width=26)
        b_vps_usb.pack(side=tk.LEFT)
        all_btns.extend([b_vps_online, b_vps_usb])

    def _refresh_avast_status_display(self) -> None:
        try:
            from scanner import ScanEngine
            eng = ScanEngine()
            if not eng.is_avast_installed():
                self._avast_status_var.set(
                    "❌ Avast Business non installé\n"
                    "   → Utilisez le bouton 'Installer Avast Business' ci-dessous\n"
                    "   → Dépôt : https://repo.avcdn.net"
                )
                return
            if not eng.is_avast_licensed():
                self._avast_status_var.set(
                    "✅ Avast Business : installé\n"
                    "⚠  Licence requise — activez via les boutons ci-dessous."
                )
                return
            from config import AVAST_LICENSE_PATH
            import time as _time
            try:
                mtime = os.path.getmtime(AVAST_LICENSE_PATH)
                date  = _time.strftime("%Y-%m-%d", _time.localtime(mtime))
            except OSError:
                date = "?"
            self._avast_status_var.set(
                f"✅ Avast Business : installé et licencié\n"
                f"   Licence active depuis le : {date}"
            )
        except Exception as e:
            self._avast_status_var.set(f"Erreur vérification : {e}")

    # ══════════════════════════════════════════════════════════════════════════
    # Helpers partagés
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _mini_terminal(parent: tk.Widget, height: int = 6):
        """
        Terminal miniature ancré en bas à droite du parent.
        Retourne (frame, foot, append_fn, clear_fn, status_var, after_fn).
        """
        bottom_bar = ttk.Frame(parent)
        bottom_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 0))

        # Statut à gauche, terminal à droite
        status_var = tk.StringVar(value="Prêt.")
        ttk.Label(bottom_bar, textvariable=status_var,
                  foreground="#7ec8e3", font=("Arial", 8)).pack(side=tk.LEFT,
                                                                  padx=(0, 8))

        term_wrap = ttk.LabelFrame(bottom_bar, text="Activité", padding=2)
        term_wrap.pack(side=tk.RIGHT)

        txt = tk.Text(
            term_wrap, bg="#0b0d14", fg="#c8d0de",
            font=("Courier", 7), wrap=tk.WORD,
            state=tk.DISABLED, relief=tk.FLAT,
            height=height, width=120,
            padx=4, pady=2
        )
        sb = ttk.Scrollbar(term_wrap, orient=tk.VERTICAL, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.tag_config("ok",      foreground="#4ec94e")
        txt.tag_config("threat",  foreground="#ff4444")
        txt.tag_config("warning", foreground="#ffaa00")
        txt.tag_config("info",    foreground="#5577aa")
        txt.tag_config("normal",  foreground="#c8d0de")
        txt.pack(side=tk.LEFT)
        sb.pack(side=tk.LEFT, fill=tk.Y)

        ttk.Button(term_wrap, text="✕", width=2,
                   command=lambda: (
                       txt.configure(state=tk.NORMAL),
                       txt.delete("1.0", tk.END),
                       txt.configure(state=tk.DISABLED),
                       status_var.set("Prêt.")
                   )).pack(side=tk.LEFT, padx=(2, 0))

        def _append(line: str, tag: str = "normal") -> None:
            def _do():
                try:
                    txt.configure(state=tk.NORMAL)
                    txt.insert(tk.END, line + "\n", tag)
                    txt.see(tk.END)
                    txt.configure(state=tk.DISABLED)
                except Exception:
                    pass
            try:
                txt.after(0, _do)
            except Exception:
                pass

        def _clear() -> None:
            def _do():
                try:
                    txt.configure(state=tk.NORMAL)
                    txt.delete("1.0", tk.END)
                    txt.configure(state=tk.DISABLED)
                except Exception:
                    pass
            try:
                txt.after(0, _do)
            except Exception:
                pass

        def _after(ms: int, fn, *args):
            try:
                txt.after(ms, fn, *args)
            except Exception:
                pass

        return bottom_bar, None, _append, _clear, status_var, _after

    @staticmethod
    def _make_terminal(parent: tk.Widget, height: int = 10):
        """
        Crée un terminal Text dark dans parent.
        Retourne (frame, foot, append_fn, clear_fn, status_var, after_fn).
        append_fn et clear_fn sont thread-safe (planifiées via txt.after).
        after_fn(ms, fn, *args) permet de planifier n'importe quel appel
        sur le thread principal depuis un thread de fond.
        """
        frame = ttk.LabelFrame(parent, text="Terminal", padding=4)
        txt = tk.Text(
            frame, bg="#0b0d14", fg="#c8d0de",
            font=("Courier", 8), wrap=tk.WORD,
            state=tk.DISABLED, relief=tk.FLAT, height=height,
            padx=6, pady=4
        )
        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.tag_config("ok",      foreground="#4ec94e")
        txt.tag_config("threat",  foreground="#ff4444")
        txt.tag_config("warning", foreground="#ffaa00")
        txt.tag_config("info",    foreground="#5577aa")
        txt.tag_config("normal",  foreground="#c8d0de")
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        status_var = tk.StringVar(value="Prêt.")
        foot = ttk.Frame(parent)
        ttk.Label(foot, textvariable=status_var,
                  foreground="#7ec8e3", font=("Arial", 8)).pack(side=tk.LEFT)

        # ── Fonctions thread-safe ─────────────────────────────────────────────
        def _append(line: str, tag: str = "normal") -> None:
            def _do():
                try:
                    txt.configure(state=tk.NORMAL)
                    txt.insert(tk.END, line + "\n", tag)
                    txt.see(tk.END)
                    txt.configure(state=tk.DISABLED)
                except Exception:
                    pass
            try:
                txt.after(0, _do)
            except Exception:
                pass

        def _clear() -> None:
            def _do():
                try:
                    txt.configure(state=tk.NORMAL)
                    txt.delete("1.0", tk.END)
                    txt.configure(state=tk.DISABLED)
                except Exception:
                    pass
            try:
                txt.after(0, _do)
            except Exception:
                pass

        def _after(ms: int, fn, *args):
            """Planifie fn(*args) sur le thread principal depuis n'importe quel thread."""
            try:
                txt.after(ms, fn, *args)
            except Exception:
                pass

        ttk.Button(foot, text="🧹 Vider", command=_clear,
                   width=9).pack(side=tk.RIGHT)

        return frame, foot, _append, _clear, status_var, _after

    def _stream_to_terminal(self, cmd: list, label: str,
                             append_fn, status_var,
                             set_btns_fn=None, on_done=None,
                             after_fn=None) -> None:
        """Lance cmd en streaming dans le terminal fourni via append_fn.
        after_fn : planificateur thread-safe (issu de _make_terminal).
        """
        import threading as _th

        def _schedule(fn, *args):
            """Appelle fn(*args) en planifiant sur le thread principal si possible."""
            if after_fn:
                after_fn(0, fn, *args)
            else:
                try:
                    fn(*args)
                except Exception:
                    pass

        def _worker():
            _schedule(status_var.set, f"⏳ {label}…")
            append_fn(f"▶ {label}", "info")
            append_fn(f"$ {' '.join(cmd)}", "info")
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                for raw in proc.stdout:
                    line = raw.rstrip()
                    if not line:
                        continue
                    low = line.lower()
                    if any(w in low for w in ("error", "erreur", "failed",
                                              "fail", "infect")):
                        tag = "threat"
                    elif any(w in low for w in ("warning", "warn", "attention")):
                        tag = "warning"
                    elif any(w in low for w in ("ok", "done", "succès",
                                                 "upgraded", "installed",
                                                 "nothing to do",
                                                 "up-to-date", "à jour")):
                        tag = "ok"
                    else:
                        tag = "normal"
                    append_fn(line, tag)
                proc.wait()
                rc = proc.returncode
                if rc == 0:
                    append_fn(f"✅ {label} terminé.", "ok")
                    _schedule(status_var.set, f"✅ {label} terminé.")
                else:
                    append_fn(f"⚠ {label} — code retour {rc}.", "warning")
                    _schedule(status_var.set, f"⚠ {label} — code {rc}.")
                if on_done:
                    _schedule(on_done, rc)
            except Exception as exc:
                append_fn(f"❌ {exc}", "threat")
                _schedule(status_var.set, f"❌ Erreur : {exc}")
            finally:
                if set_btns_fn:
                    _schedule(set_btns_fn, tk.NORMAL)

        if set_btns_fn:
            set_btns_fn(tk.DISABLED)
        _th.Thread(target=_worker, daemon=True).start()

    # ── Onglet YARA ────────────────────────────────────────────────────────────

    def _tab_yara(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="🔍 YARA")

        ttk.Label(tab, text="Gestion des règles YARA",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 6))

        ctrl_frame = ttk.LabelFrame(tab, text="Règles signature-base", padding=8)
        ctrl_frame.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(
            ctrl_frame,
            text="En ligne  : télécharge signature-base de Florian Roth (GitHub) — ~30 Mo.\n"
                 "Hors-ligne : placez des fichiers .yar/.yara ou un .zip sur une clé USB.",
            justify=tk.LEFT, foreground="#cccccc"
        ).pack(anchor=tk.W, pady=(0, 8))
        btn_row = ttk.Frame(ctrl_frame)
        btn_row.pack(anchor=tk.W)

        # ── Terminal mini en bas à droite ─────────────────────────────────────
        _, _, _append, _clear, status_var, _after = self._mini_terminal(tab)

        all_btns: list = []

        def _set_btns(state):
            for b in all_btns:
                try:
                    b.configure(state=state)
                except Exception:
                    pass

        def _do_online():
            _clear()
            cmd = [
                "python3", "-c",
                "import sys; sys.path.insert(0, " + repr(self._app_dir) + "); "
                "from db_manager import DBManager; "
                "db=DBManager(None); "
                "ok,msg=db.update_yara_online(); "
                "print(msg); sys.exit(0 if ok else 1)"
            ]
            self._stream_to_terminal(cmd, "YARA — téléchargement signature-base",
                                      _append, status_var, set_btns_fn=_set_btns, after_fn=_after)

        def _do_usb():
            _append("⚙ Lancement import USB YARA…", "info")
            self._cb["yara_usb"]()

        b_online = ttk.Button(btn_row, text="🌐  Télécharger signature-base",
                              command=_do_online, width=30)
        b_online.pack(side=tk.LEFT, padx=(0, 6))
        b_usb = ttk.Button(btn_row, text="🔌  Importer depuis clé USB",
                           command=_do_usb, width=28)
        b_usb.pack(side=tk.LEFT)
        all_btns.extend([b_online, b_usb])

    # ── Onglet Planification ───────────────────────────────────────────────────

    def _tab_cron(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="⏰ Planification")

        auth = self._auth

        ttk.Label(tab,
                  text="Mise à jour automatique (crontab)",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 4))
        ttk.Label(tab,
                  text="Configurez indépendamment chaque tâche de mise à jour.\n"
                       "Chaque tâche possède sa propre fréquence et son heure d'exécution.",
                  foreground="#cccccc").pack(anchor=tk.W, pady=(0, 10))

        ttk.Separator(tab, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 10))

        _TASK_LABELS = [
            ("clamav",      "🛡  ClamAV",             "freshclam — base de signatures virale"),
            ("thirdparty",  "🌐  Signatures tierces",  "URLhaus, Sanesecurity, InterServer…"),
            ("avast",       "🔐  Avast VPS",           "Base de définitions Avast Business"),
            ("yara",        "🔍  YARA",                "Règles signature-base (Florian Roth / GitHub)"),
        ]

        current_schedules = auth.get_all_cron_tasks()

        # Canvas + scrollbar pour que les 4 cadres tiennent en plein écran
        canvas_frame = ttk.Frame(tab)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        scroll_canvas = tk.Canvas(canvas_frame, highlightthickness=0)
        vsb = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL,
                             command=scroll_canvas.yview)
        scroll_canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        scroll_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        inner = ttk.Frame(scroll_canvas)
        win_id = scroll_canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: (
            scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all")),
            scroll_canvas.itemconfig(win_id, width=scroll_canvas.winfo_width())
        ))
        scroll_canvas.bind("<Configure>",
                           lambda e: scroll_canvas.itemconfig(win_id, width=e.width))

        for task_key, task_name, task_desc in _TASK_LABELS:
            current = current_schedules.get(task_key)

            frm = ttk.LabelFrame(inner,
                                  text=f"{task_name}  —  {task_desc}",
                                  padding=10)
            frm.pack(fill=tk.X, pady=(0, 12), padx=4)

            cur_text = (f"Planification active : {current}"
                        if current else "⏸  Désactivée")
            cur_var = tk.StringVar(value=cur_text)
            ttk.Label(frm, textvariable=cur_var,
                      foreground="#7ec8e3").pack(anchor=tk.W, pady=(0, 6))

            ctrl_row = ttk.Frame(frm)
            ctrl_row.pack(anchor=tk.W)

            ttk.Label(ctrl_row, text="Fréquence :").pack(side=tk.LEFT, padx=(0, 6))
            freq_var = tk.StringVar(value="daily")
            ttk.Radiobutton(ctrl_row, text="Quotidienne",
                            variable=freq_var, value="daily").pack(side=tk.LEFT, padx=4)
            ttk.Radiobutton(ctrl_row, text="Hebdomadaire (lundi)",
                            variable=freq_var, value="weekly").pack(side=tk.LEFT, padx=4)
            ttk.Label(ctrl_row, text="  Heure (0-23) :").pack(side=tk.LEFT, padx=(10, 4))
            hour_var = tk.StringVar(value="2")
            ttk.Spinbox(ctrl_row, from_=0, to=23, textvariable=hour_var,
                        width=5, format="%02.0f").pack(side=tk.LEFT)

            if current:
                parts = current.split()
                if len(parts) >= 2:
                    try:
                        hour_var.set(str(int(parts[1])))
                    except ValueError:
                        pass
                if len(parts) >= 5 and parts[4] == "1":
                    freq_var.set("weekly")

            sv = tk.StringVar()
            sl = ttk.Label(frm, textvariable=sv, wraplength=560)
            sl.pack(anchor=tk.W, pady=(4, 0))

            def _make_apply(tk=task_key, fv=freq_var, hv=hour_var,
                             cv=cur_var, sv=sv, sl=sl):
                def _apply():
                    try:
                        h = int(hv.get())
                        assert 0 <= h <= 23
                    except Exception:
                        sv.set("❌ Heure invalide (0-23)")
                        sl.configure(foreground="#ff6b6b")
                        return
                    expr = f"0 {h} * * *" if fv.get() == "daily" else f"0 {h} * * 1"
                    ok, msg = auth.set_cron_task(tk, expr)
                    sl.configure(foreground="#66cc66" if ok else "#ff6b6b")
                    sv.set(("✅ " if ok else "❌ ") + msg)
                    if ok:
                        cv.set(f"Planification active : {expr}")
                return _apply

            def _make_remove(tk=task_key, cv=cur_var, sv=sv, sl=sl):
                def _remove():
                    ok, msg = auth.set_cron_task(tk, None)
                    sl.configure(foreground="#66cc66" if ok else "#ff6b6b")
                    sv.set(("✅ " if ok else "❌ ") + msg)
                    if ok:
                        cv.set("⏸  Désactivée")
                return _remove

            btn_row = ttk.Frame(frm)
            btn_row.pack(anchor=tk.W, pady=(6, 0))
            ttk.Button(btn_row, text="✓ Appliquer",
                       command=_make_apply(),
                       width=16).pack(side=tk.LEFT, padx=(0, 6))
            ttk.Button(btn_row, text="🗑 Désactiver",
                       command=_make_remove(),
                       width=16).pack(side=tk.LEFT)

    # ── Onglet PDFs ────────────────────────────────────────────────────────────

    def _tab_pdf(self, nb: ttk.Notebook, dlg: tk.Toplevel) -> None:
        """Onglet de gestion des PDFs affichés en boucle sur l'interface."""
        _outer = ttk.Frame(nb)
        nb.add(_outer, text="📄 PDFs")

        # ── Canvas scrollable pour que tous les boutons soient accessibles ────
        _canvas = tk.Canvas(_outer, highlightthickness=0)
        _vsb    = ttk.Scrollbar(_outer, orient=tk.VERTICAL, command=_canvas.yview)
        _canvas.configure(yscrollcommand=_vsb.set)
        _vsb.pack(side=tk.RIGHT, fill=tk.Y)
        _canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tab = ttk.Frame(_canvas, padding=10)
        _win = _canvas.create_window((0, 0), window=tab, anchor="nw")
        tab.bind("<Configure>", lambda e: (
            _canvas.configure(scrollregion=_canvas.bbox("all")),
            _canvas.itemconfig(_win, width=_canvas.winfo_width())
        ))
        _canvas.bind("<Configure>",
                     lambda e: _canvas.itemconfig(_win, width=e.width))
        # Molette souris
        _canvas.bind_all("<MouseWheel>",
                         lambda e: _canvas.yview_scroll(-1*(e.delta//120), "units"))

        ttk.Label(tab, text="Gestion des PDFs de la visionneuse",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 6))

        pdf_dir = self._pdf_dir

        # ── Liste des PDFs présents dans ../pdf/ ──────────────────────────────
        list_frame = ttk.LabelFrame(tab, text=f"PDFs dans {pdf_dir}", padding=8)
        list_frame.pack(fill=tk.X, pady=(0, 8))

        cols = ("name", "size")
        tree = ttk.Treeview(list_frame, columns=cols, show="headings",
                            height=4, selectmode="extended")
        tree.heading("name", text="Fichier")
        tree.heading("size", text="Taille")
        tree.column("name", width=360, anchor=tk.W)
        tree.column("size", width=80,  anchor=tk.CENTER)
        sb_tree = ttk.Scrollbar(list_frame, orient=tk.VERTICAL,
                                command=tree.yview)
        tree.configure(yscrollcommand=sb_tree.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_tree.pack(side=tk.RIGHT, fill=tk.Y)

        status_var = tk.StringVar()
        ttk.Label(tab, textvariable=status_var,
                  foreground="#7ec8e3", wraplength=520).pack(anchor=tk.W, pady=2)

        def _refresh_list():
            for row in tree.get_children():
                tree.delete(row)
            try:
                os.makedirs(pdf_dir, exist_ok=True)
                files = sorted(
                    (f for f in os.listdir(pdf_dir)
                     if f.lower().endswith(".pdf")),
                    key=str.casefold
                )
                for fname in files:
                    fpath = os.path.join(pdf_dir, fname)
                    try:
                        sz = os.path.getsize(fpath)
                        sz_str = (f"{sz // 1024} Ko" if sz >= 1024
                                  else f"{sz} o")
                    except OSError:
                        sz_str = "?"
                    tree.insert("", tk.END, iid=fpath,
                                values=(fname, sz_str))
                count = len(files)
                status_var.set(f"{count} PDF(s) présent(s).")
            except Exception as e:
                status_var.set(f"Erreur lecture dossier : {e}")

        _refresh_list()

        # ── Boutons de gestion des PDFs locaux ────────────────────────────────
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, pady=(0, 8))

        def _delete_selected():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Aucune sélection",
                                       "Sélectionnez au moins un PDF.",
                                       parent=dlg)
                return
            names = "\n".join(f"• {os.path.basename(p)}" for p in sel)
            if not messagebox.askyesno(
                "Confirmer la suppression",
                f"Supprimer définitivement :\n{names}",
                icon="warning", parent=dlg
            ):
                return
            errors = []
            for fpath in sel:
                try:
                    os.remove(fpath)
                except Exception as e:
                    errors.append(f"{os.path.basename(fpath)}: {e}")
            if errors:
                messagebox.showerror("Erreurs",
                                     "\n".join(errors), parent=dlg)
            else:
                status_var.set(f"✅ {len(sel)} fichier(s) supprimé(s).")
            _refresh_list()
            self._on_pdf_reload()

        ttk.Button(btn_frame, text="🗑  Supprimer sélection",
                   command=_delete_selected,
                   width=24).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_frame, text="↺  Actualiser",
                   command=_refresh_list,
                   width=14).pack(side=tk.LEFT)

        # ── Import depuis clé USB ──────────────────────────────────────────────
        usb_frame = ttk.LabelFrame(tab, text="Importer des PDFs depuis une clé USB",
                                   padding=10)
        usb_frame.pack(fill=tk.X)

        # ── Ligne 1 : sélection de la partition + montage ─────────────────────
        r1 = ttk.Frame(usb_frame); r1.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(r1, text="Partition USB :", width=14).pack(side=tk.LEFT)
        usb_var = tk.StringVar(value="— sélectionner —")
        usb_combo = ttk.Combobox(r1, textvariable=usb_var,
                                  state="readonly", width=26)
        usb_combo.pack(side=tk.LEFT, padx=4)

        _mp_holder: list = [None]   # point de montage actif
        usb_status_var = tk.StringVar()

        def _refresh_usb_combo():
            parts = self._get_usb_partitions()
            names = [p.device + (f"  [{p.label}]" if p.label else "")
                     for p in parts]
            usb_combo["values"] = names
            if names:
                usb_combo.current(0)
            else:
                usb_var.set("— aucune clé détectée —")

        ttk.Button(r1, text="↺", width=3,
                   command=_refresh_usb_combo).pack(side=tk.LEFT, padx=2)
        _refresh_usb_combo()

        def _mount_usb_pdf():
            parts = self._get_usb_partitions()
            idx   = usb_combo.current()
            if idx < 0 or idx >= len(parts):
                usb_status_var.set("⚠ Sélectionnez une clé USB valide.")
                return
            part = parts[idx]
            # Déjà monté ?
            existing_mp = None
            try:
                with open("/proc/mounts") as f:
                    for line in f:
                        tok = line.split()
                        if len(tok) >= 2 and tok[0] == part.device:
                            existing_mp = tok[1]
                            break
            except Exception:
                pass
            if existing_mp:
                _mp_holder[0] = existing_mp
                usb_status_var.set(f"✅ Déjà monté → {existing_mp}")
                _populate_usb_tree()
                return
            try:
                mp = f"/mnt/pdf_import_{part.device.replace('/', '_')}"
                os.makedirs(mp, exist_ok=True)
                r = subprocess.run(["mount", "-o", "ro", part.device, mp],
                                   capture_output=True, text=True)
                if r.returncode != 0:
                    usb_status_var.set(f"❌ mount : {r.stderr.strip()[:80]}")
                    return
                _mp_holder[0] = mp
                usb_status_var.set(f"✅ Monté en lecture seule → {mp}")
                _populate_usb_tree()
            except Exception as e:
                usb_status_var.set(f"❌ {e}")

        def _umount_usb_pdf():
            mp = _mp_holder[0]
            if not mp:
                usb_status_var.set("⚠ Aucun montage actif.")
                return
            r = subprocess.run(["umount", mp], capture_output=True, text=True)
            if r.returncode == 0:
                _mp_holder[0] = None
                for row in usb_tree.get_children():
                    usb_tree.delete(row)
                usb_status_var.set("✅ Clé démontée.")
            else:
                usb_status_var.set(f"❌ umount : {r.stderr.strip()[:80]}")

        mount_row = ttk.Frame(usb_frame); mount_row.pack(fill=tk.X, pady=(0, 4))
        ttk.Button(mount_row, text="▲  Monter la clé",
                   command=_mount_usb_pdf, width=18).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(mount_row, text="▼  Démonter la clé",
                   command=_umount_usb_pdf, width=18).pack(side=tk.LEFT)

        ttk.Label(usb_frame, textvariable=usb_status_var,
                  foreground="#7ec8e3", font=("Courier", 8)).pack(anchor=tk.W,
                                                                   pady=(0, 4))

        # ── Navigateur de fichiers PDF sur la clé ─────────────────────────────
        nav_frame = ttk.LabelFrame(usb_frame, text="PDFs sur la clé (sélection multiple)",
                                   padding=6)
        nav_frame.pack(fill=tk.X, pady=(0, 6))

        usb_tree_wrap = ttk.Frame(nav_frame)
        usb_tree_wrap.pack(fill=tk.BOTH, expand=True)

        usb_tree = ttk.Treeview(usb_tree_wrap, columns=("fname", "sz"),
                                 show="headings", height=4,
                                 selectmode="extended")
        usb_tree.heading("fname", text="Fichier PDF (chemin relatif)")
        usb_tree.heading("sz",    text="Taille")
        usb_tree.column("fname", width=400, anchor=tk.W)
        usb_tree.column("sz",    width=80,  anchor=tk.CENTER)
        usb_sb = ttk.Scrollbar(usb_tree_wrap, orient=tk.VERTICAL,
                                command=usb_tree.yview)
        usb_tree.configure(yscrollcommand=usb_sb.set)
        usb_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        usb_sb.pack(side=tk.RIGHT, fill=tk.Y)

        usb_count_var = tk.StringVar(value="Montez la clé pour voir les PDFs.")
        ttk.Label(nav_frame, textvariable=usb_count_var,
                  foreground="#aaaaaa", font=("Arial", 8)).pack(anchor=tk.W,
                                                                 pady=(2, 0))

        def _populate_usb_tree():
            for row in usb_tree.get_children():
                usb_tree.delete(row)
            mp = _mp_holder[0]
            if not mp or not os.path.isdir(mp):
                usb_count_var.set("⚠ Montez d'abord la clé.")
                return
            pdfs = []
            for root_dir, _, fnames in os.walk(mp):
                for fn in sorted(fnames, key=str.casefold):
                    if fn.lower().endswith(".pdf"):
                        full = os.path.join(root_dir, fn)
                        rel  = os.path.relpath(full, mp)
                        try:
                            sz = os.path.getsize(full)
                            sz_str = f"{sz // 1024} Ko" if sz >= 1024 else f"{sz} o"
                        except OSError:
                            sz_str = "?"
                        pdfs.append((rel, full, sz_str))
            for rel, full, sz_str in pdfs:
                usb_tree.insert("", tk.END, iid=full,
                                values=(rel, sz_str))
            usb_count_var.set(
                f"{len(pdfs)} PDF(s) trouvé(s) — sélectionnez puis cliquez Copier."
            )

        ttk.Button(nav_frame, text="🔍  Scanner la clé",
                   command=_populate_usb_tree,
                   width=18).pack(anchor=tk.W, pady=(4, 0))

        # ── Bouton copier ─────────────────────────────────────────────────────
        import_status_var = tk.StringVar()
        ttk.Label(usb_frame, textvariable=import_status_var,
                  foreground="#66cc66").pack(anchor=tk.W, pady=2)

        def _import_selected():
            sel = usb_tree.selection()
            if not sel:
                messagebox.showwarning("Aucune sélection",
                                       "Sélectionnez au moins un fichier PDF.",
                                       parent=dlg)
                return
            os.makedirs(pdf_dir, exist_ok=True)
            copied, errors = 0, []
            import shutil as _sh
            for src in sel:
                fname = os.path.basename(src)
                dst   = os.path.join(pdf_dir, fname)
                try:
                    _sh.copy2(src, dst)
                    copied += 1
                except Exception as e:
                    errors.append(f"{fname}: {e}")
            if errors:
                import_status_var.set(
                    f"⚠ {copied} copié(s), {len(errors)} erreur(s) : "
                    + " | ".join(errors[:2]))
            else:
                import_status_var.set(f"✅ {copied} PDF(s) copiés vers {pdf_dir}.")
            _refresh_list()
            self._on_pdf_reload()

        ttk.Button(usb_frame, text="⬆  Copier les PDFs sélectionnés vers ../pdf/",
                   command=_import_selected,
                   width=44).pack(anchor=tk.W, pady=(0, 12))

    # ── Onglet Journaux ────────────────────────────────────────────────────────

    def _tab_logs(self, nb: ttk.Notebook) -> None:
        outer = ttk.Frame(nb)
        nb.add(outer, text="📋 Journaux")

        # ── Conteneur scrollable ───────────────────────────────────────────────
        canvas  = tk.Canvas(outer, highlightthickness=0)
        vscroll = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vscroll.set)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tab = ttk.Frame(canvas, padding=10)
        win_id = canvas.create_window((0, 0), window=tab, anchor="nw")

        def _on_configure(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_resize(event):
            canvas.itemconfig(win_id, width=event.width)

        tab.bind("<Configure>", _on_configure)
        canvas.bind("<Configure>", _on_canvas_resize)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>",    _on_mousewheel)
        canvas.bind_all("<Button-4>",
                        lambda e: canvas.yview_scroll(-1, "units"))
        canvas.bind_all("<Button-5>",
                        lambda e: canvas.yview_scroll( 1, "units"))

        ttk.Label(tab, text="Journaux d'activité et statistiques",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 6))

        # ── Statistiques de scan ───────────────────────────────────────────────
        stats_frame = ttk.LabelFrame(tab, text="Statistiques cumulées (persistantes)", padding=8)
        stats_frame.pack(fill=tk.X, pady=(0, 8))

        stats_var = tk.StringVar(value="Chargement…")
        stats_lbl = ttk.Label(stats_frame, textvariable=stats_var,
                               font=("Courier", 9), foreground="#7ec8e3")
        stats_lbl.pack(anchor=tk.W)

        def _refresh_stats():
            try:
                s = self._get_scan_stats()
                stats_var.set(
                    f"Clés USB analysées  : {s['keys']}\n"
                    f"Menaces détectées   : {s['threats']}"
                )
            except Exception as e:
                stats_var.set(f"Erreur stats : {e}")

        _refresh_stats()
        stats_btn_row = ttk.Frame(stats_frame)
        stats_btn_row.pack(anchor=tk.W, pady=(6, 0))
        ttk.Button(stats_btn_row, text="↺  Actualiser",
                   command=_refresh_stats, width=14).pack(side=tk.LEFT, padx=(0, 6))

        def _do_purge_counters():
            if not messagebox.askyesno(
                "Purge compteurs",
                "Remettre à zéro le nombre de clés scannées\n"
                "et le compteur de menaces ?\n\n"
                "(Le tableau des menaces est conservé.)",
                icon="warning", parent=tab.winfo_toplevel()
            ):
                return
            self._cb["purge_counters"]()
            _refresh_stats()

        def _do_purge_threats():
            if not messagebox.askyesno(
                "Purge menaces",
                "Vider DÉFINITIVEMENT le tableau des menaces\n"
                "et remettre le compteur de menaces à zéro ?",
                icon="warning", parent=tab.winfo_toplevel()
            ):
                return
            self._cb["purge_threats"]()
            _refresh_stats()
            _refresh_threats()

        ttk.Button(stats_btn_row, text="🗑  Purge compteurs",
                   command=_do_purge_counters,
                   width=18).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(stats_btn_row, text="🗑  Purge menaces",
                   command=_do_purge_threats,
                   width=18).pack(side=tk.LEFT)

        # ── Tableau fichiers malveillants ──────────────────────────────────────
        threat_frame = ttk.LabelFrame(
            tab, text="Fichiers malveillants détectés (cumulés, toutes sessions)",
            padding=8)
        threat_frame.pack(fill=tk.X, pady=(0, 8))

        th_cols = ("ts", "file", "threat", "hash")
        th_tree = ttk.Treeview(threat_frame, columns=th_cols, show="headings",
                                height=6)
        th_tree.heading("ts",     text="Horodatage")
        th_tree.heading("file",   text="Fichier")
        th_tree.heading("threat", text="Menace")
        th_tree.heading("hash",   text="SHA-256")
        th_tree.column("ts",     width=130, anchor=tk.W)
        th_tree.column("file",   width=200, anchor=tk.W)
        th_tree.column("threat", width=130, anchor=tk.W)
        th_tree.column("hash",   width=280, anchor=tk.W,
                        stretch=True)
        th_sb = ttk.Scrollbar(threat_frame, orient=tk.VERTICAL,
                               command=th_tree.yview)
        th_tree.configure(yscrollcommand=th_sb.set)
        th_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        th_sb.pack(side=tk.RIGHT, fill=tk.Y)

        def _refresh_threats():
            for row in th_tree.get_children():
                th_tree.delete(row)
            try:
                s = self._get_scan_stats()
                for d in s["details"]:
                    th_tree.insert("", tk.END, values=(
                        d.get("ts",     ""),
                        os.path.basename(d.get("file",   "")),
                        d.get("threat", ""),
                        d.get("hash",   "N/A"),
                    ), tags=("threat",))
                th_tree.tag_configure("threat", foreground="#ff6b6b")
                if not s["details"]:
                    th_tree.insert("", tk.END,
                                   values=("—", "Aucune menace cette session",
                                           "", ""))
            except Exception as e:
                th_tree.insert("", tk.END,
                               values=("ERR", str(e), "", ""))

        _refresh_threats()

        def _export_threats_csv():
            from tkinter import filedialog
            try:
                s = self._get_scan_stats()
                if not s["details"]:
                    messagebox.showinfo("Vide",
                                        "Aucun fichier malveillant à exporter.",
                                        parent=tab.winfo_toplevel())
                    return
                path = filedialog.asksaveasfilename(
                    parent=tab.winfo_toplevel(),
                    title="Exporter les menaces",
                    defaultextension=".csv",
                    filetypes=[("CSV", "*.csv"), ("Tous", "*.*")],
                )
                if not path:
                    return
                import csv
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(
                        f, fieldnames=["ts","file","threat","hash","dev","mp"],
                        extrasaction="ignore")
                    w.writeheader()
                    w.writerows(s["details"])
                messagebox.showinfo("Export terminé",
                                    f"Exporté : {path}",
                                    parent=tab.winfo_toplevel())
            except Exception as e:
                messagebox.showerror("Erreur export",
                                     str(e), parent=tab.winfo_toplevel())

        th_btn_row = ttk.Frame(threat_frame)
        th_btn_row.pack(side=tk.BOTTOM, fill=tk.X, pady=(4, 0))
        ttk.Button(th_btn_row, text="↺  Actualiser",
                   command=lambda: [_refresh_stats(), _refresh_threats()],
                   width=14).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(th_btn_row, text="💾  Exporter CSV",
                   command=_export_threats_csv,
                   width=16).pack(side=tk.LEFT)

        # ── Volumétrie des logs ────────────────────────────────────────────────
        from log_handler import get_log_size_info
        from config import LOG_FILE as _LOG_FILE

        self._log_size_var = tk.StringVar(value=get_log_size_info())

        info_frame = ttk.LabelFrame(tab, text="Volumétrie des journaux", padding=8)
        info_frame.pack(fill=tk.X, pady=(0, 8))

        r1 = ttk.Frame(info_frame); r1.pack(fill=tk.X)
        ttk.Label(r1, text="Fichier principal :").pack(side=tk.LEFT)
        ttk.Label(r1, text=_LOG_FILE,
                  foreground="#7ec8e3", font=("Courier", 9)).pack(side=tk.LEFT,
                                                                padx=6)
        r2 = ttk.Frame(info_frame); r2.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(r2, text="Taille totale :").pack(side=tk.LEFT)
        ttk.Label(r2, textvariable=self._log_size_var,
                  foreground="#7ec8e3", font=("Courier", 9)).pack(side=tk.LEFT,
                                                                padx=6)

        def _refresh_size():
            from log_handler import get_log_size_info
            self._log_size_var.set(get_log_size_info())

        ttk.Button(info_frame, text="↺  Actualiser",
                   command=_refresh_size, width=14).pack(anchor=tk.W,
                                                          pady=(6, 0))
        ttk.Label(info_frame,
                  text="Rotation : fichiers 5 Mo max, 5 archives.",
                  foreground="#aaaaaa", font=("Arial", 8)).pack(anchor=tk.W,
                                                              pady=(4, 0))

        # ── Export / Purge ─────────────────────────────────────────────────────
        export_frame = ttk.LabelFrame(tab, text="Export vers support externe",
                                      padding=8)
        export_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(export_frame,
                  text="Monte une clé USB en écriture, ouvre un sélecteur\n"
                       "de dossier, copie les logs, puis démonte le support.",
                  foreground="#cccccc").pack(anchor=tk.W, pady=(0, 6))

        def _do_export():
            self._cb["export_logs_usb"]()
            _refresh_size()

        ttk.Button(export_frame, text="💾  Exporter les logs vers USB",
                   command=_do_export, width=32).pack(anchor=tk.W)

        purge_frame = ttk.LabelFrame(tab, text="Purge des logs", padding=8)
        purge_frame.pack(fill=tk.X)

        ttk.Label(purge_frame,
                  text="⚠  Supprime définitivement tous les fichiers de log.",
                  foreground="#ff6b6b").pack(anchor=tk.W, pady=(0, 6))

        def _do_purge():
            if not messagebox.askyesno(
                "⚠ Confirmer la purge",
                "Cette opération supprime DÉFINITIVEMENT\n"
                "tous les journaux d'activité.\n\nConfirmer ?",
                icon="warning",
                parent=tab.winfo_toplevel()
            ):
                return
            self._cb["purge_logs"]()
            _refresh_size()

        ttk.Button(purge_frame, text="🗑  Purger tous les logs",
                   command=_do_purge, width=24).pack(anchor=tk.W)

    def _tab_system(self, nb: ttk.Notebook) -> None:
        """Onglet de maintenance système : mises à jour APT et analyse sécurité."""
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="🖥 Système")

        ttk.Label(tab, text="Maintenance et sécurité du système",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 6))

        # ── Mises à jour APT ─────────────────────────────────────────────────
        apt_frame = ttk.LabelFrame(tab, text="Mises à jour du système (APT)",
                                   padding=10)
        apt_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(
            apt_frame,
            text="Lance apt update → apt full-upgrade → autoremove de façon non interactive.",
            foreground="#cccccc", justify=tk.LEFT
        ).pack(anchor=tk.W, pady=(0, 6))

        # ── Analyse antivirus (ClamAV) ────────────────────────────────────────
        av_frame = ttk.LabelFrame(tab, text="Analyse antivirale (ClamAV)",
                                  padding=10)
        av_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(
            av_frame,
            text="Analyse complète : / avec exclusions /proc /sys /dev /run.\n"
                 "⚠  Peut durer plusieurs minutes.",
            foreground="#cccccc", justify=tk.LEFT
        ).pack(anchor=tk.W, pady=(0, 6))

        # ── Analyse chkrootkit ────────────────────────────────────────────────
        rk_frame = ttk.LabelFrame(tab, text="Détection de rootkits (chkrootkit)",
                                  padding=10)
        rk_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(
            rk_frame,
            text="Lance chkrootkit (apt install chkrootkit si absent).",
            foreground="#cccccc", justify=tk.LEFT
        ).pack(anchor=tk.W, pady=(0, 6))

        # ── Terminal mini en bas à droite ─────────────────────────────────────
        _, _, _append, _clear, status_var, _after = self._mini_terminal(tab)

        all_btns: list = []

        def _set_btns(state):
            for b in all_btns:
                try:
                    b.configure(state=state)
                except Exception:
                    pass

        # ── Actions ───────────────────────────────────────────────────────────
        def _do_apt_upgrade():
            _clear()
            cmds = [
                (["apt-get", "update", "-q"], "Mise à jour des listes APT"),
                (["apt-get", "full-upgrade", "-y",
                  "-o", "Dpkg::Options::=--force-confdef",
                  "-o", "Dpkg::Options::=--force-confold"],
                 "Mise à niveau complète"),
                (["apt-get", "autoremove", "-y"], "Nettoyage paquets obsolètes"),
            ]
            def _chain(idx: int, _rc=None):
                if idx >= len(cmds):
                    _append("━━━ Toutes les étapes terminées ━━━", "ok")
                    _set_btns(tk.NORMAL)
                    return
                c, lbl = cmds[idx]
                self._stream_to_terminal(c, lbl, _append, status_var,
                                          on_done=lambda rc: _chain(idx + 1, rc),
                                          after_fn=_after)
            _set_btns(tk.DISABLED)
            _chain(0)

        def _do_clamav_scan():
            _clear()
            self._stream_to_terminal(
                ["clamscan", "--recursive",
                 "--exclude-dir=^/proc", "--exclude-dir=^/sys",
                 "--exclude-dir=^/dev",  "--exclude-dir=^/run",
                 "--infected", "/"],
                "Analyse ClamAV système", _append, status_var,
                set_btns_fn=_set_btns, after_fn=_after
            )

        def _do_chkrootkit():
            _clear()
            import shutil as _sh
            if not _sh.which("chkrootkit"):
                if messagebox.askyesno(
                    "chkrootkit manquant",
                    "chkrootkit n'est pas installé.\n"
                    "L'installer maintenant (apt install chkrootkit) ?",
                    parent=tab.winfo_toplevel()
                ):
                    self._stream_to_terminal(
                        ["apt-get", "install", "-y", "chkrootkit"],
                        "Installation de chkrootkit", _append, status_var,
                        set_btns_fn=_set_btns, after_fn=_after,
                        on_done=lambda rc: (
                            self._stream_to_terminal(
                                ["chkrootkit"], "Analyse chkrootkit",
                                _append, status_var, set_btns_fn=_set_btns,
                                after_fn=_after)
                            if rc == 0 else None
                        )
                    )
                return
            self._stream_to_terminal(["chkrootkit"], "Analyse chkrootkit",
                                      _append, status_var, set_btns_fn=_set_btns,
                                      after_fn=_after)

        btn_apt = ttk.Button(apt_frame, text="🔄  Mettre à jour",
                             command=_do_apt_upgrade, width=22)
        btn_apt.pack(anchor=tk.W)
        btn_clam = ttk.Button(av_frame, text="🔍  Analyser avec ClamAV",
                              command=_do_clamav_scan, width=26)
        btn_clam.pack(anchor=tk.W)
        btn_rk = ttk.Button(rk_frame, text="🕵  Analyser avec chkrootkit",
                             command=_do_chkrootkit, width=28)
        btn_rk.pack(anchor=tk.W)
        all_btns.extend([btn_apt, btn_clam, btn_rk])

    # ── Onglet Sécurité ────────────────────────────────────────────────────────

    def _tab_security(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="🔑 Sécurité")

        auth = self._auth

        ttk.Label(tab, text="Changer le code administrateur",
                  font=("Arial", 11, "bold")).grid(row=0, column=0,
                                                    columnspan=2,
                                                    pady=(0, 12),
                                                    sticky=tk.W)

        labels = ["Code actuel :", "Nouveau code :", "Confirmer :"]
        svars  = [tk.StringVar() for _ in labels]
        entries = []
        for i, (lbl, sv) in enumerate(zip(labels, svars)):
            ttk.Label(tab, text=lbl).grid(row=i+1, column=0,
                                           sticky=tk.E, padx=(0, 8), pady=4)
            e = ttk.Entry(tab, textvariable=sv, show="●", width=20)
            e.grid(row=i+1, column=1, sticky=tk.W, pady=4)
            entries.append(e)
        entries[0].focus_set()

        status_var = tk.StringVar()
        status_lbl = ttk.Label(tab, textvariable=status_var, wraplength=380)
        status_lbl.grid(row=4, column=0, columnspan=2, pady=8)

        def _apply():
            ok, msg = auth.change_code(svars[0].get(), svars[1].get(), svars[2].get())
            status_lbl.configure(foreground="#66cc66" if ok else "red")
            status_var.set(("✅ " if ok else "❌ ") + msg)
            if ok:
                for sv in svars:
                    sv.set("")

        ttk.Button(tab, text="💾 Enregistrer",
                   command=_apply).grid(row=5, column=0, columnspan=2, pady=4)

        if auth.is_default_code():
            ttk.Label(tab,
                      text="⚠  Code par défaut (0000) – changez-le maintenant !",
                      foreground="#ff6b6b",
                      font=("Arial", 9, "bold")).grid(
                row=6, column=0, columnspan=2, pady=4)

    # ── Onglet Arrêt ──────────────────────────────────────────────────────────

    def _tab_poweroff(self, nb: ttk.Notebook, dlg: tk.Toplevel) -> None:
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="⏻ Arrêt")

        ttk.Label(tab, text="Gestion de l'alimentation",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 10))

        # ── Arrêt ─────────────────────────────────────────────────────────────
        off_frame = ttk.LabelFrame(tab, text="Éteindre la station", padding=12)
        off_frame.pack(fill=tk.X, pady=(0, 12))

        ttk.Label(
            off_frame,
            text="• Les clés USB gérées sont démontées proprement.\n"
                 "• L'application est fermée.\n"
                 "• La commande 'poweroff' est exécutée.\n\n"
                 "⚠  Assurez-vous d'avoir sauvegardé votre travail.",
            justify=tk.LEFT, foreground="#cccccc"
        ).pack(anchor=tk.W, pady=(0, 10))

        def _do_poweroff():
            if messagebox.askyesno(
                "⏻ Confirmer l'arrêt",
                "Voulez-vous vraiment éteindre la station ?",
                icon="warning", parent=dlg
            ):
                dlg.destroy()
                self._cb["poweroff"]()

        ttk.Button(off_frame, text="⏻  Éteindre la station",
                   command=_do_poweroff, width=28).pack(anchor=tk.W)

        # ── Redémarrage ───────────────────────────────────────────────────────
        rb_frame = ttk.LabelFrame(tab, text="Redémarrer la station", padding=12)
        rb_frame.pack(fill=tk.X, pady=(0, 12))

        ttk.Label(
            rb_frame,
            text="• Les clés USB gérées sont démontées proprement.\n"
                 "• L'application est fermée.\n"
                 "• La commande 'reboot' est exécutée.",
            justify=tk.LEFT, foreground="#cccccc"
        ).pack(anchor=tk.W, pady=(0, 10))

        def _do_reboot():
            if messagebox.askyesno(
                "🔄 Confirmer le redémarrage",
                "Voulez-vous vraiment redémarrer la station ?",
                icon="warning", parent=dlg
            ):
                dlg.destroy()
                # Démontage propre puis reboot
                try:
                    from usb_manager import UsbManager as _UsbManager
                    _UsbManager().umount_all()
                except Exception:
                    pass
                import logging as _log
                try:
                    from log_handler import log_info as _log_info
                    _log_info("Redémarrage système.")
                except Exception:
                    pass
                subprocess.run(["reboot"], check=False)

        ttk.Button(rb_frame, text="🔄  Redémarrer la station",
                   command=_do_reboot, width=28).pack(anchor=tk.W)

    # ── Onglet Quitter ────────────────────────────────────────────────────────

    def _tab_quit(self, nb: ttk.Notebook, dlg: tk.Toplevel) -> None:
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="🚪 Quitter")

        ttk.Label(tab, text="Quitter l'application",
                  font=("Arial", 11, "bold")).pack(pady=(0, 12))
        ttk.Label(tab,
                  text="Ferme le scanner antiviral.\n"
                       "Toutes les clés USB gérées seront démontées proprement.",
                  justify=tk.CENTER).pack(pady=8)

        def _do():
            dlg.destroy()
            self._cb["quit"]()   # doit faire sys.exit(0) pour éviter le relancement
            import sys as _sys; _sys.exit(0)  # filet de sécurité si le callback ne quitte pas

        ttk.Button(tab, text="🚪  Quitter l'application",
                   command=_do).pack(pady=16)