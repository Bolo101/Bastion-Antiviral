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
FRESHCLAM_CMD   = (
    "freshclam --datadir=/var/lib/clamav "
    ">> /var/log/virusscanner_auto.log 2>&1"
)


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

    _CRON_TAG = "# virusscanner_auto"

    def get_cron_schedule(self) -> Optional[str]:
        try:
            r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if self._CRON_TAG in line:
                    return line.replace(self._CRON_TAG, "").strip()
        except Exception:
            pass
        return None

    def set_cron_schedule(self, cron_expr: Optional[str]) -> Tuple[bool, str]:
        try:
            r        = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            existing = r.stdout if r.returncode == 0 else ""
            lines    = [l for l in existing.splitlines() if self._CRON_TAG not in l]
            if cron_expr:
                lines.append(f"{cron_expr} {FRESHCLAM_CMD} {self._CRON_TAG}")
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
        # Système
        on_poweroff: Callable,
        on_quit:     Callable,
        # Supports exhaustifs
        get_usb_partitions: Callable,
        refresh_usb:        Callable,
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
            "poweroff":           on_poweroff,
            "quit":               on_quit,
        }
        self._get_usb_partitions = get_usb_partitions
        self._refresh_usb        = refresh_usb

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
        dlg.resizable(True, True)
        dlg.grab_set()
        dlg.transient(self._parent)

        w, h = 700, 580
        px = self._parent.winfo_rootx() + (self._parent.winfo_width()  - w) // 2
        py = self._parent.winfo_rooty() + (self._parent.winfo_height() - h) // 2
        dlg.geometry(f"{w}x{h}+{px}+{py}")

        nb = ttk.Notebook(dlg)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self._tab_engines(nb)
        self._tab_usb_detail(nb, dlg)
        self._tab_clamav(nb)
        self._tab_avast(nb)
        self._tab_yara(nb)
        self._tab_cron(nb)
        self._tab_logs(nb)
        self._tab_security(nb)
        self._tab_poweroff(nb, dlg)
        self._tab_quit(nb, dlg)

        ttk.Button(dlg, text="Fermer", command=dlg.destroy).pack(pady=6)

    # ── Onglet Moteurs ────────────────────────────────────────────────────────

    def _tab_engines(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=16)
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
            foreground="#555"
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
            foreground="#8B0000"
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
                  foreground="navy", font=("Courier", 9)).pack(anchor=tk.W, pady=4)
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

        ttk.Label(tab, text="Affichage exhaustif des supports amovibles",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 6))

        # Treeview complet
        cols = ("device", "label", "size", "fstype", "uuid", "mountpoint", "status")
        tree = ttk.Treeview(tab, columns=cols, show="headings",
                             height=8, selectmode="browse")
        for cid, heading, width in [
            ("device",     "Périphérique",  105),
            ("label",      "Étiquette",      80),
            ("size",       "Taille",         55),
            ("fstype",     "FS",             55),
            ("uuid",       "UUID",          155),
            ("mountpoint", "Point montage", 150),
            ("status",     "État",          110),
        ]:
            tree.heading(cid, text=heading)
            tree.column(cid, width=width, minwidth=30, anchor=tk.W)

        tree.tag_configure("ro",      background="#e6f4ea")
        tree.tag_configure("rw",      background="#fef3cd")
        tree.tag_configure("unmount", background="#f0f0f0")

        sb = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=sb.set)

        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, in_=tree_frame)
        sb.pack(side=tk.RIGHT, fill=tk.Y, in_=tree_frame)

        # Détail sélectionné
        detail_var = tk.StringVar()
        ttk.Label(tab, textvariable=detail_var,
                  font=("Courier", 8), foreground="navy",
                  wraplength=640, justify=tk.LEFT).pack(anchor=tk.W, pady=4)

        def _on_select(_=None):
            sel = tree.selection()
            if not sel:
                detail_var.set("")
                return
            vals = tree.item(sel[0], "values")
            detail_var.set(
                f"Périphérique : {vals[0]}  |  "
                f"Étiquette : {vals[1]}  |  Taille : {vals[2]}  |  "
                f"FS : {vals[3]}\nUUID : {vals[4]}\n"
                f"Point montage : {vals[5]}  |  État : {vals[6]}"
            )
        tree.bind("<<TreeviewSelect>>", _on_select)

        def _populate():
            for row in tree.get_children():
                tree.delete(row)
            from usb_manager import UsbManager
            usb = self._get_usb_partitions()
            if not usb:
                tree.insert("", tk.END,
                             values=("—", "—", "—", "—", "—", "—",
                                     "Aucun support détecté"))
                return
            for p in usb:
                from scanner import ScanEngine
                eng = ScanEngine()
                try:
                    from usb_manager import UsbManager as _UM
                    usb_mgr = _UM()
                    mp  = usb_mgr.get_mountpoint(p.device) or "—"
                    ro  = usb_mgr._is_ro(p.device, mp) if mp != "—" else None
                    if mp != "—":
                        status = ("✅ RO" if ro else "⚠ RW")
                        tag    = "ro" if ro else "rw"
                    else:
                        status = "⏏ Non monté"
                        tag    = "unmount"
                except Exception:
                    mp     = "—"
                    status = "?"
                    tag    = "unmount"

                tree.insert("", tk.END,
                             values=(p.device,
                                     p.label or "—",
                                     p.size,
                                     p.fstype or "—",
                                     p.uuid  or "—",
                                     mp,
                                     status),
                             tags=(tag,))

        btn_row = ttk.Frame(tab)
        btn_row.pack(anchor=tk.W, pady=4)
        ttk.Button(btn_row, text="↺  Actualiser",
                   command=lambda: (self._refresh_usb(), _populate()),
                   width=16).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="▲  Monter RO",
                   command=lambda: self._mount_selected(tree),
                   width=16).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="▼  Démonter",
                   command=lambda: self._umount_selected(tree),
                   width=16).pack(side=tk.LEFT, padx=4)

        _populate()

    def _mount_selected(self, tree: ttk.Treeview) -> None:
        sel = tree.selection()
        if not sel:
            return
        dev = tree.item(sel[0], "values")[0]
        if dev == "—":
            return
        from usb_manager import UsbManager
        usb = UsbManager()
        ok, msg = usb.mount(dev)
        messagebox.showinfo("Montage", msg) if ok else messagebox.showerror("Montage", msg)

    def _umount_selected(self, tree: ttk.Treeview) -> None:
        sel = tree.selection()
        if not sel:
            return
        dev = tree.item(sel[0], "values")[0]
        if dev == "—":
            return
        from usb_manager import UsbManager
        usb = UsbManager()
        ok, msg = usb.umount(dev)
        messagebox.showinfo("Démontage", msg) if ok else messagebox.showerror("Démontage", msg)

    # ── Onglet ClamAV ──────────────────────────────────────────────────────────

    def _tab_clamav(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="🛡 ClamAV")

        ttk.Label(tab, text="Mise à jour de la base ClamAV",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 8))
        ttk.Label(
            tab,
            text="• En ligne : freshclam contacte les serveurs ClamAV (Internet requis).\n"
                 "• Hors-ligne : copiez main.cvd, daily.cvd et bytecode.cvd\n"
                 "  à la racine d'une clé USB (source : database.clamav.net).",
            justify=tk.LEFT, foreground="#444"
        ).pack(anchor=tk.W, pady=(0, 8))

        row1 = ttk.Frame(tab)
        row1.pack(anchor=tk.W)
        ttk.Button(row1, text="🌐  Mise à jour en ligne (freshclam)",
                   command=self._cb["clamav_online"], width=36).pack(side=tk.LEFT, padx=4)
        ttk.Button(row1, text="🔌  Importer depuis clé USB",
                   command=self._cb["clamav_usb"],   width=26).pack(side=tk.LEFT, padx=4)

        ttk.Separator(tab, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

        ttk.Label(tab, text="Signatures tierces supplémentaires",
                  font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(0, 4))
        ttk.Label(
            tab,
            text="• URLhaus (abuse.ch), Sanesecurity, InterServer\n"
                 "  Installés dans /var/lib/clamav/ — Internet requis.",
            justify=tk.LEFT, foreground="#444"
        ).pack(anchor=tk.W, pady=(0, 8))

        row2 = ttk.Frame(tab)
        row2.pack(anchor=tk.W)
        ttk.Button(row2, text="🌐  Télécharger signatures tierces",
                   command=self._cb["clamav_thirdparty"],
                   width=36).pack(side=tk.LEFT, padx=4)

    # ── Onglet Avast ───────────────────────────────────────────────────────────

    def _tab_avast(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="🔐 Avast")

        ttk.Label(tab, text="Gestion d'Avast Business for Linux",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 6))

        # ── Statut ────────────────────────────────────────────────────────────
        status_frame = ttk.LabelFrame(tab, text="Statut", padding=8)
        status_frame.pack(fill=tk.X, pady=(0, 8))

        self._avast_status_var = tk.StringVar(value="Vérification…")
        ttk.Label(status_frame, textvariable=self._avast_status_var,
                  foreground="navy", font=("Courier", 9)).pack(anchor=tk.W)
        ttk.Button(status_frame, text="↺  Actualiser",
                   command=self._refresh_avast_status_display,
                   width=20).pack(anchor=tk.W, pady=(4, 0))
        self._refresh_avast_status_display()

        # ── Installation (mode installé) ──────────────────────────────────────
        install_frame = ttk.LabelFrame(tab, text="Installation (mode installé)", padding=8)
        install_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(
            install_frame,
            text="Installe Avast Business for Linux depuis le dépôt officiel.\n"
                 "Nécessite une connexion Internet et les droits root.\n\n"
                 "Étapes automatiques :\n"
                 "  1. Ajout de la clé GPG depuis repo.avcdn.net\n"
                 "  2. Ajout du dépôt APT avast\n"
                 "  3. apt-get install avast\n"
                 "  4. Activation du service systemd",
            justify=tk.LEFT, foreground="#444"
        ).pack(anchor=tk.W, pady=(0, 6))

        install_row = ttk.Frame(install_frame)
        install_row.pack(anchor=tk.W)
        ttk.Button(install_row, text="📦  Installer Avast Business",
                   command=self._cb["avast_install"],
                   width=28).pack(side=tk.LEFT, padx=4)

        ttk.Label(
            install_frame,
            text="Installation manuelle :\n"
                 "  curl -fsSL https://repo.avcdn.net/linux/avast.gpg "
                 "| tee /etc/apt/trusted.gpg.d/avast.gpg\n"
                 "  echo 'deb https://repo.avcdn.net/linux stable avast' "
                 "| tee /etc/apt/sources.list.d/avast.list\n"
                 "  apt-get update && apt-get install avast",
            justify=tk.LEFT, foreground="#666",
            font=("Courier", 7)
        ).pack(anchor=tk.W, pady=(6, 0))

        # ── Licence ───────────────────────────────────────────────────────────
        lic_frame = ttk.LabelFrame(tab, text="Licence Business", padding=8)
        lic_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(lic_frame,
                  text="A — Code d'activation (Internet requis) :",
                  foreground="#444").grid(row=0, column=0, columnspan=3,
                                          sticky=tk.W, pady=(0, 4))

        code_var  = tk.StringVar()
        code_entry = ttk.Entry(lic_frame, textvariable=code_var,
                               width=30, font=("Courier", 10))
        code_entry.grid(row=1, column=0, sticky=tk.W, padx=(0, 6))

        def _activate():
            code = code_var.get().strip()
            if not code:
                messagebox.showwarning("Code vide",
                                       "Entrez un code d'activation.",
                                       parent=tab.winfo_toplevel())
                return
            self._cb["avast_activate"](code)

        ttk.Button(lic_frame, text="🔑 Activer",
                   command=_activate, width=13).grid(row=1, column=1, padx=4)

        ttk.Separator(lic_frame, orient=tk.HORIZONTAL).grid(
            row=2, column=0, columnspan=3, sticky=tk.EW, pady=6)

        ttk.Label(lic_frame,
                  text="B — Fichier .avastlic depuis USB :",
                  foreground="#444").grid(row=3, column=0, columnspan=3,
                                          sticky=tk.W, pady=(0, 4))
        ttk.Button(lic_frame, text="🔌  Import depuis USB",
                   command=self._cb["avast_license_usb"],
                   width=22).grid(row=4, column=0, sticky=tk.W)

        ttk.Separator(lic_frame, orient=tk.HORIZONTAL).grid(
            row=5, column=0, columnspan=3, sticky=tk.EW, pady=6)

        ttk.Label(lic_frame,
                  text="C — Fichier .avastlic depuis le système :",
                  foreground="#444").grid(row=6, column=0, columnspan=3,
                                          sticky=tk.W, pady=(0, 4))

        self._avast_lic_path_var = tk.StringVar(value="Aucun fichier sélectionné")
        ttk.Label(lic_frame, textvariable=self._avast_lic_path_var,
                  foreground="navy", font=("Courier", 8),
                  wraplength=360).grid(row=7, column=0, columnspan=2,
                                       sticky=tk.W, pady=2)

        def _browse():
            from tkinter import filedialog
            path = filedialog.askopenfilename(
                parent=tab.winfo_toplevel(),
                title="Sélectionner la licence Avast",
                filetypes=[("Licence Avast", "*.avastlic"),
                           ("Tous", "*.*")],
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
        btn_row2.grid(row=8, column=0, columnspan=3, sticky=tk.W, pady=(2, 0))
        ttk.Button(btn_row2, text="📂  Parcourir…",
                   command=_browse, width=16).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_row2, text="⬇  Installer",
                   command=_import_browsed, width=16).pack(side=tk.LEFT)

        # ── Base VPS ──────────────────────────────────────────────────────────
        vps_frame = ttk.LabelFrame(tab, text="Base VPS (définitions)", padding=8)
        vps_frame.pack(fill=tk.X)

        ttk.Label(vps_frame,
                  text="• En ligne : Avast télécharge la dernière VPS.\n"
                       "• Hors-ligne : copiez un fichier .vps/.vpz sur une clé USB.",
                  foreground="#444").pack(anchor=tk.W, pady=(0, 6))

        vps_row = ttk.Frame(vps_frame)
        vps_row.pack(anchor=tk.W)
        ttk.Button(vps_row, text="🌐  Mise à jour VPS en ligne",
                   command=self._cb["avast_vps_online"],
                   width=26).pack(side=tk.LEFT, padx=4)
        ttk.Button(vps_row, text="🔌  Importer VPS depuis USB",
                   command=self._cb["avast_vps_usb"],
                   width=26).pack(side=tk.LEFT, padx=4)

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

    # ── Onglet YARA ────────────────────────────────────────────────────────────

    def _tab_yara(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="🔍 YARA")

        ttk.Label(tab, text="Gestion des règles YARA",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 8))
        ttk.Label(
            tab,
            text="• En ligne  : télécharge signature-base de Florian Roth (GitHub).\n"
                 "  Connexion Internet requise — ~30 Mo.\n"
                 "• Hors-ligne : placez des fichiers .yar/.yara ou un .zip\n"
                 "  contenant des règles à la racine d'une clé USB.",
            justify=tk.LEFT, foreground="#444"
        ).pack(anchor=tk.W, pady=(0, 12))

        row = ttk.Frame(tab)
        row.pack(anchor=tk.W)
        ttk.Button(row, text="🌐  Télécharger signature-base",
                   command=self._cb["yara_online"], width=30).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="🔌  Importer depuis clé USB",
                   command=self._cb["yara_usb"],    width=28).pack(side=tk.LEFT, padx=4)

    # ── Onglet Planification ───────────────────────────────────────────────────

    def _tab_cron(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="⏰ Planification")

        auth = self._auth

        ttk.Label(tab, text="Mise à jour automatique ClamAV (crontab)",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 8))

        current = auth.get_cron_schedule()
        cur_var = tk.StringVar(
            value=f"Actuelle : {current}" if current else "Aucune planification active"
        )
        ttk.Label(tab, textvariable=cur_var, foreground="navy").pack(anchor=tk.W, pady=4)
        ttk.Separator(tab, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=8)

        freq_var = tk.StringVar(value="daily")
        row1 = ttk.Frame(tab); row1.pack(anchor=tk.W)
        ttk.Label(row1, text="Fréquence :").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Radiobutton(row1, text="Quotidienne",
                        variable=freq_var, value="daily").pack(side=tk.LEFT, padx=4)
        ttk.Radiobutton(row1, text="Hebdomadaire (lundi)",
                        variable=freq_var, value="weekly").pack(side=tk.LEFT, padx=4)

        hour_var = tk.StringVar(value="2")
        row2 = ttk.Frame(tab); row2.pack(anchor=tk.W, pady=6)
        ttk.Label(row2, text="Heure (0-23) :").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Spinbox(row2, from_=0, to=23, textvariable=hour_var,
                    width=5, format="%02.0f").pack(side=tk.LEFT)

        status_var = tk.StringVar()
        status_lbl = ttk.Label(tab, textvariable=status_var, wraplength=420)
        status_lbl.pack(pady=6)

        def _apply():
            try:
                h = int(hour_var.get())
                assert 0 <= h <= 23
            except Exception:
                messagebox.showerror("Valeur invalide", "Heure entre 0 et 23.",
                                     parent=tab.winfo_toplevel())
                return
            expr = f"0 {h} * * *" if freq_var.get() == "daily" else f"0 {h} * * 1"
            ok, msg = auth.set_cron_schedule(expr)
            status_lbl.configure(foreground="green" if ok else "red")
            status_var.set(("✅ " if ok else "❌ ") + msg)
            if ok:
                cur_var.set(f"Actuelle : {expr}")

        def _remove():
            ok, msg = auth.set_cron_schedule(None)
            status_lbl.configure(foreground="green" if ok else "red")
            status_var.set(("✅ " if ok else "❌ ") + msg)
            if ok:
                cur_var.set("Aucune planification active")

        row3 = ttk.Frame(tab); row3.pack(anchor=tk.W, pady=4)
        ttk.Button(row3, text="✓ Appliquer",  command=_apply,  width=16).pack(side=tk.LEFT, padx=4)
        ttk.Button(row3, text="🗑 Supprimer", command=_remove, width=16).pack(side=tk.LEFT, padx=4)

    # ── Onglet Journaux ────────────────────────────────────────────────────────

    def _tab_logs(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="📋 Journaux")

        ttk.Label(tab, text="Gestion des journaux d'activité",
                  font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 6))

        from log_handler import get_log_size_info
        from config import LOG_FILE as _LOG_FILE

        self._log_size_var = tk.StringVar(value=get_log_size_info())

        info_frame = ttk.LabelFrame(tab, text="Volumétrie", padding=8)
        info_frame.pack(fill=tk.X, pady=(0, 10))

        r1 = ttk.Frame(info_frame); r1.pack(fill=tk.X)
        ttk.Label(r1, text="Fichier principal :").pack(side=tk.LEFT)
        ttk.Label(r1, text=_LOG_FILE,
                  foreground="navy", font=("Courier", 9)).pack(side=tk.LEFT, padx=6)

        r2 = ttk.Frame(info_frame); r2.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(r2, text="Taille totale :").pack(side=tk.LEFT)
        ttk.Label(r2, textvariable=self._log_size_var,
                  foreground="navy", font=("Courier", 9)).pack(side=tk.LEFT, padx=6)

        def _refresh_size():
            from log_handler import get_log_size_info
            self._log_size_var.set(get_log_size_info())

        ttk.Button(info_frame, text="↺  Actualiser",
                   command=_refresh_size, width=14).pack(anchor=tk.W, pady=(6, 0))
        ttk.Label(info_frame,
                  text="Rotation : fichiers 5 Mo max, 5 archives.",
                  foreground="#666", font=("Arial", 8)).pack(anchor=tk.W, pady=(4, 0))

        # Export
        export_frame = ttk.LabelFrame(tab, text="Export vers support externe", padding=8)
        export_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(export_frame,
                  text="Monte une clé USB en écriture, ouvre un sélecteur\n"
                       "de dossier, copie les logs, puis démonte le support.",
                  foreground="#444").pack(anchor=tk.W, pady=(0, 6))

        def _do_export():
            self._cb["export_logs_usb"]()
            _refresh_size()

        ttk.Button(export_frame, text="💾  Exporter les logs vers USB",
                   command=_do_export, width=32).pack(anchor=tk.W)

        # Purge
        purge_frame = ttk.LabelFrame(tab, text="Purge des logs", padding=8)
        purge_frame.pack(fill=tk.X)

        ttk.Label(purge_frame,
                  text="⚠  Supprime définitivement tous les fichiers de log.",
                  foreground="#8B0000").pack(anchor=tk.W, pady=(0, 6))

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

    # ── Onglet Sécurité ────────────────────────────────────────────────────────

    def _tab_security(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="🔑 Sécurité")

        auth = self._auth

        ttk.Label(tab, text="Changer le code administrateur",
                  font=("Arial", 11, "bold")).grid(row=0, column=0,
                                                    columnspan=2,
                                                    pady=(0, 12), sticky=tk.W)

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
            status_lbl.configure(foreground="green" if ok else "red")
            status_var.set(("✅ " if ok else "❌ ") + msg)
            if ok:
                for sv in svars:
                    sv.set("")

        ttk.Button(tab, text="💾 Enregistrer",
                   command=_apply).grid(row=5, column=0, columnspan=2, pady=4)

        if auth.is_default_code():
            ttk.Label(tab,
                      text="⚠  Code par défaut (0000) – changez-le maintenant !",
                      foreground="red",
                      font=("Arial", 9, "bold")).grid(
                row=6, column=0, columnspan=2, pady=4)

    # ── Onglet Arrêt ──────────────────────────────────────────────────────────

    def _tab_poweroff(self, nb: ttk.Notebook, dlg: tk.Toplevel) -> None:
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="⏻ Arrêt")

        ttk.Label(tab, text="Arrêt de la station",
                  font=("Arial", 11, "bold")).pack(pady=(0, 8))
        ttk.Label(
            tab,
            text="Éteint complètement la station de travail.\n\n"
                 "• Les clés USB gérées sont démontées proprement.\n"
                 "• L'application est fermée.\n"
                 "• La commande 'poweroff' est exécutée.\n\n"
                 "⚠  Assurez-vous d'avoir sauvegardé votre travail.",
            justify=tk.LEFT, foreground="#444"
        ).pack(anchor=tk.W, pady=(0, 16))

        def _do():
            if messagebox.askyesno(
                "⏻ Confirmer l'arrêt",
                "Voulez-vous vraiment éteindre la station ?",
                icon="warning", parent=dlg
            ):
                dlg.destroy()
                self._cb["poweroff"]()

        ttk.Button(tab, text="⏻  Éteindre la station",
                   command=_do, width=26).pack(pady=8)

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
            self._cb["quit"]()

        ttk.Button(tab, text="🚪  Quitter l'application",
                   command=_do).pack(pady=16)