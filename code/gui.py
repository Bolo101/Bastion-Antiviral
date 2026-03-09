#!/usr/bin/env python3
"""
gui.py  –  Interface graphique du scanner antiviral USB/disque dur.
Supporte ClamAV et Avast avec :
  • sélection du moteur
  • import de licence Avast depuis clé USB (license.avastlic)
  • mise à jour de la base virale en ligne (freshclam / avast update)
  • import hors-ligne de la base depuis une clé USB
"""

import os
import sys
import time
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, List, Optional, Set

from utils import get_disk_list, get_base_disk, get_active_disk, get_disk_serial, is_ssd
from log_handler import log_info, log_error, log_warning
from antivirus_manager import AntivirusManager, UsbMountManager


# ══════════════════════════════════════════════════════════════════════════════
class VirusScannerGUI:
    """Fenêtre principale du scanner antiviral."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("USB & Disk Antivirus Scanner")
        self.root.attributes("-fullscreen", True)

        # ── state ──
        self.av  = AntivirusManager()
        self.usb = UsbMountManager()
        self.selected_disk_var    = tk.StringVar()
        self.scan_mode_var        = tk.StringVar(value="quick")
        self.remove_infected_var  = tk.BooleanVar(value=False)
        self.engine_var           = tk.StringVar(value="clamav")

        self.disks:        List[Dict]  = []
        self.active_disks: Set[str]    = set()
        self.is_scanning               = False
        self.session_logs:  List[str]  = []
        self.scan_results = {"scanned": 0, "infected": 0, "threats": []}

        # root check
        if os.geteuid() != 0:
            messagebox.showerror("Erreur", "Ce programme doit être lancé en root !")
            root.destroy()
            sys.exit(1)

        self._build_ui()
        self.refresh_disks()
        self._refresh_engine_status()

    # ══════════════════════════════════════════════════════════════════════════
    # UI construction
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        # Title bar
        title_bar = ttk.Frame(main)
        title_bar.pack(fill=tk.X)
        ttk.Label(title_bar, text="USB & Disk Antivirus Scanner",
                  font=("Arial", 15, "bold")).pack(side=tk.LEFT)
        ttk.Button(title_bar, text="⛶ Plein écran",
                   command=self._toggle_fullscreen).pack(side=tk.RIGHT, padx=4)
        ttk.Button(title_bar, text="✕ Quitter",
                   command=self._exit_application).pack(side=tk.RIGHT, padx=4)

        ttk.Separator(main, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=4)

        # Two-column layout: left=config, right=log
        body = ttk.Frame(main)
        body.pack(fill=tk.BOTH, expand=True)

        left  = ttk.Frame(body)
        right = ttk.Frame(body)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0))

        # ── Left column ───────────────────────────────────────────────────────
        self._build_engine_frame(left)
        self._build_license_frame(left)
        self._build_db_frame(left)
        self._build_usb_manager_frame(left)
        self._build_disk_frame(left)
        self._build_scan_options(left)
        self._build_control_buttons(left)
        self._build_progress_frame(left)

        # ── Right column ──────────────────────────────────────────────────────
        self._build_log_frame(right)

        self.root.protocol("WM_DELETE_WINDOW", self._exit_application)

    # ── Engine selection ──────────────────────────────────────────────────────

    def _build_engine_frame(self, parent: ttk.Frame) -> None:
        lf = ttk.LabelFrame(parent, text="Moteur antiviral", padding=6)
        lf.pack(fill=tk.X, pady=4)

        row = ttk.Frame(lf)
        row.pack(fill=tk.X)

        ttk.Radiobutton(row, text="ClamAV",
                        variable=self.engine_var, value="clamav",
                        command=self._on_engine_change).pack(side=tk.LEFT, padx=8)
        ttk.Radiobutton(row, text="Avast",
                        variable=self.engine_var, value="avast",
                        command=self._on_engine_change).pack(side=tk.LEFT, padx=8)

        self.engine_status_var = tk.StringVar(value="Vérification…")
        ttk.Label(lf, textvariable=self.engine_status_var,
                  font=("Arial", 9), foreground="navy").pack(anchor=tk.W, pady=2)

    # ── Avast license ─────────────────────────────────────────────────────────

    def _build_license_frame(self, parent: ttk.Frame) -> None:
        self.license_frame = ttk.LabelFrame(parent, text="Licence Avast", padding=6)
        # Packed/forgotten dynamically by _on_engine_change

        row = ttk.Frame(self.license_frame)
        row.pack(fill=tk.X)

        ttk.Button(row, text="📂 Importer depuis clé USB",
                   command=self._import_avast_license_usb).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="📁 Choisir un fichier…",
                   command=self._import_avast_license_file).pack(side=tk.LEFT, padx=4)

        self.license_status_var = tk.StringVar(value="—")
        ttk.Label(self.license_frame, textvariable=self.license_status_var,
                  font=("Arial", 9)).pack(anchor=tk.W, pady=2)

    # ── Database management ───────────────────────────────────────────────────

    def _build_db_frame(self, parent: ttk.Frame) -> None:
        lf = ttk.LabelFrame(parent, text="Base virale", padding=6)
        lf.pack(fill=tk.X, pady=4)

        self.db_status_var = tk.StringVar(value="Vérification…")
        ttk.Label(lf, textvariable=self.db_status_var,
                  font=("Arial", 9)).pack(anchor=tk.W)

        btn_row = ttk.Frame(lf)
        btn_row.pack(fill=tk.X, pady=4)

        self.btn_update_online = ttk.Button(
            btn_row, text="🌐 Mettre à jour (Internet)",
            command=self._update_db_online)
        self.btn_update_online.pack(side=tk.LEFT, padx=4)

        self.btn_import_usb = ttk.Button(
            btn_row, text="🔌 Importer depuis clé USB",
            command=self._import_db_from_usb)
        self.btn_import_usb.pack(side=tk.LEFT, padx=4)

        ttk.Button(btn_row, text="↺ Actualiser",
                   command=self._refresh_db_status).pack(side=tk.LEFT, padx=4)

    # ── USB manager panel ─────────────────────────────────────────────────────

    def _build_usb_manager_frame(self, parent: ttk.Frame) -> None:
        lf = ttk.LabelFrame(parent, text="Gestion des clés USB", padding=6)
        lf.pack(fill=tk.X, pady=4)

        # ── Treeview ──────────────────────────────────────────────────────────
        cols = ("device", "label", "size", "fstype", "status")
        self.usb_tree = ttk.Treeview(lf, columns=cols, show="headings",
                                      height=4, selectmode="browse")

        col_cfg = [
            ("device", "Périphérique",  120),
            ("label",  "Étiquette",      90),
            ("size",   "Taille",         60),
            ("fstype", "FS",             60),
            ("status", "État",          200),
        ]
        for cid, heading, width in col_cfg:
            self.usb_tree.heading(cid, text=heading)
            self.usb_tree.column(cid, width=width, minwidth=40, anchor=tk.W)

        # Couleurs par état
        self.usb_tree.tag_configure("mounted",   background="#d4edda")
        self.usb_tree.tag_configure("unmounted", background="#f8f9fa")
        self.usb_tree.tag_configure("managed",   background="#cce5ff")

        usb_sb = ttk.Scrollbar(lf, orient=tk.VERTICAL,
                                command=self.usb_tree.yview)
        self.usb_tree.configure(yscrollcommand=usb_sb.set)
        self.usb_tree.pack(side=tk.LEFT, fill=tk.X, expand=True)
        usb_sb.pack(side=tk.LEFT, fill=tk.Y)

        # ── Boutons ───────────────────────────────────────────────────────────
        btn_col = ttk.Frame(lf)
        btn_col.pack(side=tk.LEFT, fill=tk.Y, padx=(6, 0))

        ttk.Button(btn_col, text="↺ Actualiser",
                   command=self._refresh_usb_list).pack(fill=tk.X, pady=2)

        self.btn_usb_mount = ttk.Button(
            btn_col, text="▲ Monter",
            command=self._mount_selected_usb)
        self.btn_usb_mount.pack(fill=tk.X, pady=2)

        self.btn_usb_umount = ttk.Button(
            btn_col, text="▼ Démonter",
            command=self._umount_selected_usb)
        self.btn_usb_umount.pack(fill=tk.X, pady=2)

        ttk.Button(btn_col, text="▼▼ Tout démonter",
                   command=self._umount_all_usb).pack(fill=tk.X, pady=2)

        # Info ligne sélectionnée
        self.usb_info_var = tk.StringVar(value="")
        ttk.Label(lf, textvariable=self.usb_info_var,
                  font=("Arial", 8), foreground="navy").pack(
            anchor=tk.W, pady=2, side=tk.BOTTOM)

        self.usb_tree.bind("<<TreeviewSelect>>", self._on_usb_select)

        # Premier chargement
        self._refresh_usb_list()

    # ── USB list actions ──────────────────────────────────────────────────────

    def _refresh_usb_list(self) -> None:
        """Recharge la liste des partitions USB dans le Treeview."""
        # Mémorise la sélection actuelle
        selected_dev = self._get_selected_usb_device()

        for row in self.usb_tree.get_children():
            self.usb_tree.delete(row)

        partitions = self.usb.list_usb_partitions()

        if not partitions:
            self.usb_tree.insert("", tk.END, values=(
                "—", "—", "—", "—", "Aucune clé USB détectée"
            ))
            self.usb_info_var.set("")
            return

        reselect_iid = None
        for p in partitions:
            dev = p["device"]
            mp  = p.get("mountpoint")
            if mp:
                status = f"✅ Monté sur {mp}"
                tag    = "managed" if p["managed"] else "mounted"
            else:
                status = "⏏  Non monté"
                tag    = "unmounted"

            iid = self.usb_tree.insert("", tk.END, iid=dev, values=(
                dev,
                p["label"] or "—",
                p["size"],
                p["fstype"],
                status,
            ), tags=(tag,))

            if dev == selected_dev:
                reselect_iid = iid

        if reselect_iid:
            self.usb_tree.selection_set(reselect_iid)
            self.usb_tree.see(reselect_iid)

        self._update_usb_buttons()

    def _on_usb_select(self, _event=None) -> None:
        dev = self._get_selected_usb_device()
        if not dev:
            self.usb_info_var.set("")
            return
        mp = self.usb.get_mountpoint(dev)
        if mp:
            self.usb_info_var.set(f"Point de montage : {mp}")
        else:
            self.usb_info_var.set(f"{dev} — non monté")
        self._update_usb_buttons()

    def _update_usb_buttons(self) -> None:
        dev = self._get_selected_usb_device()
        if not dev or dev == "—":
            self.btn_usb_mount.configure(state=tk.DISABLED)
            self.btn_usb_umount.configure(state=tk.DISABLED)
            return
        mp = self.usb.get_mountpoint(dev)
        self.btn_usb_mount.configure(
            state=tk.DISABLED if mp else tk.NORMAL)
        self.btn_usb_umount.configure(
            state=tk.NORMAL if mp else tk.DISABLED)

    def _get_selected_usb_device(self) -> Optional[str]:
        sel = self.usb_tree.selection()
        if not sel:
            return None
        values = self.usb_tree.item(sel[0], "values")
        if not values or values[0] == "—":
            return None
        return values[0]

    def _mount_selected_usb(self) -> None:
        dev = self._get_selected_usb_device()
        if not dev:
            messagebox.showwarning("Aucune sélection",
                                   "Veuillez sélectionner une clé USB.")
            return
        self._update_log(f"Montage de {dev} …")
        self.btn_usb_mount.configure(state=tk.DISABLED)

        def _worker():
            ok, msg = self.usb.mount(
                dev,
                progress_cb=lambda l: self.root.after(0, self._update_log, l)
            )
            def _done():
                if ok:
                    self._update_log(f"✅ {msg}")
                    # Propose de lancer l'import de base si mode hors-ligne
                    mp = self.usb.get_mountpoint(dev)
                    if mp:
                        self._propose_db_import_from(mp)
                else:
                    messagebox.showerror("Erreur de montage", msg)
                    self._update_log(f"❌ {msg}", tag="threat")
                self._refresh_usb_list()
            self.root.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    def _umount_selected_usb(self) -> None:
        dev = self._get_selected_usb_device()
        if not dev:
            messagebox.showwarning("Aucune sélection",
                                   "Veuillez sélectionner une clé USB.")
            return
        self._update_log(f"Démontage de {dev} …")
        self.btn_usb_umount.configure(state=tk.DISABLED)

        def _worker():
            ok, msg = self.usb.umount(
                dev,
                progress_cb=lambda l: self.root.after(0, self._update_log, l)
            )
            def _done():
                if ok:
                    self._update_log(f"✅ {msg}")
                else:
                    messagebox.showerror("Erreur de démontage", msg)
                    self._update_log(f"❌ {msg}", tag="threat")
                self._refresh_usb_list()
            self.root.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    def _umount_all_usb(self) -> None:
        if not messagebox.askyesno("Démonter tout",
                                    "Démonter toutes les clés USB montées ?"):
            return
        self._update_log("Démontage de toutes les clés USB gérées…")

        def _worker():
            self.usb.umount_all_managed()
            self.root.after(0, self._refresh_usb_list)
            self.root.after(0, self._update_log,
                            "✅ Démontage terminé.")

        threading.Thread(target=_worker, daemon=True).start()

    def _propose_db_import_from(self, mount_point: str) -> None:
        """
        Après un montage réussi, propose automatiquement d'importer
        la base virale si des fichiers de base sont trouvés.
        """
        engine = self.engine_var.get()
        if engine == "clamav":
            import glob as _glob
            files = (_glob.glob(os.path.join(mount_point, "*.cvd")) +
                     _glob.glob(os.path.join(mount_point, "*.cld")))
            if files:
                names = ", ".join(os.path.basename(f) for f in files)
                if messagebox.askyesno(
                    "Fichiers de base ClamAV détectés",
                    f"Fichiers trouvés sur la clé :\n{names}\n\n"
                    "Importer la base ClamAV maintenant ?"
                ):
                    self._import_db_from_usb()
        else:
            import glob as _glob
            files = (_glob.glob(os.path.join(mount_point, "*.vps")) +
                     _glob.glob(os.path.join(mount_point, "*.vpz")))
            lic = os.path.join(mount_point, "license.avastlic")
            if os.path.exists(lic):
                if messagebox.askyesno(
                    "Licence Avast détectée",
                    "Un fichier license.avastlic a été trouvé.\n"
                    "Importer la licence Avast maintenant ?"
                ):
                    self._import_avast_license_usb()
            elif files:
                if messagebox.askyesno(
                    "Fichiers VPS Avast détectés",
                    "Des fichiers VPS Avast ont été trouvés.\n"
                    "Importer la base Avast maintenant ?"
                ):
                    self._import_db_from_usb()

    # ── Disk selection ────────────────────────────────────────────────────────

    def _build_disk_frame(self, parent: ttk.Frame) -> None:
        lf = ttk.LabelFrame(parent, text="Disque / clé USB à analyser", padding=6)
        lf.pack(fill=tk.BOTH, expand=True, pady=4)

        inner = ttk.Frame(lf)
        inner.pack(fill=tk.BOTH, expand=True)

        self.disk_listbox = tk.Listbox(inner, selectmode=tk.SINGLE, height=5,
                                       font=("Courier", 9))
        sb = ttk.Scrollbar(inner, orient=tk.VERTICAL,
                            command=self.disk_listbox.yview)
        self.disk_listbox.configure(yscrollcommand=sb.set)
        self.disk_listbox.bind("<<ListboxSelect>>", self._on_disk_select)
        self.disk_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.disk_info_var = tk.StringVar(value="Aucun disque sélectionné")
        ttk.Label(lf, textvariable=self.disk_info_var,
                  wraplength=480, justify=tk.LEFT,
                  font=("Arial", 9)).pack(anchor=tk.W, pady=2)

        self.disk_warning_var = tk.StringVar()
        ttk.Label(lf, textvariable=self.disk_warning_var,
                  foreground="red", wraplength=480).pack(anchor=tk.W)

    # ── Scan options ──────────────────────────────────────────────────────────

    def _build_scan_options(self, parent: ttk.Frame) -> None:
        lf = ttk.LabelFrame(parent, text="Options d'analyse", padding=6)
        lf.pack(fill=tk.X, pady=4)

        mode_row = ttk.Frame(lf)
        mode_row.pack(fill=tk.X)
        ttk.Label(mode_row, text="Mode :").pack(side=tk.LEFT, padx=4)
        ttk.Radiobutton(mode_row, text="Rapide (partitions montées)",
                        variable=self.scan_mode_var,
                        value="quick").pack(side=tk.LEFT, padx=8)
        ttk.Radiobutton(mode_row, text="Complet (toutes partitions)",
                        variable=self.scan_mode_var,
                        value="deep").pack(side=tk.LEFT, padx=8)

        ttk.Checkbutton(lf, text="⚠ Supprimer les fichiers infectés (DANGER !)",
                        variable=self.remove_infected_var).pack(anchor=tk.W, pady=4)

    # ── Control buttons ───────────────────────────────────────────────────────

    def _build_control_buttons(self, parent: ttk.Frame) -> None:
        row = ttk.Frame(parent)
        row.pack(fill=tk.X, pady=4)

        ttk.Button(row, text="↺ Rafraîchir disques",
                   command=self.refresh_disks).pack(side=tk.LEFT, padx=4)

        self.start_btn = ttk.Button(row, text="▶ Lancer l'analyse",
                                    command=self._start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = ttk.Button(row, text="⏹ Arrêter",
                                   command=self._stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        ttk.Button(row, text="📄 Exporter PDF",
                   command=self._export_pdf).pack(side=tk.LEFT, padx=4)

    # ── Progress ──────────────────────────────────────────────────────────────

    def _build_progress_frame(self, parent: ttk.Frame) -> None:
        lf = ttk.LabelFrame(parent, text="Progression", padding=6)
        lf.pack(fill=tk.X, pady=4)

        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(lf, variable=self.progress_var,
                                        maximum=100, mode="indeterminate")
        self.progress.pack(fill=tk.X, padx=4, pady=2)

        self.status_var = tk.StringVar(value="Prêt")
        ttk.Label(lf, textvariable=self.status_var).pack(anchor=tk.W)

        row = ttk.Frame(lf)
        row.pack(fill=tk.X)
        self.scanned_var  = tk.StringVar(value="Fichiers analysés : 0")
        self.infected_var = tk.StringVar(value="Menaces : 0")
        ttk.Label(row, textvariable=self.scanned_var).pack(side=tk.LEFT, padx=10)
        ttk.Label(row, textvariable=self.infected_var,
                  foreground="red").pack(side=tk.LEFT, padx=10)

    # ── Log ───────────────────────────────────────────────────────────────────

    def _build_log_frame(self, parent: ttk.Frame) -> None:
        lf = ttk.LabelFrame(parent, text="Journal d'activité", padding=6)
        lf.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(lf, wrap=tk.WORD,
                                font=("Courier", 8), bg="#1e1e1e", fg="#d4d4d4",
                                insertbackground="white")
        sb = ttk.Scrollbar(lf, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)
        # colour tags
        self.log_text.tag_config("threat",  foreground="#ff4444")
        self.log_text.tag_config("ok",      foreground="#4ec94e")
        self.log_text.tag_config("warning", foreground="#ffaa00")
        self.log_text.tag_config("info",    foreground="#d4d4d4")

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        btn_row = ttk.Frame(parent)
        btn_row.pack(fill=tk.X, pady=2)
        ttk.Button(btn_row, text="🧹 Vider le journal",
                   command=self._clear_log).pack(side=tk.LEFT, padx=4)

    # ══════════════════════════════════════════════════════════════════════════
    # Engine logic
    # ══════════════════════════════════════════════════════════════════════════

    def _on_engine_change(self) -> None:
        engine = self.engine_var.get()
        self.av.current_engine = engine

        if engine == "avast":
            self.license_frame.pack(fill=tk.X, pady=4,
                                    after=self.license_frame.master.children.get(
                                        list(self.license_frame.master.children)[0],
                                        self.license_frame))
            # Re-pack in correct order
            self.license_frame.pack_forget()
            # Find engine frame and pack license after it
            widgets = list(self.license_frame.master.children.values())
            self.license_frame.pack(fill=tk.X, pady=4)
        else:
            self.license_frame.pack_forget()

        self._refresh_engine_status()
        self._refresh_db_status()

    def _refresh_engine_status(self) -> None:
        engine = self.engine_var.get()
        self.av.current_engine = engine
        status = self.av.engine_status_summary(engine)
        self.engine_status_var.set(status)

        if engine == "avast":
            lic_status = self.av.get_avast_license_status()
            self.license_status_var.set(f"État licence : {lic_status}")
        self._refresh_db_status()

    def _refresh_db_status(self) -> None:
        engine = self.engine_var.get()
        if engine == "clamav":
            info = self.av.get_clamav_db_info()
            s = info["status"]
            lu = info.get("last_update", "inconnue")
            if s == "OK":
                self.db_status_var.set(f"✅ ClamAV – Base OK  (màj : {lu})")
            elif s == "OUTDATED":
                self.db_status_var.set(f"⚠️  ClamAV – Base obsolète  (màj : {lu})")
            else:
                self.db_status_var.set("❌ ClamAV – Base manquante ou incomplète")
        else:
            if self.av.is_avast_installed():
                self.db_status_var.set("ℹ️  Avast – état de la base géré par le service Avast")
            else:
                self.db_status_var.set("❌ Avast non installé")

    # ══════════════════════════════════════════════════════════════════════════
    # License import
    # ══════════════════════════════════════════════════════════════════════════

    def _import_avast_license_usb(self) -> None:
        self._update_log("Recherche de license.avastlic sur les clés USB…")
        licenses = self.av.find_avast_licenses_on_usb()

        if not licenses:
            messagebox.showwarning(
                "Licence introuvable",
                "Aucun fichier license.avastlic trouvé à la racine d'une clé USB.\n\n"
                "Assurez-vous que la clé USB est montée et que le fichier\n"
                "license.avastlic se trouve à sa racine."
            )
            return

        if len(licenses) == 1:
            path = licenses[0]
        else:
            # Let user choose if multiple
            path = self._choose_from_list(
                "Plusieurs licences trouvées",
                "Choisissez la licence à importer :",
                licenses
            )
            if not path:
                return

        self._update_log(f"Import de la licence : {path}")
        ok, msg = self.av.import_avast_license(path)
        if ok:
            messagebox.showinfo("Licence importée", msg)
            self._update_log(f"✅ {msg}")
        else:
            messagebox.showerror("Erreur", msg)
            self._update_log(f"❌ {msg}", tag="threat")
        self._refresh_engine_status()

    def _import_avast_license_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Choisir le fichier de licence Avast",
            filetypes=[("Fichier licence Avast", "*.avastlic"), ("Tous", "*.*")]
        )
        if not path:
            return
        self._update_log(f"Import de la licence : {path}")
        ok, msg = self.av.import_avast_license(path)
        if ok:
            messagebox.showinfo("Licence importée", msg)
            self._update_log(f"✅ {msg}")
        else:
            messagebox.showerror("Erreur", msg)
            self._update_log(f"❌ {msg}", tag="threat")
        self._refresh_engine_status()

    # ══════════════════════════════════════════════════════════════════════════
    # Database update / import
    # ══════════════════════════════════════════════════════════════════════════

    def _update_db_online(self) -> None:
        engine = self.engine_var.get()

        if engine == "clamav" and not self.av.is_freshclam_available():
            messagebox.showerror(
                "freshclam introuvable",
                "freshclam n'est pas installé.\n"
                "Installez-le avec : apt install clamav-freshclam"
            )
            return
        if engine == "avast" and not self.av.is_avast_installed():
            messagebox.showerror("Avast introuvable", "Avast n'est pas installé.")
            return

        self.btn_update_online.configure(state=tk.DISABLED)
        self.btn_import_usb.configure(state=tk.DISABLED)
        self.db_status_var.set("⏳ Mise à jour en cours…")
        self._update_log("Démarrage de la mise à jour de la base virale…")

        def _worker():
            if engine == "clamav":
                ok, msg = self.av.update_clamav_online(
                    progress_cb=lambda l: self.root.after(0, self._update_log, l)
                )
            else:
                ok, msg = self.av.update_avast_online(
                    progress_cb=lambda l: self.root.after(0, self._update_log, l)
                )

            def _done():
                if ok:
                    messagebox.showinfo("Mise à jour terminée", msg)
                    self._update_log(f"✅ {msg}")
                else:
                    messagebox.showerror("Échec de la mise à jour", msg)
                    self._update_log(f"❌ {msg}", tag="threat")
                self._refresh_db_status()
                self.btn_update_online.configure(state=tk.NORMAL)
                self.btn_import_usb.configure(state=tk.NORMAL)

            self.root.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    def _import_db_from_usb(self) -> None:
        engine = self.engine_var.get()

        if engine == "clamav":
            self._import_clamav_db_usb()
        else:
            self._import_avast_vps_usb()

    def _import_clamav_db_usb(self) -> None:
        self._update_log("Recherche des fichiers de base ClamAV sur les clés USB…")
        files = self.av.find_clamav_db_on_usb()

        if not files:
            messagebox.showwarning(
                "Fichiers introuvables",
                "Aucun fichier .cvd ou .cld trouvé sur les clés USB.\n\n"
                "Copiez les fichiers main.cvd / daily.cvd (ou .cld)\n"
                "à la racine d'une clé USB, puis réessayez.\n\n"
                "Ces fichiers sont téléchargeables depuis :\n"
                "https://database.clamav.net/"
            )
            return

        # Show found files for confirmation
        file_list = "\n".join(f"• {os.path.basename(f)}" for f in files)
        if not messagebox.askyesno(
                "Confirmer l'import",
                f"Fichiers trouvés :\n{file_list}\n\n"
                "Importer ces fichiers dans /var/lib/clamav/ ?"
        ):
            return

        self.btn_import_usb.configure(state=tk.DISABLED)
        self.db_status_var.set("⏳ Import en cours…")

        def _worker():
            ok, msg = self.av.import_clamav_db_from_usb(
                files,
                progress_cb=lambda l: self.root.after(0, self._update_log, l)
            )

            def _done():
                if ok:
                    messagebox.showinfo("Import réussi", msg)
                    self._update_log(f"✅ {msg}")
                else:
                    messagebox.showerror("Échec de l'import", msg)
                    self._update_log(f"❌ {msg}", tag="threat")
                self._refresh_db_status()
                self.btn_import_usb.configure(state=tk.NORMAL)

            self.root.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    def _import_avast_vps_usb(self) -> None:
        self._update_log("Recherche des fichiers VPS Avast sur les clés USB…")
        files = self.av.find_avast_vps_on_usb()

        if not files:
            # Offer manual file selection
            path = filedialog.askopenfilename(
                title="Choisir le fichier VPS Avast",
                filetypes=[("Fichiers VPS", "*.vps *.zip *.vpz"),
                            ("Tous", "*.*")]
            )
            if not path:
                messagebox.showwarning(
                    "Fichier introuvable",
                    "Aucun fichier VPS Avast trouvé sur les clés USB.\n"
                    "Téléchargez le fichier VPS depuis votre espace Avast Business."
                )
                return
            files = [path]

        if len(files) > 1:
            chosen = self._choose_from_list(
                "Plusieurs fichiers VPS trouvés",
                "Choisissez le fichier VPS à importer :",
                files
            )
            if not chosen:
                return
            files = [chosen]

        self.btn_import_usb.configure(state=tk.DISABLED)

        def _worker():
            ok, msg = self.av.import_avast_vps_from_usb(
                files[0],
                progress_cb=lambda l: self.root.after(0, self._update_log, l)
            )

            def _done():
                if ok:
                    messagebox.showinfo("Import réussi", msg)
                    self._update_log(f"✅ {msg}")
                else:
                    messagebox.showerror("Échec", msg)
                    self._update_log(f"❌ {msg}", tag="threat")
                self.btn_import_usb.configure(state=tk.NORMAL)

            self.root.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    # Disk selection
    # ══════════════════════════════════════════════════════════════════════════

    def refresh_disks(self) -> None:
        self._update_log("Actualisation de la liste des disques…")
        self.disk_listbox.delete(0, tk.END)
        self.selected_disk_var.set("")

        self.disks = get_disk_list()
        active_list = get_active_disk()
        self.active_disks = set()
        if active_list:
            for d in active_list:
                self.active_disks.add(get_base_disk(d))

        if not self.disks:
            self.disk_info_var.set("Aucun disque détecté")
            return

        for disk in self.disks:
            device  = disk.get("device", "?")
            size    = disk.get("size", "?")
            model   = disk.get("model", "Inconnu")
            base    = get_base_disk(device.replace("/dev/", ""))
            active  = " [ACTIF]" if base in self.active_disks else ""
            ssd_tag = " [SSD]"   if is_ssd(device.replace("/dev/", "")) else ""
            serial  = get_disk_serial(device.replace("/dev/", ""))
            self.disk_listbox.insert(
                tk.END, f"{device}  {size:>8}  {model}{ssd_tag}{active}"
            )
            if base in self.active_disks:
                self.disk_listbox.itemconfig(tk.END, foreground="gray")

        self._update_log(f"{len(self.disks)} disque(s) trouvé(s).")

    def _on_disk_select(self, _event=None) -> None:
        sel = self.disk_listbox.curselection()
        if not sel:
            return
        idx   = sel[0]
        disk  = self.disks[idx]
        dev   = disk.get("device", "")
        self.selected_disk_var.set(dev)

        base = get_base_disk(dev.replace("/dev/", ""))
        ssd  = is_ssd(dev.replace("/dev/", ""))
        serial = get_disk_serial(dev.replace("/dev/", ""))
        info = (f"{dev}  |  {disk.get('size','?')}  |  "
                f"{disk.get('model','?')}  |  "
                f"{'SSD' if ssd else 'HDD'}  |  S/N: {serial}")
        self.disk_info_var.set(info)

        if base in self.active_disks:
            self.disk_warning_var.set(
                "⚠ Ce disque est le disque système actif – analyse en lecture seule uniquement !"
            )
        else:
            self.disk_warning_var.set("")

    # ══════════════════════════════════════════════════════════════════════════
    # Scan
    # ══════════════════════════════════════════════════════════════════════════

    def _start_scan(self) -> None:
        engine = self.engine_var.get()
        device = self.selected_disk_var.get()

        if not device:
            messagebox.showwarning("Aucun disque", "Veuillez sélectionner un disque.")
            return

        if engine == "clamav" and not self.av.is_clamav_installed():
            messagebox.showerror(
                "ClamAV introuvable",
                "ClamAV n'est pas installé.\n"
                "Installez-le avec : apt install clamav clamav-daemon"
            )
            return

        if engine == "avast" and not self.av.is_avast_installed():
            messagebox.showerror(
                "Avast introuvable",
                "Avast n'est pas installé sur ce système."
            )
            return

        base = get_base_disk(device.replace("/dev/", ""))
        if base in self.active_disks:
            if not messagebox.askyesno(
                "Disque actif",
                "Ce disque est le disque système actif.\n"
                "L'analyser peut être lent et perturber le système.\n\n"
                "Continuer quand même ?"
            ):
                return

        if self.remove_infected_var.get():
            if not messagebox.askyesno(
                "Suppression activée",
                "⚠ ATTENTION : La suppression des fichiers infectés est activée.\n"
                "Les fichiers détectés comme malveillants seront DÉFINITIVEMENT supprimés.\n\n"
                "Êtes-vous absolument sûr ?"
            ):
                return

        self.is_scanning = True
        self.scan_results = {"scanned": 0, "infected": 0, "threats": []}
        self.scanned_var.set("Fichiers analysés : 0")
        self.infected_var.set("Menaces : 0")
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.progress.configure(mode="indeterminate")
        self.progress.start()
        self.status_var.set("Analyse en cours…")

        t = threading.Thread(target=self._scan_thread,
                             args=(device,), daemon=True)
        t.start()

    def _scan_thread(self, device: str) -> None:
        try:
            self._perform_scan(device)
            if self.is_scanning:
                summary = (f"Analyse terminée !\n\n"
                           f"Fichiers analysés : {self.scan_results['scanned']}\n"
                           f"Menaces détectées : {self.scan_results['infected']}")
                if self.scan_results["threats"]:
                    summary += "\n\nMenaces :\n" + \
                               "\n".join(self.scan_results["threats"][:10])
                    if len(self.scan_results["threats"]) > 10:
                        summary += (f"\n… et {len(self.scan_results['threats'])-10} "
                                    "autres")

                def _show():
                    self.status_var.set("Analyse terminée")
                    if self.scan_results["infected"] > 0:
                        messagebox.showwarning("Menaces détectées", summary)
                    else:
                        messagebox.showinfo("Analyse terminée", summary)

                self.root.after(0, _show)

        except Exception as e:
            msg = f"Erreur durant l'analyse : {e}"
            log_error(msg)
            self.root.after(0, lambda: (
                self.status_var.set("Échec de l'analyse"),
                self._update_log(msg, tag="threat"),
                messagebox.showerror("Erreur", msg)
            ))
        finally:
            def _cleanup():
                self.is_scanning = False
                self.start_btn.configure(state=tk.NORMAL)
                self.stop_btn.configure(state=tk.DISABLED)
                self.progress.stop()
                self.progress.configure(mode="determinate")

            self.root.after(0, _cleanup)

    def _perform_scan(self, device: str) -> None:
        engine = self.engine_var.get()
        mount_points: List[str] = []
        scan_targets: List[str] = []

        try:
            if self.scan_mode_var.get() == "deep":
                scan_targets, mount_points = self._mount_all_partitions(device)
            else:
                scan_targets = ["/"]
                self.root.after(0, self._update_log,
                                "Mode rapide : analyse des systèmes de fichiers montés")

            if not scan_targets:
                scan_targets = ["/"]
                self.root.after(0, self._update_log,
                                "Aucune partition montée, repli sur /")

            cmd = self.av.build_scan_command(scan_targets,
                                             self.remove_infected_var.get())
            self.root.after(0, self._update_log,
                            f"Commande : {' '.join(cmd)}")

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, universal_newlines=True
            )

            last_ui_update = time.time()
            assert process.stdout is not None

            while process.poll() is None and self.is_scanning:
                line = process.stdout.readline()
                if line:
                    self._handle_scan_line(line.strip(), engine)
                now = time.time()
                if now - last_ui_update > 0.5:
                    self.root.after(0, self.scanned_var.set,
                                    f"Fichiers analysés : {self.scan_results['scanned']}")
                    self.root.after(0, self.root.update_idletasks)
                    last_ui_update = now

            if not self.is_scanning:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
            else:
                # Drain remaining output
                remaining = process.stdout.read()
                if remaining:
                    for line in remaining.split("\n"):
                        if line.strip():
                            self._handle_scan_line(line.strip(), engine)

            self.root.after(0, self.scanned_var.set,
                            f"Fichiers analysés : {self.scan_results['scanned']}")
            self.root.after(0, self.infected_var.set,
                            f"Menaces : {self.scan_results['infected']}")

        finally:
            for mp in mount_points:
                try:
                    subprocess.run(["umount", mp], timeout=10,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    os.rmdir(mp)
                except Exception:
                    try:
                        subprocess.run(["umount", "-f", mp], timeout=5,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
                        os.rmdir(mp)
                    except Exception as e:
                        log_warning(f"Démontage échoué pour {mp} : {e}")

    def _handle_scan_line(self, line: str, engine: str) -> None:
        if not line:
            return

        if engine == "clamav":
            self._parse_clamav_line(line)
        else:
            parsed = self.av.parse_avast_line(line)
            if parsed:
                if parsed["type"] == "threat":
                    self.scan_results["infected"] += 1
                    self.scan_results["threats"].append(parsed["value"])
                    self.root.after(0, self._update_log,
                                    f"🚨 MENACE : {parsed['value']}", "threat")
                    self.root.after(0, self.infected_var.set,
                                    f"Menaces : {self.scan_results['infected']}")
                elif parsed["type"] == "ok":
                    self.scan_results["scanned"] += 1
            else:
                # Generic progress line
                if line.startswith("/"):
                    self.scan_results["scanned"] += 1

    def _parse_clamav_line(self, line: str) -> None:
        if " FOUND" in line or line.endswith(" FOUND"):
            self.scan_results["infected"] += 1
            self.scan_results["threats"].append(line)
            self.root.after(0, self._update_log,
                            f"🚨 MENACE : {line}", "threat")
            self.root.after(0, self.infected_var.set,
                            f"Menaces : {self.scan_results['infected']}")
            return

        if line.startswith("Scanned files:"):
            try:
                self.scan_results["scanned"] = int(line.split(":")[1].strip())
            except (ValueError, IndexError):
                pass
            return

        if line.startswith("Infected files:"):
            try:
                n = int(line.split(":")[1].strip())
                self.scan_results["infected"] = max(
                    self.scan_results["infected"], n)
                self.root.after(0, self.infected_var.set,
                                f"Menaces : {self.scan_results['infected']}")
            except (ValueError, IndexError):
                pass
            return

        if line.endswith(": OK") or line.endswith(": Empty file"):
            self.scan_results["scanned"] += 1
            return

        if "Engine version:" in line or "Known viruses:" in line:
            self.root.after(0, self._update_log, line)

    def _mount_all_partitions(self, device: str) \
            -> tuple[List[str], List[str]]:
        """Mount all partitions of a device; return (targets, mount_points)."""
        targets: List[str]      = []
        mount_points: List[str] = []
        base = device.replace("/dev/", "")

        try:
            out = subprocess.check_output(
                ["lsblk", "-no", "NAME", f"/dev/{base}"],
                text=True, stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError:
            return [], []

        partitions: List[str] = []
        for line in out.strip().split("\n")[1:]:
            p = line.strip().lstrip("├─└─").strip()
            if p and p != base:
                partitions.append(f"/dev/{p}")

        if not partitions:
            self.root.after(0, self._update_log,
                            f"Aucune partition trouvée sur {device}")
            return [], []

        self.root.after(0, self._update_log,
                        f"{len(partitions)} partition(s) trouvée(s) sur {device}")

        for part in partitions:
            mp = f"/tmp/avscan_{part.replace('/','_')}_{int(time.time())}"
            try:
                os.makedirs(mp, exist_ok=True)
                r = subprocess.run(
                    ["mount", "-o", "ro", part, mp],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=30
                )
                if r.returncode == 0:
                    targets.append(mp)
                    mount_points.append(mp)
                    self.root.after(0, self._update_log,
                                    f"Montage de {part} → {mp}")
                else:
                    self.root.after(
                        0, self._update_log,
                        f"Impossible de monter {part} : {r.stderr.strip()}",
                        "warning"
                    )
                    os.rmdir(mp)
            except Exception as e:
                self.root.after(0, self._update_log,
                                f"Erreur montage {part} : {e}", "warning")
                try:
                    os.rmdir(mp)
                except Exception:
                    pass

        return targets, mount_points

    def _stop_scan(self) -> None:
        if self.is_scanning:
            if messagebox.askyesno("Confirmer",
                                   "Arrêter l'analyse en cours ?"):
                self.is_scanning = False
                self._update_log("Analyse arrêtée par l'utilisateur.", "warning")
                self.status_var.set("Analyse arrêtée")

    # ══════════════════════════════════════════════════════════════════════════
    # PDF export
    # ══════════════════════════════════════════════════════════════════════════

    def _export_pdf(self) -> None:
        try:
            from log_handler import generate_session_pdf
            if not self.session_logs:
                messagebox.showinfo("Journal vide",
                                    "Aucune entrée de journal à exporter.")
                return
            path = generate_session_pdf(self.session_logs)
            messagebox.showinfo("PDF exporté",
                                f"Rapport de session exporté :\n{path}")
        except Exception as e:
            messagebox.showerror("Erreur PDF", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # Helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _update_log(self, message: str, tag: str = "info") -> None:
        ts  = time.strftime("%H:%M:%S")
        msg = f"[{ts}] {message}\n"
        self.log_text.insert(tk.END, msg, tag)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        self.session_logs.append(msg.strip())
        log_info(message)

    def _clear_log(self) -> None:
        self.log_text.delete("1.0", tk.END)

    def _toggle_fullscreen(self) -> None:
        current = self.root.attributes("-fullscreen")
        self.root.attributes("-fullscreen", not current)

    def _exit_application(self) -> None:
        if self.is_scanning:
            if not messagebox.askyesno(
                "Analyse en cours",
                "Une analyse est en cours.\nQuitter quand même ?"
            ):
                return
            self.is_scanning = False
        # Démonte proprement les clés USB qu'on a montées
        self.usb.umount_all_managed()
        log_info("Application fermée par l'utilisateur.")
        self.root.destroy()

    @staticmethod
    def _choose_from_list(title: str, prompt: str,
                          items: List[str]) -> Optional[str]:
        """Show a simple listbox dialog and return the selected item."""
        dlg = tk.Toplevel()
        dlg.title(title)
        dlg.grab_set()
        ttk.Label(dlg, text=prompt, padding=8).pack()

        lb = tk.Listbox(dlg, selectmode=tk.SINGLE, width=80, height=10)
        for item in items:
            lb.insert(tk.END, item)
        lb.pack(padx=8, pady=4)
        lb.selection_set(0)

        chosen: List[Optional[str]] = [None]

        def _ok():
            sel = lb.curselection()
            if sel:
                chosen[0] = items[sel[0]]
            dlg.destroy()

        ttk.Button(dlg, text="Sélectionner", command=_ok).pack(pady=6)
        dlg.wait_window()
        return chosen[0]