#!/usr/bin/env python3
"""
gui.py – Interface principale du scanner antiviral USB.
Conçue pour des utilisateurs non-techniques :
  • La zone centrale est dédiée au scan (sélection + bouton unique)
  • Toutes les actions d'administration sont regroupées dans un panneau
    protégé par code (mise à jour bases, import hors-ligne, planification,
    changement du code, quitter)
"""

import os
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Dict, List, Optional

from admin_auth import AdminAuthManager, AdminPanel
from config import YARA_RULES_DIR
from db_manager import DBManager
from log_handler import generate_session_pdf, log_error, log_info, log_warning
from scanner import ScanEngine, ScanResult
from usb_manager import UsbManager, UsbPartition


# ══════════════════════════════════════════════════════════════════════════════
class VirusScannerGUI:

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("🛡  USB Antivirus Scanner")
        self.root.attributes("-fullscreen", True)
        self.root.configure(bg="#1a1a2e")

        # ── Composants métier ──
        self.usb     = UsbManager()
        self.db      = DBManager(usb_manager=self.usb)
        self.engine  = ScanEngine()
        self.auth    = AdminAuthManager()

        # ── État ──────────────────────────────────────────────────────────────
        self.is_scanning    = False
        self.session_logs:  List[str] = []
        self._usb_partitions: List[UsbPartition] = []

        # ── Check root ────────────────────────────────────────────────────────
        if os.geteuid() != 0:
            messagebox.showerror("Droits insuffisants",
                                 "Ce programme doit être lancé avec sudo.")
            root.destroy()
            sys.exit(1)

        self._build_ui()
        self._refresh_status()
        self._refresh_usb()
        self.root.protocol("WM_DELETE_WINDOW", self._request_admin)

    # ══════════════════════════════════════════════════════════════════════════
    # Construction de l'interface
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ui(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Title.TLabel",
                         background="#1a1a2e", foreground="#e0e0e0",
                         font=("Arial", 16, "bold"))
        style.configure("Status.TLabel",
                         background="#0f3460", foreground="#e0e0e0",
                         font=("Courier", 9), padding=4)
        style.configure("BigScan.TButton",
                         font=("Arial", 14, "bold"), padding=14)
        style.configure("Admin.TButton",
                         font=("Arial", 9), padding=4)

        # ── Barre de titre ────────────────────────────────────────────────────
        topbar = tk.Frame(self.root, bg="#0f3460", pady=6)
        topbar.pack(fill=tk.X)

        tk.Label(topbar, text="🛡  USB Antivirus Scanner",
                 font=("Arial", 15, "bold"),
                 bg="#0f3460", fg="#e0e0e0").pack(side=tk.LEFT, padx=12)

        tk.Button(topbar, text="⛶  Plein écran",
                  command=self._toggle_fullscreen,
                  bg="#16213e", fg="#aaa", relief=tk.FLAT,
                  font=("Arial", 9), padx=8).pack(side=tk.RIGHT, padx=4)
        tk.Button(topbar, text="⚙  Administration",
                  command=self._request_admin,
                  bg="#e94560", fg="white", relief=tk.FLAT,
                  font=("Arial", 9, "bold"), padx=10).pack(side=tk.RIGHT, padx=8)

        # ── Bandeau état des moteurs ──────────────────────────────────────────
        status_bar = tk.Frame(self.root, bg="#0f3460", pady=2)
        status_bar.pack(fill=tk.X)

        self.clamav_status_var = tk.StringVar(value="ClamAV : vérification…")
        self.yara_status_var   = tk.StringVar(value="YARA : vérification…")

        tk.Label(status_bar, textvariable=self.clamav_status_var,
                 bg="#0f3460", fg="#90ee90",
                 font=("Courier", 9), padx=12).pack(side=tk.LEFT)
        tk.Label(status_bar, textvariable=self.yara_status_var,
                 bg="#0f3460", fg="#90ee90",
                 font=("Courier", 9), padx=12).pack(side=tk.LEFT)

        # ── Corps principal ───────────────────────────────────────────────────
        body = tk.Frame(self.root, bg="#1a1a2e")
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        left  = tk.Frame(body, bg="#1a1a2e")
        right = tk.Frame(body, bg="#1a1a2e")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 6))
        left.configure(width=420)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self._build_usb_panel(left)
        self._build_scan_options(left)
        self._build_scan_controls(left)
        self._build_progress_panel(left)
        self._build_log_panel(right)

    # ── Panneau USB ───────────────────────────────────────────────────────────

    def _build_usb_panel(self, parent: tk.Frame) -> None:
        frm = self._lframe(parent, "Clés USB / Disques amovibles", fill=tk.BOTH, expand=False)

        cols = ("device", "label", "size", "fstype", "status")
        self.usb_tree = ttk.Treeview(frm, columns=cols, show="headings",
                                      height=5, selectmode="browse")
        for cid, heading, width in [
            ("device", "Périphérique", 100),
            ("label",  "Étiquette",     90),
            ("size",   "Taille",        60),
            ("fstype", "FS",            60),
            ("status", "État",         180),
        ]:
            self.usb_tree.heading(cid, text=heading)
            self.usb_tree.column(cid, width=width, minwidth=30, anchor=tk.W)

        self.usb_tree.tag_configure("ro",      background="#d4edda")
        self.usb_tree.tag_configure("rw",      background="#fff3cd")
        self.usb_tree.tag_configure("unmount", background="#f8f9fa")

        usb_sb = ttk.Scrollbar(frm, orient=tk.VERTICAL, command=self.usb_tree.yview)
        self.usb_tree.configure(yscrollcommand=usb_sb.set)
        self.usb_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        usb_sb.pack(side=tk.LEFT, fill=tk.Y)

        btn_col = tk.Frame(frm, bg="#1a1a2e")
        btn_col.pack(side=tk.LEFT, padx=(6, 0))
        for txt, cmd in [
            ("↺ Actualiser",  self._refresh_usb),
            ("▲ Monter RO",   self._mount_usb),
            ("▼ Démonter",    self._umount_usb),
        ]:
            tk.Button(btn_col, text=txt, command=cmd, width=13,
                      bg="#16213e", fg="#e0e0e0", relief=tk.FLAT,
                      font=("Arial", 9), pady=4).pack(fill=tk.X, pady=2)

        self.usb_info_var = tk.StringVar(value="")
        tk.Label(frm, textvariable=self.usb_info_var,
                 bg="#1a1a2e", fg="#aaa",
                 font=("Arial", 8)).pack(side=tk.BOTTOM, anchor=tk.W, pady=2)

        self.usb_tree.bind("<<TreeviewSelect>>", self._on_usb_select)

    # ── Options de scan ───────────────────────────────────────────────────────

    def _build_scan_options(self, parent: tk.Frame) -> None:
        frm = self._lframe(parent, "Options d'analyse")

        # Mode
        self.scan_mode_var = tk.StringVar(value="quick")
        row1 = tk.Frame(frm, bg="#16213e"); row1.pack(fill=tk.X, pady=2)
        tk.Label(row1, text="Mode :", bg="#16213e", fg="#e0e0e0",
                 width=10, anchor=tk.E).pack(side=tk.LEFT)
        for txt, val in [("Rapide", "quick"), ("Complet", "deep")]:
            tk.Radiobutton(row1, text=txt, variable=self.scan_mode_var,
                           value=val, bg="#16213e", fg="#e0e0e0",
                           selectcolor="#0f3460",
                           activebackground="#16213e",
                           font=("Arial", 9)).pack(side=tk.LEFT, padx=8)

        # YARA
        self.use_yara_var = tk.BooleanVar(value=True)
        row2 = tk.Frame(frm, bg="#16213e"); row2.pack(fill=tk.X, pady=2)
        tk.Checkbutton(row2, text="Activer l'analyse YARA",
                       variable=self.use_yara_var,
                       bg="#16213e", fg="#e0e0e0",
                       selectcolor="#0f3460",
                       activebackground="#16213e",
                       font=("Arial", 9)).pack(side=tk.LEFT, padx=(80, 0))

        # Suppression
        self.remove_var = tk.BooleanVar(value=False)
        row3 = tk.Frame(frm, bg="#16213e"); row3.pack(fill=tk.X, pady=2)
        tk.Checkbutton(row3,
                       text="⚠  Supprimer les fichiers infectés (DANGER)",
                       variable=self.remove_var,
                       bg="#16213e", fg="#ffaa00",
                       selectcolor="#0f3460",
                       activebackground="#16213e",
                       font=("Arial", 9)).pack(side=tk.LEFT, padx=(10, 0))

    # ── Boutons de contrôle ───────────────────────────────────────────────────

    def _build_scan_controls(self, parent: tk.Frame) -> None:
        frm = tk.Frame(parent, bg="#1a1a2e")
        frm.pack(fill=tk.X, pady=8)

        self.scan_btn = tk.Button(
            frm, text="▶  LANCER L'ANALYSE",
            command=self._start_scan,
            bg="#e94560", fg="white", relief=tk.FLAT,
            font=("Arial", 13, "bold"), pady=10, padx=20
        )
        self.scan_btn.pack(fill=tk.X, padx=4, pady=2)

        self.stop_btn = tk.Button(
            frm, text="⏹  Arrêter",
            command=self._stop_scan,
            bg="#555", fg="white", relief=tk.FLAT,
            font=("Arial", 10), pady=6, state=tk.DISABLED
        )
        self.stop_btn.pack(fill=tk.X, padx=4, pady=2)

        tk.Button(
            frm, text="📄  Exporter rapport PDF",
            command=self._export_pdf,
            bg="#16213e", fg="#aaa", relief=tk.FLAT,
            font=("Arial", 9), pady=4
        ).pack(fill=tk.X, padx=4, pady=2)

    # ── Progression ───────────────────────────────────────────────────────────

    def _build_progress_panel(self, parent: tk.Frame) -> None:
        frm = self._lframe(parent, "Progression")

        self.progress = ttk.Progressbar(frm, mode="indeterminate",
                                         length=300)
        self.progress.pack(fill=tk.X, padx=4, pady=4)

        self.status_var = tk.StringVar(value="Prêt")
        tk.Label(frm, textvariable=self.status_var,
                 bg="#16213e", fg="#e0e0e0",
                 font=("Arial", 9)).pack(anchor=tk.W)

        counters = tk.Frame(frm, bg="#16213e")
        counters.pack(fill=tk.X)
        self.scanned_var  = tk.StringVar(value="Analysés : 0")
        self.infected_var = tk.StringVar(value="Menaces : 0")
        tk.Label(counters, textvariable=self.scanned_var,
                 bg="#16213e", fg="#90ee90",
                 font=("Courier", 9)).pack(side=tk.LEFT, padx=8)
        tk.Label(counters, textvariable=self.infected_var,
                 bg="#16213e", fg="#ff6b6b",
                 font=("Courier", 9, "bold")).pack(side=tk.LEFT, padx=8)

    # ── Journal ───────────────────────────────────────────────────────────────

    def _build_log_panel(self, parent: tk.Frame) -> None:
        header = tk.Frame(parent, bg="#1a1a2e")
        header.pack(fill=tk.X, pady=(4, 2))
        tk.Label(header, text="Journal d'activité",
                 bg="#1a1a2e", fg="#aaa",
                 font=("Arial", 9, "bold")).pack(side=tk.LEFT)
        tk.Button(header, text="🧹 Vider",
                  command=self._clear_log,
                  bg="#16213e", fg="#aaa", relief=tk.FLAT,
                  font=("Arial", 8)).pack(side=tk.RIGHT)

        self.log_text = tk.Text(parent, bg="#0d0d0d", fg="#d4d4d4",
                                font=("Courier", 8), wrap=tk.WORD,
                                state=tk.NORMAL, insertbackground="white")
        sb = ttk.Scrollbar(parent, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)

        self.log_text.tag_config("threat",  foreground="#ff4444")
        self.log_text.tag_config("ok",      foreground="#4ec94e")
        self.log_text.tag_config("warning", foreground="#ffaa00")
        self.log_text.tag_config("info",    foreground="#888888")
        self.log_text.tag_config("normal",  foreground="#d4d4d4")

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    # ══════════════════════════════════════════════════════════════════════════
    # Helpers UI
    # ══════════════════════════════════════════════════════════════════════════

    def _lframe(self, parent: tk.Frame, title: str,
                fill=tk.X, expand=False, pady=4) -> tk.Frame:
        """
        Crée un cadre avec bordure et titre stylisé, le pack dans parent,
        et retourne le cadre intérieur prêt à recevoir des widgets.
        """
        outer = tk.Frame(parent, bg="#16213e", bd=1, relief=tk.SOLID)
        outer.pack(fill=fill, expand=expand, pady=pady)
        tk.Label(outer, text=f"  {title}  ",
                 bg="#16213e", fg="#aaa",
                 font=("Arial", 8, "bold")).pack(anchor=tk.W, padx=4, pady=(4, 0))
        inner = tk.Frame(outer, bg="#16213e", padx=6, pady=4)
        inner.pack(fill=tk.BOTH, expand=True)
        return inner

    def _log(self, msg: str, tag: str = "normal") -> None:
        ts  = time.strftime("%H:%M:%S")
        line = f"[{ts}]  {msg}\n"
        self.log_text.insert(tk.END, line, tag)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        self.session_logs.append(line.strip())
        log_info(msg)

    def _clear_log(self) -> None:
        self.log_text.delete("1.0", tk.END)

    def _toggle_fullscreen(self) -> None:
        self.root.attributes("-fullscreen",
                              not self.root.attributes("-fullscreen"))

    # ══════════════════════════════════════════════════════════════════════════
    # Statut des moteurs
    # ══════════════════════════════════════════════════════════════════════════

    def _refresh_status(self) -> None:
        # ClamAV
        if not self.engine.is_clamav_installed():
            self.clamav_status_var.set("❌  ClamAV : non installé")
        else:
            info = self.db.get_clamav_status()
            st   = info["status"]
            lu   = info.get("last_update", "?")
            if st == "OK":
                self.clamav_status_var.set(f"✅  ClamAV : base OK  (màj : {lu})")
            elif st == "OUTDATED":
                self.clamav_status_var.set(f"⚠   ClamAV : base obsolète  ({lu})")
            else:
                self.clamav_status_var.set("❌  ClamAV : base manquante")

        # YARA
        ok, method = self.engine.detect_yara()
        if not ok:
            self.yara_status_var.set("❌  YARA : non installé")
        else:
            info = self.db.get_yara_status()
            n    = info["count"]
            lu   = info.get("last_update", "?")
            if n > 0:
                self.yara_status_var.set(f"✅  YARA ({method}) : {n} règle(s)  (màj : {lu})")
            else:
                self.yara_status_var.set(f"⚠   YARA ({method}) : aucune règle installée")

    # ══════════════════════════════════════════════════════════════════════════
    # Gestion USB
    # ══════════════════════════════════════════════════════════════════════════

    def _refresh_usb(self) -> None:
        selected_dev = self._selected_usb()
        for row in self.usb_tree.get_children():
            self.usb_tree.delete(row)

        self._usb_partitions = self.usb.list_partitions()

        if not self._usb_partitions:
            self.usb_tree.insert("", tk.END,
                                  values=("—", "—", "—", "—",
                                          "Aucune clé USB détectée"))
            return

        reselect = None
        for p in self._usb_partitions:
            mp = self.usb.get_mountpoint(p.device)
            if mp:
                ro = self.usb._is_ro(p.device, mp)
                status = (f"✅ Monté RO → {mp}" if ro
                          else f"⚠  Monté RW → {mp}")
                tag    = "ro" if ro else "rw"
            else:
                status = "⏏  Non monté"
                tag    = "unmount"

            iid = self.usb_tree.insert("", tk.END, iid=p.device,
                                        values=(p.device,
                                                p.label or "—",
                                                p.size,
                                                p.fstype,
                                                status),
                                        tags=(tag,))
            if p.device == selected_dev:
                reselect = iid

        if reselect:
            self.usb_tree.selection_set(reselect)

    def _on_usb_select(self, _=None) -> None:
        dev = self._selected_usb()
        if not dev:
            self.usb_info_var.set("")
            return
        mp = self.usb.get_mountpoint(dev)
        self.usb_info_var.set(
            f"Point de montage : {mp}" if mp else f"{dev} — non monté"
        )

    def _selected_usb(self) -> Optional[str]:
        sel = self.usb_tree.selection()
        if not sel:
            return None
        vals = self.usb_tree.item(sel[0], "values")
        if not vals or vals[0] == "—":
            return None
        return vals[0]

    def _mount_usb(self) -> None:
        dev = self._selected_usb()
        if not dev:
            messagebox.showwarning("Sélection", "Sélectionnez une clé USB.",
                                    parent=self.root)
            return
        self._log(f"Montage de {dev}…")

        def _worker():
            ok, msg = self.usb.mount(
                dev,
                progress_cb=lambda m: self.root.after(0, self._log, m)
            )
            def _done():
                self._log(f"{'✅' if ok else '❌'} {msg}",
                           "ok" if ok else "threat")
                self._refresh_usb()
            self.root.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    def _umount_usb(self) -> None:
        dev = self._selected_usb()
        if not dev:
            messagebox.showwarning("Sélection", "Sélectionnez une clé USB.",
                                    parent=self.root)
            return
        self._log(f"Démontage de {dev}…")

        def _worker():
            ok, msg = self.usb.umount(
                dev,
                progress_cb=lambda m: self.root.after(0, self._log, m)
            )
            def _done():
                self._log(f"{'✅' if ok else '❌'} {msg}",
                           "ok" if ok else "threat")
                self._refresh_usb()
            self.root.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    # Scan
    # ══════════════════════════════════════════════════════════════════════════

    def _start_scan(self) -> None:
        if self.is_scanning:
            return

        # Vérifications
        if not self.engine.is_clamav_installed():
            messagebox.showerror(
                "ClamAV manquant",
                "ClamAV n'est pas installé.\n"
                "Installez-le : apt install clamav clamav-daemon clamav-freshclam",
                parent=self.root
            )
            return

        dev = self._selected_usb()
        if not dev:
            messagebox.showwarning(
                "Aucun périphérique",
                "Sélectionnez une clé USB ou un disque dans la liste.",
                parent=self.root
            )
            return

        # Obtenir le point de montage, monter si nécessaire
        mp = self.usb.get_mountpoint(dev)
        if not mp:
            if not messagebox.askyesno(
                "Monter le périphérique",
                f"{dev} n'est pas monté.\nLe monter en lecture seule maintenant ?",
                parent=self.root
            ):
                return
            ok, msg = self.usb.mount(dev)
            if not ok:
                messagebox.showerror("Erreur de montage", msg, parent=self.root)
                return
            self._refresh_usb()
            mp = self.usb.get_mountpoint(dev)

        if not mp:
            messagebox.showerror("Erreur", "Impossible d'obtenir le point de montage.",
                                  parent=self.root)
            return

        if self.remove_var.get():
            if not messagebox.askyesno(
                "⚠ Suppression activée",
                "Les fichiers infectés seront DÉFINITIVEMENT supprimés.\n"
                "Êtes-vous certain ?",
                parent=self.root
            ):
                return

        # Lance le scan
        self.is_scanning = True
        self.scan_btn.configure(state=tk.DISABLED, bg="#555")
        self.stop_btn.configure(state=tk.NORMAL, bg="#e94560")
        self.progress.configure(mode="indeterminate")
        self.progress.start(10)
        self.status_var.set("Analyse en cours…")
        self.scanned_var.set("Analysés : 0")
        self.infected_var.set("Menaces : 0")

        self._log(f"Démarrage de l'analyse : {dev} → {mp}", "info")

        targets = self._get_scan_targets(dev, mp)

        threading.Thread(
            target=self._scan_thread,
            args=(targets,),
            daemon=True
        ).start()

    def _get_scan_targets(self, device: str, mountpoint: str) -> List[str]:
        """
        Mode rapide : utilise le point de montage existant.
        Mode complet : monte toutes les partitions du disque parent.
        """
        if self.scan_mode_var.get() == "quick":
            self._log(f"Mode rapide : {mountpoint}")
            return [mountpoint]

        # Mode complet : cherche toutes les partitions du disque parent
        import subprocess as _sp
        targets = []
        try:
            p = self._find_partition(device)
            out = _sp.check_output(
                ["lsblk", "-no", "NAME", f"/dev/{p}"],
                text=True, stderr=_sp.PIPE
            )
            for line in out.strip().splitlines()[1:]:
                part = "/dev/" + line.strip().lstrip("├─└─").strip()
                if part == device:
                    targets.append(mountpoint)
                    continue
                ok, msg = self.usb.mount(part)
                if ok:
                    mp2 = self.usb.get_mountpoint(part)
                    if mp2:
                        targets.append(mp2)
                        self._log(f"Partition supplémentaire montée : {part} → {mp2}")
                else:
                    self._log(f"Partition ignorée ({part}) : {msg}", "warning")
        except Exception:
            targets = [mountpoint]

        return targets or [mountpoint]

    def _find_partition(self, device: str) -> str:
        """Retourne le nom du disque parent (ex: sdb1 → sdb)."""
        import re
        name = device.replace("/dev/", "")
        m    = re.match(r"([a-z]+)", name)
        return m.group(1) if m else name

    def _scan_thread(self, targets: List[str]) -> None:
        _scanned_last = [0]
        _infected_last = [0]

        def _progress(msg: str, tag: str = "normal") -> None:
            self.root.after(0, self._log, msg, tag)
            # Mise à jour des compteurs depuis le résultat partiel
            # (géré par le moteur en direct via les callbacks)

        try:
            result = self.engine.scan(
                targets       = targets,
                use_clamav    = True,
                use_yara      = self.use_yara_var.get(),
                remove_infected = self.remove_var.get(),
                progress_cb   = _progress,
            )
        except Exception as e:
            result = None
            msg = f"Erreur fatale durant le scan : {e}"
            log_error(msg)
            self.root.after(0, self._log, msg, "threat")

        self.root.after(0, self._scan_done, result)

    def _scan_done(self, result: Optional[ScanResult]) -> None:
        self.is_scanning = False
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.scan_btn.configure(state=tk.NORMAL, bg="#e94560")
        self.stop_btn.configure(state=tk.DISABLED, bg="#555")

        if result is None:
            self.status_var.set("Erreur durant le scan")
            return

        self.scanned_var.set(f"Analysés : {result.scanned}")
        self.infected_var.set(f"Menaces : {result.infected}")

        if result.stopped:
            self.status_var.set("Analyse interrompue")
            self._log("Analyse arrêtée par l'utilisateur.", "warning")
            return

        self.status_var.set("Analyse terminée")
        summary = result.summary()

        if result.infected > 0:
            self._log(f"⚠  {result.infected} menace(s) détectée(s) !", "threat")
            messagebox.showwarning("Menaces détectées", summary, parent=self.root)
        else:
            self._log("✅ Aucune menace détectée.", "ok")
            messagebox.showinfo("Analyse terminée", summary, parent=self.root)

        self._log(f"Durée : {result.duration:.1f}s", "info")

        for err in result.errors:
            self._log(err, "warning")

    def _stop_scan(self) -> None:
        if self.is_scanning:
            self.engine.request_stop()
            self.status_var.set("Arrêt en cours…")
            self.stop_btn.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════════
    # Administration (protégée par code)
    # ══════════════════════════════════════════════════════════════════════════

    def _request_admin(self) -> None:
        panel = AdminPanel(
            parent               = self.root,
            auth                 = self.auth,
            on_update_clamav_online = self._admin_clamav_online,
            on_import_clamav_usb    = self._admin_clamav_usb,
            on_update_yara_online   = self._admin_yara_online,
            on_import_yara_usb      = self._admin_yara_usb,
            on_quit                 = self._quit,
        )
        panel.show()

    # ── Actions admin ClamAV ──────────────────────────────────────────────────

    def _admin_clamav_online(self) -> None:
        if not self.engine.is_freshclam_available():
            messagebox.showerror(
                "freshclam manquant",
                "Installez clamav-freshclam : apt install clamav-freshclam",
                parent=self.root
            )
            return
        self._log("Mise à jour ClamAV en ligne…", "info")
        self._run_background(
            task=lambda cb: self.db.update_clamav_online(progress_cb=cb),
            label="ClamAV online update",
            on_done=lambda ok, msg: self._refresh_status()
        )

    def _admin_clamav_usb(self) -> None:
        self._log("Recherche de fichiers ClamAV sur les clés USB…", "info")
        files = self.db.find_clamav_on_usb()
        if not files:
            messagebox.showwarning(
                "Introuvable",
                "Aucun fichier .cvd / .cld trouvé sur les clés USB.\n\n"
                "Téléchargez main.cvd, daily.cvd, bytecode.cvd depuis :\n"
                "https://database.clamav.net/\n"
                "et copiez-les à la racine d'une clé USB.",
                parent=self.root
            )
            return
        names = "\n".join(f"• {os.path.basename(f)}" for f in files)
        if not messagebox.askyesno(
            "Confirmer l'import",
            f"Fichiers trouvés :\n{names}\n\nImporter vers /var/lib/clamav/ ?",
            parent=self.root
        ):
            return
        self._run_background(
            task=lambda cb: self.db.import_clamav_from_usb(files,
                                                             progress_cb=cb),
            label="ClamAV import USB",
            on_done=lambda ok, msg: self._refresh_status()
        )

    # ── Actions admin YARA ────────────────────────────────────────────────────

    def _admin_yara_online(self) -> None:
        self._log("Téléchargement de signature-base (GitHub)…", "info")
        self._run_background(
            task=lambda cb: self.db.update_yara_online(progress_cb=cb),
            label="YARA online update",
            on_done=lambda ok, msg: self._refresh_status()
        )

    def _admin_yara_usb(self) -> None:
        self._log("Recherche de règles YARA sur les clés USB…", "info")
        files = self.db.find_yara_on_usb()
        if not files:
            messagebox.showwarning(
                "Introuvable",
                "Aucun fichier .yar / .yara / .zip trouvé sur les clés USB.\n\n"
                "Téléchargez des règles depuis :\n"
                "• https://github.com/Neo23x0/signature-base\n"
                "• https://github.com/Yara-Rules/rules",
                parent=self.root
            )
            return
        count = len(files)
        if not messagebox.askyesno(
            "Confirmer l'import",
            f"{count} fichier(s) de règles trouvé(s).\n"
            f"Importer vers {YARA_RULES_DIR}/custom/ ?",
            parent=self.root
        ):
            return
        self._run_background(
            task=lambda cb: self.db.import_yara_from_usb(files, progress_cb=cb),
            label="YARA import USB",
            on_done=lambda ok, msg: self._refresh_status()
        )

    # ── Worker générique en arrière-plan ──────────────────────────────────────

    def _run_background(self, task, label: str, on_done=None) -> None:
        def _worker():
            def _cb(msg):
                self.root.after(0, self._log, msg)
            ok, msg = task(_cb)
            self.root.after(0, self._log,
                            f"{'✅' if ok else '❌'} {msg}",
                            "ok" if ok else "threat")
            if on_done:
                self.root.after(0, on_done, ok, msg)
            if ok:
                self.root.after(0, messagebox.showinfo, label, msg)
            else:
                self.root.after(0, messagebox.showerror, label, msg)

        threading.Thread(target=_worker, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    # PDF export & quitter
    # ══════════════════════════════════════════════════════════════════════════

    def _export_pdf(self) -> None:
        if not self.session_logs:
            messagebox.showinfo("Journal vide",
                                "Aucune entrée à exporter.",
                                parent=self.root)
            return
        try:
            path = generate_session_pdf(self.session_logs)
            messagebox.showinfo("PDF exporté", f"Rapport enregistré :\n{path}",
                                parent=self.root)
        except Exception as e:
            messagebox.showerror("Erreur PDF", str(e), parent=self.root)

    def _quit(self) -> None:
        if self.is_scanning:
            if not messagebox.askyesno(
                "Analyse en cours",
                "Une analyse est en cours. Quitter quand même ?",
                parent=self.root
            ):
                return
            self.engine.request_stop()
        self.usb.umount_all()
        log_info("Application fermée.")
        self.root.destroy()