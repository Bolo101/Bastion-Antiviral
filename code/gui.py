#!/usr/bin/env python3
"""
gui.py – Interface principale du scanner antiviral USB.

Interface utilisateur :
  • Sélection multi-clés USB → scans parallèles par threading
  • Journal d'activité (colonne centrale)
  • Visionneuse PDF cyclique (colonne droite) — ../pdf/, tri alpha, 35 s/page
  • Bouton lancer / annuler

Administration (protégée par code) :
  • Moteurs actifs (ClamAV / Avast / YARA) + mode scan + suppression
  • Affichage exhaustif des supports USB
  • Mise à jour ClamAV, Avast, YARA
  • Planification crontab
  • Journaux : export, purge
  • Sécurité (code admin), Arrêt, Quitter

Dépendances optionnelles pour la visionneuse PDF :
  pip install pymupdf pillow
"""

import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Dict, List, Optional

from pdf_viewer import PdfViewer, RenderedPage

from admin_auth import AdminAuthManager, AdminPanel
from config import YARA_RULES_DIR, ADMIN_CFG_DIR
from db_manager import DBManager
from log_handler import (export_logs_to_path, generate_session_pdf,
                          log_error, log_info, log_warning, purge_logs)
from scanner import ScanEngine, ScanResult
from usb_manager import UsbManager, UsbPartition


# ══════════════════════════════════════════════════════════════════════════════
class VirusScannerGUI:

    # ── Couleurs ──────────────────────────────────────────────────────────────
    BG       = "#1a1a2e"
    TOPBAR   = "#0f3460"
    CARD     = "#16213e"
    ACCENT   = "#e94560"
    FG       = "#e0e0e0"
    FG_DIM   = "#8899aa"
    GREEN    = "#4ec94e"
    YELLOW   = "#ffaa00"
    RED      = "#ff4444"

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("🛡  USB Antivirus Scanner")
        self.root.attributes("-fullscreen", True)
        self.root.configure(bg=self.BG)

        # ── Composants métier ──────────────────────────────────────────────────
        self.usb    = UsbManager()
        self.db     = DBManager(usb_manager=self.usb)
        self.engine = ScanEngine()
        self.auth   = AdminAuthManager()

        # ── État global ────────────────────────────────────────────────────────
        self._usb_partitions: List[UsbPartition] = []
        self.session_logs:    List[str] = []

        # Options de scan (modifiables depuis le panneau admin)
        self.use_clamav_var = tk.BooleanVar(value=True)
        self.use_avast_var  = tk.BooleanVar(value=False)
        self.use_yara_var   = tk.BooleanVar(value=True)
        self.scan_mode_var  = tk.StringVar(value="quick")
        self.remove_var     = tk.BooleanVar(value=False)

        # ── Suivi des scans parallèles ─────────────────────────────────────────
        self._scan_engines:  Dict[str, ScanEngine] = {}   # dev → engine
        self._targets_map:   Dict[str, str]         = {}   # dev → mountpoint
        self._scan_lock      = threading.Lock()
        self._active_scans   = 0
        self._total_scanned  = 0
        self._total_infected = 0
        self._per_dev_scanned:  Dict[str, int] = {}   # comptage temps réel par device
        self._per_dev_infected: Dict[str, int] = {}   # menaces temps réel par device

        # ── Animation (état conservé pour compatibilité scan) ─────────────────
        self._anim_after_id: Optional[str] = None
        self._anim_phase    = 0.0
        self._anim_state    = "idle"   # idle | scanning | ok | threat

        # ── Auto-actualisation USB ─────────────────────────────────────────────
        self._auto_refresh_id: Optional[str] = None

        # ── Statistiques cumulées (toutes sessions) ───────────────────────────
        self._stats_file = os.path.join(ADMIN_CFG_DIR, "scan_stats.json")
        self._total_keys_scanned: int       = 0   # nombre de clés USB analysées
        self._cumul_threats:      int       = 0   # menaces cumulées toutes sessions
        self._threat_details:     List[dict] = []  # [{file, hash, threat, ts}]
        self._session_threats:    List       = []  # ThreatInfo de la session en cours (dédupliqués)
        self._session_seen_hashes: set      = set()  # hashes déjà vus dans la session

        # Chargement des stats persistantes depuis le fichier JSON
        self._load_persistent_stats()

        # ── Visionneuse PDF ───────────────────────────────────────────────────
        self._pdf_viewer:   Optional[PdfViewer] = None
        self._pdf_tk_image: Optional[object]    = None   # référence anti-GC
        self._pdf_canvas:   Optional[tk.Canvas]  = None

        # ── Répertoire PDF ────────────────────────────────────────────────────
        self._pdf_dir = os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pdf")
        )

        if os.geteuid() != 0:
            messagebox.showerror("Droits insuffisants",
                                 "Ce programme doit être lancé avec sudo.")
            root.destroy()
            sys.exit(1)

        self._build_ui()
        self._refresh_status()
        self._start_auto_refresh()
        self._init_pdf_viewer()
        self.root.protocol("WM_DELETE_WINDOW", self._request_admin)

    # ══════════════════════════════════════════════════════════════════════════
    # Persistance des statistiques
    # ══════════════════════════════════════════════════════════════════════════

    def _load_persistent_stats(self) -> None:
        """Charge les compteurs et le tableau des menaces depuis le fichier JSON."""
        try:
            if os.path.isfile(self._stats_file):
                with open(self._stats_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._total_keys_scanned = int(data.get("keys_scanned", 0))
                self._cumul_threats      = int(data.get("cumul_threats", 0))
                self._threat_details     = data.get("threat_details", [])
                # Reconstruire le set des hashes déjà vus (déduplication inter-sessions)
                self._session_seen_hashes = {
                    d.get("hash", d.get("file", ""))
                    for d in self._threat_details
                    if d.get("hash", "N/A") not in ("", "N/A")
                }
        except Exception as e:
            log_error(f"Impossible de charger les stats persistantes : {e}")

    def _save_persistent_stats(self) -> None:
        """Sauvegarde les compteurs et le tableau des menaces dans le fichier JSON."""
        try:
            os.makedirs(os.path.dirname(self._stats_file), exist_ok=True)
            data = {
                "keys_scanned":   self._total_keys_scanned,
                "cumul_threats":  self._cumul_threats,
                "threat_details": self._threat_details,
            }
            with open(self._stats_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            log_error(f"Impossible de sauvegarder les stats : {e}")

    def _purge_threats(self) -> None:
        """Vide le tableau des menaces et remet à zéro le compteur de menaces."""
        self._threat_details     = []
        self._cumul_threats      = 0
        self._session_threats    = []
        self._session_seen_hashes = set()
        self._save_persistent_stats()
        self._log("🗑 Tableau des menaces purgé.", "warning")

    def _purge_counters(self) -> None:
        """Remet à zéro uniquement les compteurs (clés scannées + menaces)."""
        self._total_keys_scanned = 0
        self._cumul_threats      = 0
        self._save_persistent_stats()
        self._log("🗑 Compteurs de session remis à zéro.", "warning")

    # ══════════════════════════════════════════════════════════════════════════
    # Construction de l'interface
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ui(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame",        background=self.BG)
        style.configure("Card.TFrame",   background=self.CARD)
        style.configure("TLabel",        background=self.BG, foreground=self.FG)
        style.configure("Card.TLabel",   background=self.CARD, foreground=self.FG)
        style.configure("TNotebook",     background=self.BG)
        style.configure("TScrollbar",    background=self.CARD, troughcolor=self.BG)

        # ── Barre de titre ────────────────────────────────────────────────────
        topbar = tk.Frame(self.root, bg=self.TOPBAR, pady=8)
        topbar.pack(fill=tk.X)

        tk.Label(topbar, text="🛡  USB Antivirus Scanner",
                 font=("Arial", 16, "bold"),
                 bg=self.TOPBAR, fg=self.FG).pack(side=tk.LEFT, padx=16)

        self._subtitle_lbl = tk.Label(topbar, text="Protection de vos données amovibles",
                 font=("Arial", 9, "italic"),
                 bg=self.TOPBAR, fg=self.FG_DIM)
        self._subtitle_lbl.pack(side=tk.LEFT, padx=4)
        # Masquer le sous-titre si la fenetre est trop etroite
        def _toggle_subtitle(event=None):
            if self.root.winfo_width() < 620:
                self._subtitle_lbl.pack_forget()
            else:
                self._subtitle_lbl.pack(side=tk.LEFT, padx=4)
        self.root.bind("<Configure>", _toggle_subtitle)


        tk.Button(topbar, text="⚙  Administration",
                  command=self._request_admin,
                  bg=self.ACCENT, fg="white", relief=tk.FLAT,
                  font=("Arial", 9, "bold"), padx=12).pack(side=tk.RIGHT, padx=8)

        # ── Bandeau statut des moteurs (ClamAV + Avast uniquement) ────────────
        sbar = tk.Frame(self.root, bg="#0a2240", pady=2)
        sbar.pack(fill=tk.X)
        self.clamav_status_var = tk.StringVar(value="ClamAV…")
        self.avast_status_var  = tk.StringVar(value="Avast…")
        for var in (self.clamav_status_var, self.avast_status_var):
            tk.Label(sbar, textvariable=var,
                     bg="#0a2240", fg=self.GREEN,
                     font=("Courier", 8), padx=8).pack(side=tk.LEFT)

        # ── Corps principal ────────────────────────────────────────────────────
        body = tk.Frame(self.root, bg=self.BG)
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        left  = tk.Frame(body, bg=self.BG, width=420)
        right = tk.Frame(body, bg=self.BG)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 4))
        left.pack_propagate(False)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0))

        # Journal + boutons ancrés en bas ; USB remplit l'espace restant
        btm = tk.Frame(left, bg=self.BG)
        btm.pack(side=tk.BOTTOM, fill=tk.X)
        self._build_log_panel(btm)
        self._build_scan_controls(btm)
        self._build_usb_panel(left)
        self._build_pdf_viewer_panel(right)

    # ── Panneau USB (simplifié utilisateur) ───────────────────────────────────

    def _build_usb_panel(self, parent: tk.Frame) -> None:
        outer = tk.Frame(parent, bg=self.CARD, bd=1, relief=tk.SOLID)
        outer.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        # ── Entête ────────────────────────────────────────────────────────────
        hdr = tk.Frame(outer, bg=self.CARD)
        hdr.pack(fill=tk.X, padx=8, pady=(8, 4))
        tk.Label(hdr, text="  Supports USB détectés",
                 bg=self.CARD, fg=self.FG,
                 font=("Arial", 11, "bold")).pack(side=tk.LEFT)
        tk.Label(hdr, text="Appuyez pour sélectionner",
                 bg=self.CARD, fg=self.FG_DIM,
                 font=("Arial", 8, "italic")).pack(side=tk.RIGHT, padx=6)

        # ── Treeview + scrollbar dans un sous-cadre ───────────────────────────
        tree_frame = tk.Frame(outer, bg=self.CARD, padx=6, pady=2)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("label", "size", "status")
        self.usb_tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                      height=6, selectmode="none")

        style = ttk.Style()
        style.configure("Treeview",
                        background=self.CARD, fieldbackground=self.CARD,
                        foreground=self.FG, rowheight=34)
        style.configure("Treeview.Heading",
                        background=self.TOPBAR, foreground=self.FG,
                        font=("Arial", 9, "bold"))
        style.map("Treeview", background=[("selected", "#1a4a8a")])

        for cid, heading, width, anchor in [
            ("label",  "Étiquette", 130, tk.W),
            ("size",   "Taille",     65, tk.CENTER),
            ("status", "État",      175, tk.W),
        ]:
            self.usb_tree.heading(cid, text=heading)
            self.usb_tree.column(cid, width=width, minwidth=40, anchor=anchor)

        self.usb_tree.tag_configure("ro",      background="#1a3a2a", foreground="#90ee90")
        self.usb_tree.tag_configure("rw",      background="#3a2a00", foreground="#ffcc66")
        self.usb_tree.tag_configure("unmount", background=self.CARD,  foreground=self.FG_DIM)
        self.usb_tree.tag_configure("scanning",background="#1a1a4a", foreground="#88aaff")

        usb_sb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                                command=self.usb_tree.yview)
        self.usb_tree.configure(yscrollcommand=usb_sb.set)
        self.usb_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        usb_sb.pack(side=tk.RIGHT, fill=tk.Y)

        # ── Info périphérique sélectionné ─────────────────────────────────────
        self.usb_info_var = tk.StringVar(value="")
        tk.Label(outer, textvariable=self.usb_info_var,
                 bg=self.CARD, fg=self.FG_DIM,
                 font=("Arial", 8), anchor=tk.W).pack(
                     fill=tk.X, padx=10, pady=(0, 4))

        # Sélection tactile : tap = toggle (pas de Ctrl requis)
        self.usb_tree.bind("<Button-1>", self._on_usb_tap)
        self.usb_tree.bind("<<TreeviewSelect>>", self._on_usb_select)

    # ── Contrôles de scan ─────────────────────────────────────────────────────

    def _build_scan_controls(self, parent: tk.Frame) -> None:
        outer = tk.Frame(parent, bg=self.CARD, bd=1, relief=tk.SOLID)
        outer.pack(fill=tk.X, pady=(0, 4))
        frm = tk.Frame(outer, bg=self.CARD, padx=10, pady=10)
        frm.pack(fill=tk.X)

        self.scan_btn = tk.Button(
            frm, text="▶   LANCER L'ANALYSE",
            command=self._start_scan,
            bg=self.ACCENT, fg="white", relief=tk.FLAT,
            font=("Arial", 16, "bold"), pady=16, padx=20,
            cursor="hand2"
        )
        self.scan_btn.pack(fill=tk.X, pady=(0, 6))

        self.stop_btn = tk.Button(
            frm, text="⏹  Arrêter tous les scans",
            command=self._stop_all_scans,
            bg="#444", fg="white", relief=tk.FLAT,
            font=("Arial", 11), pady=8, state=tk.DISABLED
        )
        self.stop_btn.pack(fill=tk.X)

    # ── Visionneuse PDF ───────────────────────────────────────────────────────

    def _build_pdf_viewer_panel(self, parent: tk.Frame) -> None:
        """
        Panneau droit : affiche en boucle les PDFs (1 page A4 portrait)
        présents dans ../pdf/, triés alphabétiquement, 35 s par document.
        """
        outer = tk.Frame(parent, bg=self.CARD, bd=1, relief=tk.SOLID)
        outer.pack(fill=tk.BOTH, expand=True)

        # ── Entête avec nom du fichier en cours ───────────────────────────────
        hdr = tk.Frame(outer, bg=self.TOPBAR)
        hdr.pack(fill=tk.X)
        self._pdf_name_var = tk.StringVar(value="Chargement des PDFs…")
        self._pdf_counter_var = tk.StringVar(value="")
        tk.Label(hdr, textvariable=self._pdf_name_var,
                 bg=self.TOPBAR, fg=self.FG,
                 font=("Arial", 9, "bold"),
                 anchor=tk.W, padx=8, pady=4).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(hdr, textvariable=self._pdf_counter_var,
                 bg=self.TOPBAR, fg=self.FG_DIM,
                 font=("Courier", 8), padx=8).pack(side=tk.RIGHT)

        # ── Canvas pour afficher la page rendue ───────────────────────────────
        self._pdf_canvas = tk.Canvas(
            outer, bg="#2a2a2a", highlightthickness=0
        )
        self._pdf_canvas.pack(fill=tk.BOTH, expand=True)

        # ── Barre de progression 35 s ─────────────────────────────────────────
        self._pdf_progress_var = tk.DoubleVar(value=0.0)
        prog_frame = tk.Frame(outer, bg=self.CARD, pady=3)
        prog_frame.pack(fill=tk.X)
        self._pdf_progressbar = ttk.Progressbar(
            prog_frame, variable=self._pdf_progress_var,
            maximum=100, mode="determinate", length=300
        )
        self._pdf_progressbar.pack(fill=tk.X, padx=8, pady=2)

        # ── Navigation manuelle ───────────────────────────────────────────────
        nav = tk.Frame(outer, bg=self.CARD, pady=3)
        nav.pack(fill=tk.X)
        tk.Button(nav, text="◀  Précédent",
                  command=self._pdf_prev,
                  bg=self.TOPBAR, fg=self.FG, relief=tk.FLAT,
                  font=("Arial", 9), pady=4, padx=10).pack(side=tk.LEFT, padx=(8, 4))
        tk.Button(nav, text="Suivant  ▶",
                  command=self._pdf_next,
                  bg=self.TOPBAR, fg=self.FG, relief=tk.FLAT,
                  font=("Arial", 9), pady=4, padx=10).pack(side=tk.RIGHT, padx=(4, 8))

    # ── Journal ───────────────────────────────────────────────────────────────

    def _build_log_panel(self, parent: tk.Frame) -> None:
        # Vars de compatibilité (utilisées par les méthodes de scan)
        self.status_var   = tk.StringVar(value="Prêt — insérez une clé USB")
        self.scanned_var  = tk.StringVar(value="")
        self.infected_var = tk.StringVar(value="")

        # ── Entête journal ─────────────────────────────────────────────────────
        hdr = tk.Frame(parent, bg=self.BG)
        hdr.pack(fill=tk.X, pady=(0, 4))
        tk.Label(hdr, text="  Journal",
                 bg=self.BG, fg=self.FG_DIM,
                 font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        tk.Button(hdr, text="🧹",
                  command=self._clear_log,
                  bg=self.CARD, fg=self.FG_DIM, relief=tk.FLAT,
                  font=("Arial", 8)).pack(side=tk.RIGHT)

        # Cadre englobant pour que le Text+Scrollbar s'étendent ensemble
        log_wrap = tk.Frame(parent, bg="#0b0d14", bd=1, relief=tk.FLAT)
        log_wrap.pack(fill=tk.X, expand=False, pady=(0, 0))
        self.log_text = tk.Text(
            log_wrap, bg="#0b0d14", fg="#c8d0de",
            font=("Courier", 9), wrap=tk.WORD,
            height=10,
            state=tk.NORMAL, insertbackground="white",
            relief=tk.FLAT, padx=10, pady=8
        )
        sb2 = ttk.Scrollbar(log_wrap, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb2.set)

        self.log_text.tag_config("threat",  foreground=self.RED)
        self.log_text.tag_config("ok",      foreground=self.GREEN)
        self.log_text.tag_config("warning", foreground=self.YELLOW)
        self.log_text.tag_config("info",    foreground="#5577aa")
        self.log_text.tag_config("normal",  foreground="#c8d0de")

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb2.pack(side=tk.RIGHT, fill=tk.Y)

    # ══════════════════════════════════════════════════════════════════════════
    # Visionneuse PDF – wrappers UI vers PdfViewer
    # ══════════════════════════════════════════════════════════════════════════

    def _init_pdf_viewer(self) -> None:
        """Instancie PdfViewer et démarre le cycle une fois l'UI prête."""
        def _canvas_size():
            if self._pdf_canvas is None:
                return (595, 842)
            return (self._pdf_canvas.winfo_width(),
                    self._pdf_canvas.winfo_height())

        self._pdf_viewer = PdfViewer(
            base_dir       = os.path.dirname(os.path.abspath(__file__)),
            canvas_size_cb = _canvas_size,
            on_page        = self._on_pdf_page,
            on_progress    = self._on_pdf_progress,
            on_no_files    = self._on_pdf_no_files,
            after_cb       = self.root.after,
            cancel_cb      = self.root.after_cancel,
            log_error_cb   = log_error,
        )
        # Démarrer après que la fenêtre soit complètement dessinée
        self.root.after(200, self._pdf_viewer.start)

    def _on_pdf_page(self, rp: RenderedPage) -> None:
        """Appelé par PdfViewer quand une nouvelle page est prête à afficher."""
        if self._pdf_canvas is None:
            return

        # ── Mettre à jour l'entête ────────────────────────────────────────────
        self._pdf_name_var.set(rp.pdf_name)
        # Format :  document N/total  •  page P/total
        self._pdf_counter_var.set(
            f"doc {rp.pdf_index + 1}/{rp.pdf_count}"
            f"  •  p. {rp.page_index + 1}/{rp.page_count}"
        )

        # ── Afficher l'image ──────────────────────────────────────────────────
        self._pdf_canvas.delete("all")
        cw = self._pdf_canvas.winfo_width()  or 595
        ch = self._pdf_canvas.winfo_height() or 842

        if rp.img_tk is not None:
            self._pdf_tk_image = rp.img_tk   # anti-GC
            self._pdf_canvas.create_image(cw // 2, ch // 2,
                                           anchor=tk.CENTER, image=rp.img_tk)
        else:
            # Fallback : PyMuPDF ou Pillow absent
            self._pdf_canvas.create_text(
                cw // 2, ch // 2,
                text=(f"{rp.pdf_name}\n\nPage {rp.page_index + 1}"
                      f" / {rp.page_count}\n\n"
                      "(PyMuPDF et Pillow requis\npour l'affichage)"),
                fill=self.FG_DIM,
                font=("Arial", 12, "italic"),
                justify=tk.CENTER,
            )

    def _on_pdf_progress(self, pct: float) -> None:
        """Met à jour la barre de progression (0.0 – 100.0)."""
        self._pdf_progress_var.set(pct)

    def _on_pdf_no_files(self) -> None:
        """Affiche un message quand aucun PDF n'est présent dans ../pdf/."""
        if self._pdf_canvas is None:
            return
        self._pdf_canvas.delete("all")
        cw = self._pdf_canvas.winfo_width()  or 595
        ch = self._pdf_canvas.winfo_height() or 842
        self._pdf_canvas.create_text(
            cw // 2, ch // 2,
            text="Aucun PDF trouvé\ndans ../pdf/",
            fill=self.FG_DIM,
            font=("Arial", 14, "italic"),
            justify=tk.CENTER,
        )
        self._pdf_name_var.set("Aucun PDF disponible")
        self._pdf_counter_var.set("")

    def _pdf_next(self) -> None:
        """Navigation manuelle : page / document suivant."""
        if self._pdf_viewer:
            self._pdf_viewer.next_page()

    def _pdf_prev(self) -> None:
        """Navigation manuelle : page / document précédent."""
        if self._pdf_viewer:
            self._pdf_viewer.prev_page()

    def _pdf_viewer_reload(self) -> None:
        """Redémarre le cycle PDF (appelé après ajout/suppression de PDFs)."""
        if self._pdf_viewer:
            self._pdf_viewer.stop()
        self.root.after(300, self._init_pdf_viewer)

    # ══════════════════════════════════════════════════════════════════════════
    # Helpers UI
    # ══════════════════════════════════════════════════════════════════════════

    def _log(self, msg: str, tag: str = "normal") -> None:
        ts   = time.strftime("%H:%M:%S")
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
        threading.Thread(target=self._refresh_status_worker, daemon=True).start()

    def _refresh_status_worker(self) -> None:
        # ClamAV
        if not self.engine.is_clamav_installed():
            clamav_text = "❌ ClamAV"
        else:
            info = self.db.get_clamav_status()
            st   = info["status"]
            lu   = info.get("last_update", "?")
            # Raccourcir la date : garder seulement jj/mm si format ISO
            try:
                from datetime import datetime as _dt
                lu_short = _dt.fromisoformat(lu).strftime("%d/%m/%y")
            except Exception:
                lu_short = lu[:8] if lu and lu != "?" else "?"
            if st == "OK":
                clamav_text = f"✅ ClamAV · {lu_short}"
            elif st == "OUTDATED":
                clamav_text = f"⚠ ClamAV · {lu_short}"
            else:
                clamav_text = "❌ ClamAV"

        # Avast – date de MAJ lue depuis le filesystem VPS
        avast_installed = self.engine.is_avast_installed()
        avast_licensed  = self.engine.is_avast_licensed()
        if not avast_installed:
            avast_text = "⭕ Avast"
        elif not avast_licensed:
            avast_text = "⚠ Avast"
        else:
            avast_date = "?"
            try:
                import os as _os, datetime as _datetime
                _vps_paths = [
                    "/var/lib/avast/Setup/avast.vpsupdate",
                    "/var/lib/avast/Setup/vps.ver",
                ]
                for _p in _vps_paths:
                    if _os.path.exists(_p):
                        _mtime = _os.path.getmtime(_p)
                        avast_date = _datetime.datetime.fromtimestamp(
                            _mtime).strftime("%d/%m/%y")
                        break
            except Exception:
                pass
            avast_text = f"✅ Avast · {avast_date}"

        def _apply():
            self.clamav_status_var.set(clamav_text)
            self.avast_status_var.set(avast_text)
            # Synchronise les vars d'options avec la réalité du système
            if avast_installed and avast_licensed:
                self.use_avast_var.set(True)
            elif not avast_installed:
                self.use_avast_var.set(False)
        self.root.after(0, _apply)

    # ══════════════════════════════════════════════════════════════════════════
    # Gestion USB
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _get_system_devices() -> set:
        """
        Retourne l'ensemble des noms de périphériques hébergeant le système
        (ex. {'sda', 'sda1', 'sda2', 'nvme0n1', 'nvme0n1p1'…}).
        Lit /proc/mounts pour trouver le bloc monté sur '/'.
        """
        system_devs: set = set()
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == "/":
                        dev = parts[0]                          # ex. /dev/sda1
                        if dev.startswith("/dev/"):
                            part_name = dev[5:]                 # ex. sda1
                            system_devs.add(part_name)
                            # Remonter au disque parent (supprime les chiffres finaux
                            # et 'p' pour les NVMe : nvme0n1p1 → nvme0n1)
                            import re
                            parent = re.sub(r'p?\d+$', '', part_name)
                            if parent and parent != part_name:
                                system_devs.add(parent)
        except Exception:
            pass
        return system_devs

    def _refresh_usb(self) -> None:
        selected_devs = self._selected_usb_list()
        for row in self.usb_tree.get_children():
            self.usb_tree.delete(row)

        # Charger toutes les partitions puis exclure le disque système
        self._usb_partitions = self.usb.list_partitions()
        system_devs = self._get_system_devices()
        self._usb_partitions = [
            p for p in self._usb_partitions
            if os.path.basename(p.device) not in system_devs
            and os.path.basename(p.parent) not in system_devs
        ]

        if not self._usb_partitions:
            self.usb_tree.insert("", tk.END,
                                  values=("—", "—",
                                          "Aucune clé USB détectée"))
            return

        scanning_devs = set(self._scan_engines.keys())

        for p in self._usb_partitions:
            mp = self.usb.get_mountpoint(p.device)
            if p.device in scanning_devs:
                status = "🔍 Analyse en cours…"
                tag    = "scanning"
            elif mp:
                ro     = self.usb._is_ro(p.device, mp)
                status = f"✅ Monté RO → {mp}" if ro else f"⚠  Monté RW → {mp}"
                tag    = "ro" if ro else "rw"
            else:
                status = "⏏  Non monté"
                tag    = "unmount"

            # L'iid reste p.device (usage interne) ; la colonne device n'est plus affichée
            self.usb_tree.insert("", tk.END, iid=p.device,
                                  values=(p.label or "—",
                                          p.size,
                                          status),
                                  tags=(tag,))

        # Rétablit la sélection (y compris les supports en cours de scan)
        for dev in set(selected_devs) | scanning_devs:
            try:
                self.usb_tree.selection_add(dev)
            except Exception:
                pass

    # ── Actualisation automatique toutes les secondes ─────────────────────────

    def _start_auto_refresh(self) -> None:
        """Lance la boucle d'actualisation automatique USB (toutes les 1 s)."""
        self._refresh_usb()
        self._auto_refresh_id = self.root.after(1000, self._start_auto_refresh)

    def _on_usb_tap(self, event: tk.Event) -> str:
        """
        Gestion tactile de la sélection : chaque tap toggle l'état de la ligne.
        Plusieurs lignes peuvent être sélectionnées en tapant successivement.
        Retourne "break" pour empêcher le comportement par défaut du Treeview.
        """
        iid = self.usb_tree.identify_row(event.y)
        if not iid:
            return "break"
        # Seules les vraies lignes périphérique ont un iid commençant par /dev/
        if not iid.startswith("/dev/"):
            return "break"
        # Toggle : sélectionné → désélectionner, sinon → ajouter à la sélection
        current = set(self.usb_tree.selection())
        if iid in current:
            current.discard(iid)
        else:
            current.add(iid)
        self.usb_tree.selection_set(list(current))
        self._on_usb_select()
        return "break"

    def _on_usb_select(self, _=None) -> None:
        devs = self._selected_usb_list()
        if not devs:
            self.usb_info_var.set("")
            return
        if len(devs) == 1:
            dev  = devs[0]
            part = next((p for p in self._usb_partitions if p.device == dev), None)
            mp   = self.usb.get_mountpoint(dev)
            uuid = part.uuid if part else ""
            parts_s = []
            if uuid:
                parts_s.append(f"UUID : {uuid[:18]}…" if len(uuid) > 20 else f"UUID : {uuid}")
            parts_s.append(f"{'Monté : ' + mp if mp else 'Non monté'}")
            self.usb_info_var.set("  |  ".join(parts_s))
        else:
            self.usb_info_var.set(f"{len(devs)} périphérique(s) sélectionné(s)")

    def _selected_usb_list(self) -> List[str]:
        """Retourne la liste des chemins /dev/… sélectionnés (iid = p.device)."""
        return [iid for iid in self.usb_tree.selection()
                if iid.startswith("/dev/")]

    def _mount_usb(self) -> None:
        devs = self._selected_usb_list()
        if not devs:
            messagebox.showwarning("Sélection", "Sélectionnez une clé USB.",
                                    parent=self.root)
            return
        dev = devs[0]
        self._log(f"Montage de {dev}…")

        def _worker():
            ok, msg = self.usb.mount(
                dev,
                progress_cb=lambda m: self.root.after(0, self._log, m)
            )
            self.root.after(0, self._log,
                            f"{'✅' if ok else '❌'} {msg}",
                            "ok" if ok else "threat")
            self.root.after(0, self._refresh_usb)

        threading.Thread(target=_worker, daemon=True).start()

    def _umount_usb(self) -> None:
        devs = self._selected_usb_list()
        if not devs:
            messagebox.showwarning("Sélection", "Sélectionnez une clé USB.",
                                    parent=self.root)
            return
        dev = devs[0]
        self._log(f"Démontage de {dev}…")

        def _worker():
            ok, msg = self.usb.umount(
                dev,
                progress_cb=lambda m: self.root.after(0, self._log, m)
            )
            self.root.after(0, self._log,
                            f"{'✅' if ok else '❌'} {msg}",
                            "ok" if ok else "threat")
            self.root.after(0, self._refresh_usb)

        threading.Thread(target=_worker, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    # Scan – multi-périphérique + threading
    # ══════════════════════════════════════════════════════════════════════════

    def _start_scan(self) -> None:
        if (not self.engine.is_clamav_installed()
                and not self.use_avast_var.get()):
            messagebox.showerror(
                "Aucun moteur actif",
                "ClamAV n'est pas installé et Avast n'est pas activé.\n"
                "Configurez un moteur dans le panneau d'administration.",
                parent=self.root
            )
            return

        devs = self._selected_usb_list()
        if not devs:
            messagebox.showwarning(
                "Aucun périphérique",
                "Appuyez sur un support USB dans la liste pour le sélectionner.",
                parent=self.root
            )
            return

        # Exclure les supports déjà en cours de scan
        devs_to_scan = [d for d in devs if d not in self._scan_engines]
        already = [d for d in devs if d in self._scan_engines]
        if already:
            msg = "  ".join(already)
            if not devs_to_scan:
                messagebox.showinfo(
                    "Déjà en cours",
                    f"Ces supports sont déjà en cours de scan :\n{msg}",
                    parent=self.root
                )
                return
            self._log(f"ℹ Déjà en scan : {msg} — ignoré", "info")

        if (self.use_avast_var.get()
                and self.engine.is_avast_installed()
                and not self.engine.is_avast_licensed()):
            if not messagebox.askyesno(
                "Avast sans licence",
                "Avast est sélectionné mais n'est pas licencié.\n"
                "Le moteur Avast sera ignoré.\nContinuer ?",
                parent=self.root
            ):
                return

        if self.remove_var.get():
            if not messagebox.askyesno(
                "⚠ Suppression activée",
                "Les fichiers infectés seront DÉFINITIVEMENT supprimés.\n"
                "Confirmez-vous ?",
                parent=self.root
            ):
                return

        # Prépare les cibles — toujours en lecture seule pendant le scan
        # (la suppression éventuelle est effectuée après, en remontant en RW)
        targets_map: Dict[str, str] = {}
        for dev in devs_to_scan:
            mp = self.usb.get_mountpoint(dev)
            if not mp:
                ok, msg = self.usb.mount(dev)
                if not ok:
                    messagebox.showerror("Montage", msg, parent=self.root)
                    continue
                self._refresh_usb()
                mp = self.usb.get_mountpoint(dev)

            if not mp:
                messagebox.showerror(
                    "Erreur", f"Impossible de monter {dev}.", parent=self.root)
                continue
            targets_map[dev] = mp

        if not targets_map:
            return

        self._targets_map.update(targets_map)

        with self._scan_lock:
            self._active_scans    += len(targets_map)
            self._total_scanned    = 0
            self._total_infected   = 0
            self._per_dev_scanned  = {}
            self._per_dev_infected = {}
            self._session_threats  = []   # réinitialiser pour cette session
            self._session_seen_hashes = set()

        self.stop_btn.configure(state=tk.NORMAL, bg=self.ACCENT)
        self._anim_state = "scanning"
        self.status_var.set("Analyse en cours…")
        self.scanned_var.set("Analysés : 0")
        self.infected_var.set("")

        engines_str = " + ".join(filter(None, [
            "ClamAV" if self.use_clamav_var.get() else None,
            "Avast"  if self.use_avast_var.get()  else None,
            "YARA"   if self.use_yara_var.get()   else None,
        ]))

        for dev, mp in targets_map.items():
            part   = next((p for p in self._usb_partitions if p.device == dev), None)
            uuid_s = f"  UUID={part.uuid}" if part and part.uuid else ""
            self._log(
                f"Démarrage : {dev}{uuid_s} → {mp}  [{engines_str}]", "info")

            # Marquer visuellement la ligne en cours de scan
            try:
                self.usb_tree.item(dev, tags=("scanning",))
            except Exception:
                pass

            eng = ScanEngine()
            self._scan_engines[dev] = eng

            threading.Thread(
                target=self._scan_thread,
                args=(dev, [mp], eng),
                daemon=True
            ).start()

    def _scan_thread(self, dev: str, targets: List[str],
                     eng: ScanEngine) -> None:
        # Initialiser les compteurs temps réel pour ce périphérique
        self._per_dev_scanned[dev]  = 0
        self._per_dev_infected[dev] = 0

        def _progress(msg: str, tag: str = "normal") -> None:
            self.root.after(0, self._log, msg, tag)

        def _file_count_cb(scanned: int, infected: int) -> None:
            """
            Appelé par ScanEngine après chaque fichier traité (ou toutes les N lignes).
            scanned/infected = totaux cumulés pour CE périphérique.
            Mis à jour sur le thread principal pour cohérence avec l'animation.
            """
            def _update(s=scanned, i=infected, d=dev):
                self._per_dev_scanned[d]  = s
                self._per_dev_infected[d] = i
                self._total_scanned  = sum(self._per_dev_scanned.values())
                self._total_infected = sum(self._per_dev_infected.values())
            self.root.after(0, _update)

        try:
            result = eng.scan(
                targets          = targets,
                use_clamav       = self.use_clamav_var.get(),
                use_avast        = self.use_avast_var.get(),
                use_yara         = self.use_yara_var.get(),
                remove_infected  = self.remove_var.get(),
                progress_cb      = _progress,
                file_count_cb    = _file_count_cb,
            )
        except Exception as e:
            result = None
            msg    = f"Erreur scan {dev} : {e}"
            log_error(msg)
            self.root.after(0, self._log, msg, "threat")

        self.root.after(0, self._scan_done_one, dev, result)

    def _scan_done_one(self, dev: str, result: Optional[ScanResult]) -> None:
        """Appelé quand un scan individuel se termine."""
        with self._scan_lock:
            self._active_scans = max(0, self._active_scans - 1)

        # Nettoyer les entrées temps réel et figer avec les valeurs exactes du moteur
        self._per_dev_scanned.pop(dev, None)
        self._per_dev_infected.pop(dev, None)
        if result:
            self._total_scanned  = (
                sum(self._per_dev_scanned.values()) + result.scanned
            )
            self._total_infected = (
                sum(self._per_dev_infected.values()) + result.infected
            )

        # ── Compteurs globaux ─────────────────────────────────────────────────
        self._total_keys_scanned += 1

        if result:
            tag  = "threat" if result.infected > 0 else "ok"
            icon = "⚠" if result.infected > 0 else "✅"
            self._log(
                f"{icon} {dev} : {result.scanned} fichier(s), "
                f"{result.infected} menace(s)  ({result.duration:.1f}s)",
                tag
            )
            # ── Enregistrement des détails de menaces avec hash SHA-256 ───────
            threats = getattr(result, "threats", []) or []
            if threats:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                for item in threats:
                    fpath  = item.path
                    tname  = item.threat
                    sha    = item.hash if item.hash else ""

                    # ── Déduplication par hash (même fichier détecté par plusieurs
                    #    moteurs, ou présent sur plusieurs clés avec contenu identique)
                    dedup_key = sha if sha else fpath   # fallback sur le chemin si pas de hash
                    if dedup_key in self._session_seen_hashes:
                        continue
                    self._session_seen_hashes.add(dedup_key)

                    self._threat_details.append({
                        "ts":     ts,
                        "file":   fpath,
                        "threat": tname,
                        "hash":   sha if sha else "N/A",
                        "dev":    dev,
                        "mp":     self._targets_map.get(dev, ""),
                    })
                    self._session_threats.append(item)
                    self._cumul_threats += 1

                    # ── Log détaillé dans la session (chemin + hash) ──────────
                    log_info(
                        f"MENACE DÉTECTÉE | chemin={fpath}"
                        f" | hash={sha if sha else 'N/A'}"
                        f" | type={tname}"
                    )
                    self._log(
                        f"🦠 {tname}  ↳ {fpath}"
                        f"  [hash: {(sha[:16] + '…') if sha and sha != 'N/A' else 'N/A'}]",
                        "threat"
                    )

            # Recalculer _total_infected depuis la liste dédupliquée
            # (écrase la somme brute des moteurs qui peut compter en double)
            self._total_infected = len(self._session_threats)
        else:
            self._log(f"❌ {dev} : erreur durant le scan.", "threat")

        # Restaurer le tag visuel de la ligne USB
        try:
            mp = self.usb.get_mountpoint(dev)
            if mp:
                ro = self.usb._is_ro(dev, mp)
                self.usb_tree.item(dev, tags=("ro" if ro else "rw",))
            else:
                self.usb_tree.item(dev, tags=("unmount",))
        except Exception:
            pass

        # Retirer l'engine de la map
        self._scan_engines.pop(dev, None)

        self.scanned_var.set(f"Analysés : {self._total_scanned}")
        if self._total_infected > 0:
            self.infected_var.set(f"Menaces : {self._total_infected}")

        # Sauvegarde persistante des compteurs et du tableau des menaces
        self._save_persistent_stats()

        # Export PDF automatique sur le support analysé
        self._auto_export_to_device(dev, result)

        # Si plus aucun scan actif, bilan global
        if self._active_scans == 0:
            self._all_scans_done()

    def _all_scans_done(self) -> None:
        self.stop_btn.configure(state=tk.DISABLED, bg="#444")

        all_threats = list(self._session_threats)

        if all_threats:
            self._anim_state = "threat"
            self.status_var.set(
                f"⚠  {self._total_infected} menace(s) détectée(s) !")
            messagebox.showwarning(
                "Menaces détectées",
                f"{self._total_infected} menace(s) trouvée(s) "
                f"sur {self._total_scanned} fichier(s) analysé(s).\n"
                "Consultez le journal pour les détails.",
                parent=self.root
            )
            # Gestion post-scan : suppression automatique ou proposition à l'utilisateur
            if self.remove_var.get():
                # L'admin a coché "Supprimer les virus détectés" → suppression immédiate
                self._log(
                    f"🗑 Suppression automatique de {len(all_threats)} fichier(s) "
                    "infecté(s) (option admin activée)…", "warning")
                self._delete_threat_files(all_threats)
            else:
                # Proposer la suppression à l'utilisateur
                self._offer_delete_threats(all_threats)
        else:
            self._anim_state = "ok"
            self.status_var.set("✅  Aucune menace détectée")
            messagebox.showinfo(
                "Analyse terminée",
                f"{self._total_scanned} fichier(s) analysé(s) — aucune menace.",
                parent=self.root
            )

        self.root.after(5000, self._reset_anim_idle)

    # ── Proposition de suppression ─────────────────────────────────────────────

    def _offer_delete_threats(self, threats: list) -> None:
        """Demande à l'utilisateur s'il souhaite supprimer les fichiers infectés."""
        names = "\n".join(
            f"  • {os.path.basename(t.path)}  [{t.threat}]"
            for t in threats[:12]
        )
        if len(threats) > 12:
            names += f"\n  … et {len(threats) - 12} autre(s)"

        answer = messagebox.askyesno(
            "⚠ Supprimer les fichiers infectés ?",
            f"{len(threats)} fichier(s) infecté(s) ont été détectés :\n\n"
            f"{names}\n\n"
            "Voulez-vous supprimer DÉFINITIVEMENT ces fichiers ?",
            icon="warning",
            parent=self.root
        )
        if answer:
            self._delete_threat_files(threats)
        else:
            self._show_risks_window(threats)

    # ── Suppression des fichiers infectés ─────────────────────────────────────

    def _delete_threat_files(self, threats: list) -> None:
        """
        Supprime les fichiers infectés en remontant les supports en RW.

        Problème clé : après l'export PDF, le support est démonté.
        Quand on le remonte, le point de montage peut différer de celui utilisé
        pendant le scan (ex. /media/user/SANDISK → /mnt/avscan_usb/sdb1).
        On traduit donc chaque chemin : ancien_mp/rel → nouveau_mp/rel.
        """
        import threading as _th

        # Index : chemin_fichier → (device, mountpoint_au_scan)
        file_info = {
            d["file"]: (d.get("dev", ""), d.get("mp", ""))
            for d in self._threat_details
        }

        def _worker():
            deleted, failed = [], []

            # Regrouper les menaces par (device, mountpoint_scan)
            by_dev: dict = {}   # dev → {"scan_mp": str, "threats": [...]}
            for t in threats:
                dev, scan_mp = file_info.get(t.path, ("", ""))
                if dev not in by_dev:
                    by_dev[dev] = {"scan_mp": scan_mp, "threats": []}
                by_dev[dev]["threats"].append(t)

            for dev, data in by_dev.items():
                scan_mp    = data["scan_mp"]
                dev_threats = data["threats"]
                action     = None
                new_mp     = None

                if dev:
                    cur_mp = self.usb.get_mountpoint(dev)
                    if not cur_mp:
                        # Périphérique démonté → remonter en RW
                        ok_mnt, msg_mnt, new_mp, action = self.usb.mount_rw(dev)
                        if not ok_mnt:
                            self.root.after(0, self._log,
                                            f"❌ Impossible de monter {dev} en RW : {msg_mnt}",
                                            "threat")
                            failed.extend(t.path for t in dev_threats)
                            continue
                    elif self.usb._is_ro(dev, cur_mp):
                        # Monté RO → remonter en RW
                        ok_mnt, msg_mnt, new_mp, action = self.usb.mount_rw(dev)
                        if not ok_mnt:
                            self.root.after(0, self._log,
                                            f"❌ Impossible de remonter {dev} en RW : {msg_mnt}",
                                            "threat")
                            failed.extend(t.path for t in dev_threats)
                            continue
                    else:
                        # Déjà monté RW
                        new_mp = cur_mp

                for t in dev_threats:
                    # ── Translation du chemin si le mountpoint a changé ───────
                    # Cas typique : scan sur /media/user/SANDISK,
                    # remontage sur /mnt/avscan_usb/sdb1
                    actual_path = t.path
                    if new_mp and scan_mp and scan_mp != new_mp:
                        try:
                            rel = os.path.relpath(t.path, scan_mp)
                            actual_path = os.path.join(new_mp, rel)
                        except ValueError:
                            pass  # relpath impossible (Windows-style paths, etc.)

                    try:
                        if os.path.exists(actual_path):
                            os.remove(actual_path)
                            deleted.append(actual_path)
                            self.root.after(0, self._log,
                                            f"🗑 Supprimé : {os.path.basename(actual_path)}",
                                            "warning")
                        else:
                            # Dernière tentative avec le chemin brut original
                            if actual_path != t.path and os.path.exists(t.path):
                                os.remove(t.path)
                                deleted.append(t.path)
                                self.root.after(0, self._log,
                                                f"🗑 Supprimé : {os.path.basename(t.path)}",
                                                "warning")
                            else:
                                failed.append(actual_path)
                                self.root.after(0, self._log,
                                                f"❌ Introuvable : {os.path.basename(t.path)}"
                                                f"  (cherché dans {new_mp or scan_mp})",
                                                "threat")
                    except Exception as exc:
                        failed.append(actual_path)
                        self.root.after(0, self._log,
                                        f"❌ Impossible de supprimer "
                                        f"{os.path.basename(t.path)} : {exc}",
                                        "threat")

                # Restaurer le montage RO après suppression
                if dev and action:
                    self.usb.restore_after_export(dev, action)

            # ── Bilan ─────────────────────────────────────────────────────────
            summary = f"✅ {len(deleted)} fichier(s) infecté(s) supprimé(s)."
            if failed:
                summary += (f"\n❌ {len(failed)} fichier(s) non supprimé(s) "
                            "(voir journal).")
            self.root.after(0, messagebox.showinfo, "Suppression terminée", summary)
            self.root.after(0, self._refresh_usb)

        _th.Thread(target=_worker, daemon=True).start()

    # ── Page des risques ───────────────────────────────────────────────────────

    def _show_risks_window(self, threats: list) -> None:
        """Affiche une fenêtre d'avertissement sur les risques liés aux fichiers conservés."""
        win = tk.Toplevel(self.root)
        win.title("⚠ Risques — Fichiers infectés conservés")
        win.configure(bg="#1a0808")
        win.grab_set()
        win.transient(self.root)
        win.resizable(True, True)
        win.attributes("-fullscreen", True)

        # ── Bandeau rouge ────────────────────────────────────────────────────
        banner = tk.Frame(win, bg="#8b0000", pady=14)
        banner.pack(fill=tk.X)
        tk.Label(
            banner,
            text="⚠  ATTENTION — FICHIERS MALVEILLANTS CONSERVÉS",
            bg="#8b0000", fg="white",
            font=("Arial", 14, "bold")
        ).pack()
        tk.Label(
            banner,
            text=f"{len(threats)} fichier(s) infecté(s) n'ont PAS été supprimés.",
            bg="#8b0000", fg="#ffcccc",
            font=("Arial", 10)
        ).pack(pady=(2, 0))

        # ── Contenu scrollable ────────────────────────────────────────────────
        body_frame = tk.Frame(win, bg="#1a0808")
        body_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=10)

        # Liste des fichiers infectés
        list_lbl = tk.Label(
            body_frame,
            text="Fichiers infectés présents sur vos supports :",
            bg="#1a0808", fg="#ffaaaa",
            font=("Arial", 10, "bold"), anchor=tk.W
        )
        list_lbl.pack(anchor=tk.W, pady=(0, 4))

        list_wrap = tk.Frame(body_frame, bg="#300808")
        list_wrap.pack(fill=tk.X, pady=(0, 10))

        cols = ("fichier", "menace", "hash")
        tree = ttk.Treeview(list_wrap, columns=cols, show="headings", height=6)
        tree.heading("fichier", text="Fichier")
        tree.heading("menace",  text="Menace détectée")
        tree.heading("hash",    text="SHA-256")
        tree.column("fichier", width=200, anchor=tk.W)
        tree.column("menace",  width=160, anchor=tk.W)
        tree.column("hash",    width=340, anchor=tk.W)
        t_sb = ttk.Scrollbar(list_wrap, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=t_sb.set)
        tree.pack(side=tk.LEFT, fill=tk.X, expand=True)
        t_sb.pack(side=tk.RIGHT, fill=tk.Y)

        for t in threats:
            tree.insert("", tk.END, values=(
                os.path.basename(t.path),
                t.threat,
                t.hash if t.hash else "N/A",
            ))

        # Texte des risques
        risks_text = (
            "RISQUES LIÉS À LA CONSERVATION DE FICHIERS INFECTÉS\n\n"
            "1.  PROPAGATION  —  Les fichiers malveillants peuvent se copier\n"
            "    automatiquement vers d'autres supports ou machines dès leur connexion.\n\n"
            "2.  VOL DE DONNÉES  —  Certains malwares (chevaux de Troie, spywares)\n"
            "    collectent silencieusement vos fichiers personnels, mots de passe\n"
            "    et coordonnées bancaires.\n\n"
            "3.  CHIFFREMENT RANSOMWARE  —  Si le fichier est un ransomware, il peut\n"
            "    chiffrer l'intégralité de vos données et réclamer une rançon.\n\n"
            "4.  PERSISTANCE  —  Certains rootkits s'installent dans le secteur de\n"
            "    démarrage et survivent à un formatage simple du support.\n\n"
            "5.  COMPROMISSION DU RÉSEAU  —  En insérant ce support sur un autre\n"
            "    ordinateur connecté au réseau, vous exposez l'ensemble du réseau.\n\n"
            "RECOMMANDATIONS\n\n"
            "  ✦  Supprimez immédiatement les fichiers listés ci-dessus.\n"
            "  ✦  Formatez le support USB si la suppression n'est pas possible.\n"
            "  ✦  N'insérez pas ce support sur d'autres ordinateurs.\n"
            "  ✦  Contactez votre responsable informatique si vous avez un doute."
        )

        txt_wrap = tk.Frame(body_frame, bg="#1a0808")
        txt_wrap.pack(fill=tk.BOTH, expand=True)
        risks_box = tk.Text(
            txt_wrap,
            bg="#200a0a", fg="#ffdddd",
            font=("Courier", 9), wrap=tk.WORD,
            state=tk.DISABLED, relief=tk.FLAT,
            padx=10, pady=8
        )
        r_sb = ttk.Scrollbar(txt_wrap, orient=tk.VERTICAL, command=risks_box.yview)
        risks_box.configure(yscrollcommand=r_sb.set)
        risks_box.configure(state=tk.NORMAL)
        risks_box.insert(tk.END, risks_text)
        risks_box.configure(state=tk.DISABLED)
        risks_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        r_sb.pack(side=tk.RIGHT, fill=tk.Y)

        # ── Boutons ───────────────────────────────────────────────────────────
        btn_bar = tk.Frame(win, bg="#1a0808", pady=10)
        btn_bar.pack(fill=tk.X)

        def _delete_now():
            win.destroy()
            self._delete_threat_files(threats)

        tk.Button(
            btn_bar,
            text="🗑  Supprimer maintenant",
            command=_delete_now,
            bg="#8b0000", fg="white", relief=tk.FLAT,
            font=("Arial", 11, "bold"), padx=18, pady=8,
            cursor="hand2"
        ).pack(side=tk.LEFT, padx=(16, 8))

        tk.Button(
            btn_bar,
            text="✕  Fermer (conserver les fichiers)",
            command=win.destroy,
            bg="#444", fg="white", relief=tk.FLAT,
            font=("Arial", 10), padx=14, pady=8
        ).pack(side=tk.LEFT)

    def _reset_anim_idle(self) -> None:
        if self._active_scans == 0:
            self._anim_state = "idle"
            self.status_var.set("Prêt — insérez une clé USB")

    def _stop_all_scans(self) -> None:
        if self._active_scans > 0:
            for eng in self._scan_engines.values():
                eng.request_stop()
            self.status_var.set("Arrêt en cours…")
            self.stop_btn.configure(state=tk.DISABLED)
            self._log("Arrêt demandé par l'utilisateur.", "warning")

    def _auto_export_to_device(self, dev: str,
                                result: Optional[ScanResult]) -> None:
        """
        Génère un PDF de rapport sur le support analysé.
        Séquence : remontage RW → écriture PDF → remontage RO → démontage.
        """
        if result is None:
            return

        part  = next((p for p in self._usb_partitions if p.device == dev), None)
        label = (part.label if part and part.label else "") or dev.replace("/dev/", "")
        uuid  = (part.uuid  if part and part.uuid  else "") or ""

        # Snapshot des options UI (thread-safe car BooleanVar)
        engines_used = {
            "clamav": self.use_clamav_var.get(),
            "avast":  self.use_avast_var.get(),
            "yara":   self.use_yara_var.get(),
        }
        avast_installed = self.engine.is_avast_installed()
        avast_licensed  = self.engine.is_avast_licensed()

        # Référence aux managers (thread-safe en lecture)
        db     = self.db
        engine = self.engine

        def _worker() -> None:
            # Collecte des infos bases dans le thread worker (évite de bloquer l'UI)
            clamav_info = db.get_clamav_status()
            yara_info   = db.get_yara_status()
            avast_info  = {
                "installed": avast_installed,
                "licensed":  avast_licensed,
            }

            # ── Obtenir un point de montage RW ────────────────────────────────
            current_mp = self.usb.get_mountpoint(dev)

            if current_mp and not self.usb._is_ro(dev, current_mp):
                # Déjà monté en RW (scan avec suppression activée)
                # → utiliser directement, sans démonter/remonter
                mp_rw  = current_mp
                action = "existing_rw"
            else:
                # Monté RO ou non monté → démonter proprement, puis remonter RW
                if current_mp:
                    ok_u, msg_u = self.usb.umount(dev)
                    if not ok_u:
                        self.root.after(
                            0, self._log,
                            f"⚠ Démontage RO impossible ({msg_u}) — "
                            f"tentative de remontage RW forcé…", "warning"
                        )
                ok_mnt, msg_mnt, mp_rw, action = self.usb.mount_for_export(
                    dev,
                    progress_cb=lambda m: self.root.after(0, self._log, m, "info")
                )
                if not ok_mnt:
                    self.root.after(0, self._log,
                                    f"⚠ PDF non écrit sur {dev} : {msg_mnt}",
                                    "warning")
                    return
            try:
                from log_handler import write_device_scan_report_pdf
                report_path = write_device_scan_report_pdf(
                    mountpoint   = mp_rw,
                    device       = dev,
                    label        = label,
                    uuid         = uuid,
                    result       = result,
                    clamav_info  = clamav_info,
                    yara_info    = yara_info,
                    avast_info   = avast_info,
                    engines_used = engines_used,
                )
                self.root.after(0, self._log,
                                f"📄 Rapport PDF écrit : {report_path}",
                                "ok")
                # Inscrire dans les logs de session le chemin complet du PDF
                log_info(f"PDF DE RAPPORT EXPORTÉ SUR CLÉ | chemin={report_path} | device={dev}")
            except Exception as exc:
                self.root.after(0, self._log,
                                f"⚠ Erreur PDF sur {dev} : {exc}",
                                "warning")
            finally:
                # Remontage RO puis démontage propre
                self.usb.restore_after_export(dev, action)
                self.usb.umount(dev)
                self.root.after(0, self._refresh_usb)

        threading.Thread(target=_worker, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    # Administration
    # ══════════════════════════════════════════════════════════════════════════

    def _request_admin(self) -> None:
        panel = AdminPanel(
            parent                    = self.root,
            auth                      = self.auth,
            # Options moteurs (vars partagées)
            use_clamav_var            = self.use_clamav_var,
            use_avast_var             = self.use_avast_var,
            use_yara_var              = self.use_yara_var,
            scan_mode_var             = self.scan_mode_var,
            remove_var                = self.remove_var,
            # ClamAV
            on_update_clamav_online      = self._admin_clamav_online,
            on_import_clamav_usb         = self._admin_clamav_usb,
            on_download_third_party_sigs = self._admin_clamav_thirdparty,
            # Avast
            on_install_avast            = self._admin_install_avast,
            on_update_avast_vps_online  = self._admin_avast_vps_online,
            on_import_avast_vps_usb     = self._admin_avast_vps_usb,
            on_import_avast_license_usb  = self._admin_avast_license_usb,
            on_import_avast_license_file = self._admin_avast_license_file,
            on_activate_avast_code       = self._admin_avast_activate_code,
            on_refresh_avast_status     = self._refresh_status,
            # YARA
            on_update_yara_online     = self._admin_yara_online,
            on_import_yara_usb        = self._admin_yara_usb,
            # Journaux
            on_export_logs_usb        = self._admin_export_logs_usb,
            on_purge_logs             = self._admin_purge_logs,
            on_purge_threats          = self._purge_threats,
            on_purge_counters         = self._purge_counters,
            # Système
            on_poweroff               = self._admin_poweroff,
            on_quit                   = self._quit,
            # Support exhaustif
            get_usb_partitions        = lambda: self._usb_partitions,
            refresh_usb               = self._refresh_usb,
            # PDFs
            pdf_dir                   = self._pdf_dir,
            on_pdf_reload_viewer      = self._pdf_viewer_reload,
            # Statistiques pour onglet Journaux
            get_scan_stats            = lambda: {
                "keys":    self._total_keys_scanned,
                "threats": self._cumul_threats,
                "details": list(self._threat_details),
            },
        )
        panel.show()

    # ── Actions admin ─────────────────────────────────────────────────────────

    def _admin_install_avast(self) -> None:
        """Installe Avast Business for Linux via apt (mode installer)."""
        self._run_background(
            task  = self._do_install_avast,
            label = "Installation Avast",
            on_done = lambda ok, msg: self._refresh_status()
        )

    def _do_install_avast(self, progress_cb) -> tuple:
        """Séquence d'installation complète d'Avast (mode installé)."""
        import shutil, subprocess as sp
        steps = [
            ("Ajout de la clé GPG Avast…",
             "curl -fsSL https://repo.avcdn.net/linux/avast.gpg "
             "| tee /etc/apt/trusted.gpg.d/avast.gpg"),
            ("Ajout du dépôt APT Avast…",
             "echo 'deb https://repo.avcdn.net/linux stable avast' "
             "| tee /etc/apt/sources.list.d/avast.list"),
            ("Mise à jour des listes APT…", "apt-get update -q"),
            ("Installation d'avast…",
             "DEBIAN_FRONTEND=noninteractive apt-get install -y avast"),
            ("Activation du service Avast…",
             "systemctl enable avast && systemctl start avast"),
        ]
        for label, cmd in steps:
            progress_cb(label)
            try:
                r = subprocess.run(cmd, shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   text=True, timeout=300)
                for line in r.stdout.splitlines():
                    if line.strip():
                        progress_cb(f"  {line.strip()}")
                if r.returncode != 0:
                    return False, f"Échec à l'étape : {label}\n{r.stdout[-300:]}"
            except Exception as e:
                return False, f"Erreur à l'étape '{label}' : {e}"
        return True, "Avast Business for Linux installé avec succès."

    def _admin_clamav_online(self) -> None:
        if not self.engine.is_freshclam_available():
            messagebox.showerror(
                "freshclam manquant",
                "Installez clamav-freshclam : apt install clamav-freshclam",
                parent=self.root)
            return
        self._log("Mise à jour ClamAV en ligne…", "info")
        self._run_background(
            task    = lambda cb: self.db.update_clamav_online(progress_cb=cb),
            label   = "ClamAV online update",
            on_done = lambda ok, msg: self._refresh_status()
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
                parent=self.root)
            return
        names = "\n".join(f"• {os.path.basename(f)}" for f in files)
        if not messagebox.askyesno(
            "Confirmer l'import",
            f"Fichiers trouvés :\n{names}\n\nImporter vers /var/lib/clamav/ ?",
            parent=self.root
        ):
            return
        self._run_background(
            task    = lambda cb: self.db.import_clamav_from_usb(files,
                                                                 progress_cb=cb),
            label   = "ClamAV import USB",
            on_done = lambda ok, msg: self._refresh_status()
        )

    def _admin_clamav_thirdparty(self) -> None:
        from db_manager import THIRD_PARTY_SIGNATURES
        names = "\n".join(f"  • {s['name']}" for s in THIRD_PARTY_SIGNATURES[:6])
        if not messagebox.askyesno(
            "Télécharger signatures tierces",
            f"Sources (Internet requis) :\n{names}\n…\n\nContinuer ?",
            parent=self.root
        ):
            return
        self._run_background(
            task    = lambda cb: self.db.download_third_party_sigs(progress_cb=cb),
            label   = "Signatures tierces ClamAV",
            on_done = lambda ok, msg: self._refresh_status()
        )

    def _admin_avast_activate_code(self, code: str) -> None:
        self._log(f"Activation du code Avast…", "info")
        self._run_background(
            task    = lambda cb: self.db.activate_avast_with_code(code,
                                                                   progress_cb=cb),
            label   = "Activation Avast",
            on_done = lambda ok, msg: self._refresh_status()
        )

    def _admin_avast_license_usb(self) -> None:
        self._log("Recherche de license.avastlic sur les clés USB…", "info")
        files = self.db.find_avast_license_on_usb()
        if not files:
            messagebox.showwarning(
                "Introuvable",
                "Aucun fichier license.avastlic trouvé sur les clés USB.",
                parent=self.root)
            return
        chosen = max(files, key=os.path.getmtime) if len(files) > 1 else files[0]
        if not messagebox.askyesno(
            "Confirmer",
            f"Importer la licence :\n{chosen} ?",
            parent=self.root
        ):
            return
        self._run_background(
            task    = lambda cb: self.db.import_avast_license_from_file(
                chosen, progress_cb=cb),
            label   = "Avast licence import",
            on_done = lambda ok, msg: self._refresh_status()
        )

    def _admin_avast_license_file(self, path: str) -> None:
        if not os.path.isfile(path):
            messagebox.showerror("Fichier introuvable",
                                  f"Le fichier n'existe pas :\n{path}",
                                  parent=self.root)
            return
        self._log(f"Import de la licence Avast depuis : {path}", "info")
        self._run_background(
            task    = lambda cb: self.db.import_avast_license_from_file(
                path, progress_cb=cb),
            label   = "Import licence Avast",
            on_done = lambda ok, msg: self._refresh_status()
        )

    def _admin_avast_vps_online(self) -> None:
        if not self.engine.is_avast_installed():
            messagebox.showerror(
                "Avast non installé",
                "Installez Avast Business via l'onglet Avast du panneau.",
                parent=self.root)
            return
        self._log("Mise à jour VPS Avast en ligne…", "info")
        self._run_background(
            task    = lambda cb: self.db.update_avast_vps_online(progress_cb=cb),
            label   = "Avast VPS online",
            on_done = lambda ok, msg: self._refresh_status()
        )

    def _admin_avast_vps_usb(self) -> None:
        self._log("Recherche de fichiers VPS Avast sur les clés USB…", "info")
        files = self.db.find_avast_vps_on_usb()
        if not files:
            messagebox.showwarning(
                "Introuvable",
                "Aucun fichier VPS Avast (.vps, .vpz) trouvé sur les clés USB.",
                parent=self.root)
            return
        chosen = max(files, key=os.path.getmtime)
        if not messagebox.askyesno(
            "Confirmer", f"Importer {os.path.basename(chosen)} ?",
            parent=self.root
        ):
            return
        self._run_background(
            task    = lambda cb: self.db.import_avast_vps_from_usb(
                chosen, progress_cb=cb),
            label   = "Avast VPS USB",
            on_done = lambda ok, msg: self._refresh_status()
        )

    def _admin_yara_online(self) -> None:
        self._log("Téléchargement signature-base (GitHub)…", "info")
        self._run_background(
            task    = lambda cb: self.db.update_yara_online(progress_cb=cb),
            label   = "YARA online",
            on_done = lambda ok, msg: self._refresh_status()
        )

    def _admin_yara_usb(self) -> None:
        self._log("Recherche de règles YARA sur les clés USB…", "info")
        files = self.db.find_yara_on_usb()
        if not files:
            messagebox.showwarning(
                "Introuvable",
                "Aucun fichier .yar / .yara / .zip trouvé sur les clés USB.",
                parent=self.root)
            return
        if not messagebox.askyesno(
            "Confirmer",
            f"{len(files)} fichier(s) trouvé(s). Importer ?",
            parent=self.root
        ):
            return
        self._run_background(
            task    = lambda cb: self.db.import_yara_from_usb(files,
                                                               progress_cb=cb),
            label   = "YARA USB",
            on_done = lambda ok, msg: self._refresh_status()
        )

    def _admin_export_logs_usb(self) -> None:
        from tkinter import filedialog
        partitions = self.usb.list_partitions()
        if not partitions:
            messagebox.showwarning(
                "Aucune clé USB",
                "Insérez une clé USB de destination et réessayez.",
                parent=self.root)
            return

        target = partitions[0] if len(partitions) == 1 else self._pick_usb(partitions)
        if target is None:
            return

        self._log(f"Montage RW de {target.device} pour export…", "info")
        ok, msg, mp, action = self.usb.mount_for_export(
            target.device,
            progress_cb=lambda m: self._log(m, "info")
        )
        if not ok:
            self._log(f"❌ {msg}", "threat")
            messagebox.showerror("Erreur de montage", msg, parent=self.root)
            return

        self._log(f"✅ {msg}", "ok")
        self._refresh_usb()

        try:
            dest_dir = filedialog.askdirectory(
                parent=self.root,
                title="Dossier de destination sur USB",
                initialdir=mp
            )
            if not dest_dir:
                return
            os.makedirs(dest_dir, exist_ok=True)
            ok_exp, msg_exp = export_logs_to_path(dest_dir)
            tag = "ok" if ok_exp else "threat"
            self._log(f"{'✅' if ok_exp else '❌'} {msg_exp}", tag)
            if ok_exp:
                messagebox.showinfo("Export terminé", msg_exp, parent=self.root)
            else:
                messagebox.showerror("Erreur export", msg_exp, parent=self.root)
        finally:
            self.usb.restore_after_export(target.device, action)
            self._refresh_usb()

    def _admin_purge_logs(self) -> None:
        ok, msg = purge_logs()
        self._log(f"{'✅' if ok else '❌'} {msg}", "ok" if ok else "threat")
        if not ok:
            messagebox.showerror("Erreur purge", msg, parent=self.root)

    def _admin_poweroff(self) -> None:
        self._log("Arrêt demandé — démontage des USB…", "warning")
        self.usb.umount_all()
        log_info("Arrêt système.")
        try:
            self.root.destroy()
        except Exception:
            pass
        subprocess.run(["poweroff"], check=False)

    def _pick_usb(self, partitions: List[UsbPartition]) -> Optional[UsbPartition]:
        """Fenêtre de sélection d'une partition USB parmi plusieurs."""
        sel_win = tk.Toplevel(self.root)
        sel_win.title("Sélectionner le support")
        sel_win.resizable(False, False)
        sel_win.grab_set()
        sel_win.transient(self.root)

        w, h = 480, 240
        px = self.root.winfo_rootx() + (self.root.winfo_width()  - w) // 2
        py = self.root.winfo_rooty() + (self.root.winfo_height() - h) // 2
        sel_win.geometry(f"{w}x{h}+{px}+{py}")

        ttk.Label(sel_win, text="Support USB de destination :",
                  font=("Arial", 10, "bold"), padding=10).pack(anchor=tk.W)
        lb = tk.Listbox(sel_win, font=("Courier", 9), height=6)
        for p in partitions:
            mp = self.usb.get_mountpoint(p.device) or "non monté"
            lb.insert(tk.END, f"{p.device}  {p.size}  [{mp}]")
        lb.pack(fill=tk.BOTH, expand=True, padx=10)
        lb.selection_set(0)

        chosen: list = [None]

        def _ok():
            idx = lb.curselection()
            if idx:
                chosen[0] = partitions[idx[0]]
            sel_win.destroy()

        btn_row = ttk.Frame(sel_win, padding=8)
        btn_row.pack()
        ttk.Button(btn_row, text="✓ Sélectionner",
                   command=_ok, width=16).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="✕ Annuler",
                   command=sel_win.destroy, width=12).pack(side=tk.LEFT)
        sel_win.wait_window()
        return chosen[0]

    # ── Worker générique ──────────────────────────────────────────────────────

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
    # PDF + Quitter
    # ══════════════════════════════════════════════════════════════════════════

    def _export_pdf(self) -> None:
        if not self.session_logs:
            messagebox.showinfo("Journal vide", "Aucune entrée à exporter.",
                                parent=self.root)
            return
        try:
            path = generate_session_pdf(self.session_logs)
            messagebox.showinfo("PDF exporté",
                                f"Rapport enregistré :\n{path}",
                                parent=self.root)
        except Exception as e:
            messagebox.showerror("Erreur PDF", str(e), parent=self.root)

    def _quit(self) -> None:
        if self._active_scans > 0:
            if not messagebox.askyesno(
                "Analyse en cours",
                "Une analyse est en cours. Quitter quand même ?",
                parent=self.root
            ):
                return
            for eng in self._scan_engines.values():
                eng.request_stop()
        if self._anim_after_id:
            self.root.after_cancel(self._anim_after_id)
        if self._auto_refresh_id:
            self.root.after_cancel(self._auto_refresh_id)
        if self._pdf_viewer:
            self._pdf_viewer.stop()
        self.usb.umount_all()
        log_info("Application fermée.")
        self.root.destroy()