#!/usr/bin/env python3
"""
gui.py – Interface principale du scanner antiviral USB.

Interface utilisateur :
  • Sélection multi-clés USB → scans parallèles par threading
  • Animation canvas (bouclier pulsant)
  • Journal d'activité
  • Bouton lancer / annuler

Administration (protégée par code) :
  • Moteurs actifs (ClamAV / Avast / YARA) + mode scan + suppression
  • Affichage exhaustif des supports USB
  • Mise à jour ClamAV, Avast, YARA
  • Planification crontab
  • Journaux : export, purge
  • Sécurité (code admin), Arrêt, Quitter
"""

import math
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Dict, List, Optional

from admin_auth import AdminAuthManager, AdminPanel
from config import YARA_RULES_DIR
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

        # ── Animation ─────────────────────────────────────────────────────────
        self._anim_after_id: Optional[str] = None
        self._anim_phase    = 0.0
        self._anim_state    = "idle"   # idle | scanning | ok | threat

        if os.geteuid() != 0:
            messagebox.showerror("Droits insuffisants",
                                 "Ce programme doit être lancé avec sudo.")
            root.destroy()
            sys.exit(1)

        self._build_ui()
        self._refresh_status()
        self._refresh_usb()
        self._animate()
        self.root.protocol("WM_DELETE_WINDOW", self._request_admin)

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

        tk.Label(topbar, text="Protection de vos données amovibles",
                 font=("Arial", 9, "italic"),
                 bg=self.TOPBAR, fg=self.FG_DIM).pack(side=tk.LEFT, padx=4)

        tk.Button(topbar, text="⛶ Plein écran",
                  command=self._toggle_fullscreen,
                  bg=self.CARD, fg=self.FG_DIM, relief=tk.FLAT,
                  font=("Arial", 9), padx=8).pack(side=tk.RIGHT, padx=4)
        tk.Button(topbar, text="⚙  Administration",
                  command=self._request_admin,
                  bg=self.ACCENT, fg="white", relief=tk.FLAT,
                  font=("Arial", 9, "bold"), padx=12).pack(side=tk.RIGHT, padx=8)

        # ── Bandeau statut des moteurs ─────────────────────────────────────────
        sbar = tk.Frame(self.root, bg="#0a2240", pady=3)
        sbar.pack(fill=tk.X)
        self.clamav_status_var = tk.StringVar(value="ClamAV : vérification…")
        self.avast_status_var  = tk.StringVar(value="Avast : vérification…")
        self.yara_status_var   = tk.StringVar(value="YARA : vérification…")
        self.tp_status_var     = tk.StringVar(value="Sigs tierces : vérification…")
        for var in (self.clamav_status_var, self.avast_status_var,
                    self.yara_status_var, self.tp_status_var):
            tk.Label(sbar, textvariable=var,
                     bg="#0a2240", fg=self.GREEN,
                     font=("Courier", 8), padx=14).pack(side=tk.LEFT)

        # ── Corps principal ────────────────────────────────────────────────────
        body = tk.Frame(self.root, bg=self.BG)
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        left   = tk.Frame(body, bg=self.BG, width=420)
        center = tk.Frame(body, bg=self.BG)
        right  = tk.Frame(body, bg=self.BG, width=360)
        left.pack(side=tk.LEFT,  fill=tk.BOTH, expand=False, padx=(0, 4))
        left.pack_propagate(False)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(4, 0))
        right.pack_propagate(False)
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,  padx=(0, 4))

        self._build_usb_panel(left)
        self._build_scan_controls(left)
        self._build_animation_panel(center)
        self._build_log_panel(right)

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
                                      height=7, selectmode="none")

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

        # ── Boutons en ligne sous le tableau ──────────────────────────────────
        btn_row = tk.Frame(outer, bg=self.CARD, padx=6, pady=4)
        btn_row.pack(fill=tk.X)
        btn_row.columnconfigure(0, weight=1)
        btn_row.columnconfigure(1, weight=1)
        btn_row.columnconfigure(2, weight=1)
        for col, (txt, cmd, color) in enumerate([
            ("↺  Actualiser", self._refresh_usb,  self.TOPBAR),
            ("▲  Monter",     self._mount_usb,    "#1a4a1a"),
            ("▼  Démonter",   self._umount_usb,   "#3a1a00"),
        ]):
            tk.Button(btn_row, text=txt, command=cmd,
                      bg=color, fg=self.FG, relief=tk.FLAT,
                      font=("Arial", 9, "bold"), pady=8,
                      cursor="hand2").grid(row=0, column=col,
                                           sticky=tk.EW, padx=2)

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
        outer.pack(fill=tk.X, pady=4)
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

    # ── Panneau animation ─────────────────────────────────────────────────────

    def _build_animation_panel(self, parent: tk.Frame) -> None:
        # ── Zone logo ──────────────────────────────────────────────────────────
        logo_frame = tk.Frame(parent, bg=self.CARD, bd=1, relief=tk.SOLID,
                              height=88)
        logo_frame.pack(fill=tk.X, pady=(0, 4))
        logo_frame.pack_propagate(False)

        logo_path = os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "..", "img", "logo.png"))
        self._logo_img: Optional[tk.PhotoImage] = None
        try:
            img = tk.PhotoImage(file=logo_path)
            # Sous-échantillonnage si trop grand (PhotoImage natif)
            iw, ih = img.width(), img.height()
            max_h = 76
            if ih > max_h:
                factor = max(1, ih // max_h)
                img = img.subsample(factor, factor)
            self._logo_img = img
            tk.Label(logo_frame, image=self._logo_img,
                     bg=self.CARD, cursor="arrow").pack(expand=True)
        except Exception:
            # Fallback texte si l'image est introuvable
            tk.Label(logo_frame,
                     text="🛡  USB Antivirus Scanner",
                     bg=self.CARD, fg="#3a6498",
                     font=("Arial", 18, "bold italic")).pack(expand=True)

        # ── Canvas d'animation (remplit tout l'espace restant) ─────────────────
        anim_outer = tk.Frame(parent, bg=self.CARD, bd=1, relief=tk.SOLID)
        anim_outer.pack(fill=tk.BOTH, expand=True)

        self._anim_canvas = tk.Canvas(
            anim_outer, bg=self.CARD, highlightthickness=0
        )
        self._anim_canvas.pack(fill=tk.BOTH, expand=True)

        # Vars conservées pour compatibilité avec le reste du code
        self.status_var   = tk.StringVar(value="Prêt — insérez une clé USB")
        self.scanned_var  = tk.StringVar(value="")
        self.infected_var = tk.StringVar(value="")

    # ── Journal ───────────────────────────────────────────────────────────────

    def _build_log_panel(self, parent: tk.Frame) -> None:
        hdr = tk.Frame(parent, bg=self.BG)
        hdr.pack(fill=tk.X, pady=(0, 4))
        tk.Label(hdr, text="  Journal d'activité",
                 bg=self.BG, fg=self.FG_DIM,
                 font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        tk.Button(hdr, text="🧹 Vider",
                  command=self._clear_log,
                  bg=self.CARD, fg=self.FG_DIM, relief=tk.FLAT,
                  font=("Arial", 8)).pack(side=tk.RIGHT)

        self.log_text = tk.Text(
            parent, bg="#0b0d14", fg="#c8d0de",
            font=("Courier", 9), wrap=tk.WORD,
            state=tk.NORMAL, insertbackground="white",
            relief=tk.FLAT, padx=10, pady=8
        )
        sb = ttk.Scrollbar(parent, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)

        self.log_text.tag_config("threat",  foreground=self.RED)
        self.log_text.tag_config("ok",      foreground=self.GREEN)
        self.log_text.tag_config("warning", foreground=self.YELLOW)
        self.log_text.tag_config("info",    foreground="#5577aa")
        self.log_text.tag_config("normal",  foreground="#c8d0de")

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    # ══════════════════════════════════════════════════════════════════════════
    # Animation canvas
    # ══════════════════════════════════════════════════════════════════════════

    def _animate(self) -> None:
        c  = self._anim_canvas
        cw = c.winfo_width()  or 500
        ch = c.winfo_height() or 340
        cx, cy = cw // 2, ch // 2
        c.delete("all")

        st = self._anim_state
        ph = self._anim_phase

        # ── Avancer la phase ──────────────────────────────────────────────────
        speed = {"scanning": 3.5, "ok": 1.2, "threat": 2.0, "idle": 0.7}
        self._anim_phase = (ph + speed.get(st, 0.7)) % 360

        # ── Rayon du bouclier (adapté à la taille du canvas) ──────────────────
        sr = max(44, min(int(min(cw, ch) * 0.22), 88))

        # ══ 1. FOND — grille de points hexagonaux ════════════════════════════
        spacing = 30
        for row_i, gy in enumerate(range(0, ch + spacing, spacing)):
            for gx in range(-(spacing if row_i % 2 else 0),
                             cw + spacing, spacing):
                dx, dy = gx - cx, gy - cy
                dist = math.sqrt(dx*dx + dy*dy)
                if dist < sr * 1.1:
                    continue
                brightness = max(0, 1.0 - dist / (max(cw, ch) * 0.65))
                if brightness > 0.06:
                    c.create_oval(gx-1, gy-1, gx+1, gy+1,
                                   fill="#1e2a4a", outline="")

        # ══ 2. EFFETS SPÉCIFIQUES À L'ÉTAT ═══════════════════════════════════

        if st == "scanning":
            # ── Anneaux radars concentriques ──────────────────────────────────
            for i in range(6):
                ring_ph = (ph + i * 60) % 360
                fade    = abs(math.sin(math.radians(ring_ph)))
                r_ring  = sr * (1.6 + i * 0.55) + fade * 5
                if r_ring > max(cw, ch):
                    break
                stip = ("gray75", "gray50", "gray50", "gray25",
                         "gray25", "gray12")[i]
                c.create_oval(cx - r_ring, cy - r_ring,
                               cx + r_ring, cy + r_ring,
                               outline="#2244aa", width=1, stipple=stip)

            # ── Balayage radar ────────────────────────────────────────────────
            sweep_deg  = (ph * 2.2) % 360
            sweep_rad  = math.radians(sweep_deg)
            radar_r    = sr * 3.0
            # Traînée en arc (dégradé simulé par plusieurs arcs)
            for arc_i, (ext, w, stip) in enumerate(
                    [(90, 6, "gray50"), (60, 4, "gray25"), (30, 2, "gray12")]):
                c.create_arc(cx - radar_r, cy - radar_r,
                              cx + radar_r, cy + radar_r,
                              start=sweep_deg, extent=ext,
                              outline="#4488ff", width=w,
                              style=tk.ARC, stipple=stip)
            # Ligne de balayage
            c.create_line(cx, cy,
                           cx + math.cos(sweep_rad) * radar_r,
                           cy - math.sin(sweep_rad) * radar_r,
                           fill="#88bbff", width=2)

            # ── Particules / points scannés ───────────────────────────────────
            for i in range(12):
                angle    = math.radians((ph * 2.8 + i * 30) % 360)
                progress = ((ph / 360.0) * 0.7 + i / 12.0) % 1.0
                r_p      = sr * 1.3 + progress * sr * 2.8
                px_p     = cx + math.cos(angle) * r_p
                py_p     = cy - math.sin(angle) * r_p
                size_p   = max(1.5, 3.5 * (1 - progress))
                if 0 < px_p < cw and 0 < py_p < ch:
                    alpha_color = "#4488ff" if progress < 0.5 else "#224466"
                    c.create_oval(px_p - size_p, py_p - size_p,
                                   px_p + size_p, py_p + size_p,
                                   fill=alpha_color, outline="")

            # ── Compteurs en temps réel (affichage proéminent) ────────────────
            ns = self._total_scanned
            ni = self._total_infected
            na = self._active_scans

            # Position : deux colonnes au-dessus du bouclier
            stat_y  = cy - sr - 52
            left_x  = cx - sr * 1.1
            right_x = cx + sr * 1.1

            # Fond semi-transparent (rectangles)
            pad = 8
            for bx, val_text, lbl_text, col in [
                (left_x,  str(ns), "fichiers analysés", "#88ccff"),
                (right_x, str(ni),
                 "menace(s)",
                 self.RED if ni > 0 else self.GREEN),
            ]:
                tw = max(60, len(str(max(ns, ni))) * 14 + 30)
                c.create_rectangle(bx - tw//2 - pad, stat_y - 4,
                                    bx + tw//2 + pad, stat_y + 36,
                                    fill="#0d1528", outline="#223355",
                                    width=1)
                c.create_text(bx, stat_y + 2,
                              text=val_text, fill=col,
                              font=("Courier", 20, "bold"), anchor=tk.N)
                c.create_text(bx, stat_y + 30,
                              text=lbl_text, fill=self.FG_DIM,
                              font=("Arial", 8), anchor=tk.N)

            if na > 1:
                c.create_text(cx, stat_y + 52,
                              text=f"⚡ {na} scans en parallèle",
                              fill="#5577aa", font=("Arial", 9, "bold"),
                              anchor=tk.CENTER)

        elif st == "ok":
            # ── Éclat de lumière verte ────────────────────────────────────────
            pulse = abs(math.sin(math.radians(ph * 2.5)))
            for i in range(4):
                r_g = sr * (1.35 + i * 0.35 + pulse * 0.12)
                stip = ("gray75", "gray50", "gray25", "gray12")[i]
                c.create_oval(cx - r_g, cy - r_g, cx + r_g, cy + r_g,
                               fill="", outline=self.GREEN,
                               width=2, stipple=stip)
            # Étincelles
            for i in range(10):
                angle = math.radians(ph * 2.5 + i * 36)
                r_sp  = sr * (1.55 + pulse * 0.45)
                sx    = cx + math.cos(angle) * r_sp
                sy    = cy - math.sin(angle) * r_sp
                if 0 < sx < cw and 0 < sy < ch:
                    c.create_oval(sx-2, sy-2, sx+2, sy+2,
                                   fill=self.GREEN, outline="")
            # Résultats finaux
            res_y = cy - sr - 44
            c.create_rectangle(cx - 110, res_y - 6, cx + 110, res_y + 32,
                                fill="#071a0f", outline="#1a5e2a", width=1)
            c.create_text(cx, res_y + 2,
                          text=f"✓  {self._total_scanned} fichier(s) analysé(s) — propre",
                          fill=self.GREEN,
                          font=("Arial", 11, "bold"), anchor=tk.N)

        elif st == "threat":
            # ── Pulsations rouges ─────────────────────────────────────────────
            pulse = abs(math.sin(math.radians(ph * 3.5)))
            for i in range(4):
                r_t = sr * (1.3 + i * 0.4 + pulse * 0.2)
                stip = ("gray75", "gray50", "gray25", "gray12")[i]
                c.create_oval(cx - r_t, cy - r_t, cx + r_t, cy + r_t,
                               fill="", outline=self.RED,
                               width=2, stipple=stip)
            # Triangles d'alerte aux coins
            for i in range(4):
                angle = math.radians(ph * 1.8 + i * 90 + 45)
                r_tri = sr * 2.2
                tx    = cx + math.cos(angle) * r_tri
                ty    = cy - math.sin(angle) * r_tri
                sz    = 10
                tri_pts = [tx,       ty - sz,
                            tx - sz * 0.87, ty + sz * 0.5,
                            tx + sz * 0.87, ty + sz * 0.5]
                c.create_polygon(tri_pts, fill=self.RED,
                                  outline="", stipple="gray75")
            # Résultats
            res_y = cy - sr - 44
            c.create_rectangle(cx - 130, res_y - 6, cx + 130, res_y + 32,
                                fill="#1a0000", outline="#5e1a1a", width=1)
            c.create_text(cx, res_y + 2,
                          text=f"⚠  {self._total_infected} menace(s) / "
                               f"{self._total_scanned} fichier(s)",
                          fill=self.RED,
                          font=("Arial", 11, "bold"), anchor=tk.N)

        else:  # idle
            # ── Halo pulsant ──────────────────────────────────────────────────
            pulse = abs(math.sin(math.radians(ph * 1.8)))
            for i in range(3):
                r_h = sr * (1.25 + i * 0.45 + pulse * 0.12)
                stip = ("gray50", "gray25", "gray12")[i]
                c.create_oval(cx - r_h, cy - r_h, cx + r_h, cy + r_h,
                               fill="", outline="#2a4a78",
                               width=1, stipple=stip)
            # Trois petits USB en orbite
            for i in range(3):
                orbit_angle = math.radians(ph * 1.4 + i * 120)
                orbit_r     = sr * 1.75
                ox = cx + math.cos(orbit_angle) * orbit_r
                oy = cy - math.sin(orbit_angle) * orbit_r
                # Corps USB
                c.create_rectangle(ox-6, oy-4, ox+6, oy+4,
                                    fill="#2a4a78", outline="#4a7ab8", width=1)
                c.create_rectangle(ox-3, oy+4, ox+3, oy+8,
                                    fill="#2a4a78", outline="#4a7ab8", width=1)
                # Connecteur
                c.create_rectangle(ox-2, oy-8, ox+2, oy-4,
                                    fill="#4a7ab8", outline="#88aacc", width=1)

        # ══ 3. BOUCLIER CENTRAL ══════════════════════════════════════════════
        if st == "scanning":
            sf, so, gc = "#0f1e55", "#4488ff", "#4488ff"
        elif st == "ok":
            sf, so, gc = "#062210", self.GREEN, self.GREEN
        elif st == "threat":
            sf, so, gc = "#3a0000", self.RED, self.RED
        else:
            sf, so, gc = "#0f2244", "#3a6498", "#3a6498"

        # Forme bouclier
        pts = [
            cx,      cy - sr,
            cx + int(sr * 0.76), cy - int(sr * 0.50),
            cx + int(sr * 0.76), cy + int(sr * 0.30),
            cx,      cy + sr,
            cx - int(sr * 0.76), cy + int(sr * 0.30),
            cx - int(sr * 0.76), cy - int(sr * 0.50),
        ]
        # Ombre
        c.create_polygon([p + 5 for p in pts],
                          fill="#000000", outline="", stipple="gray25")
        # Corps
        c.create_polygon(pts, fill=sf, outline=so, width=2)
        # Reflet haut-gauche
        hl = [
            cx - int(sr * 0.30), cy - int(sr * 0.72),
            cx + int(sr * 0.10), cy - int(sr * 0.72),
            cx - int(sr * 0.08), cy - int(sr * 0.20),
            cx - int(sr * 0.40), cy - int(sr * 0.32),
        ]
        c.create_polygon(hl, fill="white", outline="", stipple="gray25")
        # Bord interne
        inset = 5
        inner_pts = [
            cx,           cy - sr + inset,
            cx + int((sr - inset) * 0.74), cy - int((sr - inset) * 0.50),
            cx + int((sr - inset) * 0.74), cy + int((sr - inset) * 0.28),
            cx,           cy + sr - inset,
            cx - int((sr - inset) * 0.74), cy + int((sr - inset) * 0.28),
            cx - int((sr - inset) * 0.74), cy - int((sr - inset) * 0.50),
        ]
        c.create_polygon(inner_pts, fill="", outline=gc, width=1,
                          stipple="gray50")

        # ── Icône dans le bouclier ────────────────────────────────────────────
        ic = int(sr * 0.38)
        lw = max(2, sr // 18)
        if st == "ok":
            c.create_line(cx - ic, cy + ic//5,
                           cx - ic//4, cy + ic,
                           cx + ic,    cy - ic,
                           fill=self.GREEN, width=lw + 1,
                           joinstyle=tk.ROUND, capstyle=tk.ROUND)
        elif st == "threat":
            c.create_line(cx - ic * 0.75, cy - ic * 0.75,
                           cx + ic * 0.75, cy + ic * 0.75,
                           fill=self.RED, width=lw + 1, capstyle=tk.ROUND)
            c.create_line(cx + ic * 0.75, cy - ic * 0.75,
                           cx - ic * 0.75, cy + ic * 0.75,
                           fill=self.RED, width=lw + 1, capstyle=tk.ROUND)
        elif st == "scanning":
            # Arc tournant double
            a0 = (ph * 2.2) % 360
            c.create_arc(cx - ic, cy - ic, cx + ic, cy + ic,
                          start=a0, extent=250,
                          outline="#88bbff", width=lw + 1, style=tk.ARC)
            c.create_arc(cx - ic//2, cy - ic//2, cx + ic//2, cy + ic//2,
                          start=a0 + 180, extent=200,
                          outline="#4466aa", width=lw, style=tk.ARC)
        else:
            # Clé USB stylisée
            c.create_rectangle(cx - ic//2, cy - ic//5,
                                cx + ic//2, cy + ic//2,
                                fill=sf, outline=gc, width=1)
            c.create_rectangle(cx - ic//4, cy + ic//2,
                                cx + ic//4, cy + int(ic * 0.85),
                                fill=sf, outline=gc, width=1)
            c.create_rectangle(cx - ic//6, cy - int(ic * 0.65),
                                cx + ic//6, cy - ic//5,
                                fill=gc, outline=gc, width=1)

        # ══ 4. TEXTE D'ÉTAT sous le bouclier ═════════════════════════════════
        text_y = cy + sr + 18
        if st == "scanning":
            dots  = "." * (int(ph / 90) % 4)
            label = f"Analyse en cours{dots}"
        elif st == "ok":
            label = "✓  Aucune menace détectée"
        elif st == "threat":
            label = f"⚠  {self._total_infected} menace(s) !"
        else:
            label = "Prêt — insérez une clé USB"

        c.create_text(cx, text_y,
                      text=label, fill=gc,
                      font=("Arial", 11, "bold"), anchor=tk.CENTER)

        # Sous-texte résultats (hors scan)
        if st not in ("scanning", "idle") and self._total_scanned > 0:
            c.create_text(cx, text_y + 20,
                          text=f"{self._total_scanned} fichier(s) analysé(s)",
                          fill=self.FG_DIM, font=("Courier", 8),
                          anchor=tk.CENTER)

        interval = 33 if st == "scanning" else 100
        self._anim_after_id = self.root.after(interval, self._animate)

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
            clamav_text = "❌  ClamAV : non installé"
        else:
            info    = self.db.get_clamav_status()
            st      = info["status"]
            lu      = info.get("last_update", "?")
            count   = self.db.get_known_virus_count()
            count_s = (f"  {count:,} sig.".replace(",", "\u202f")
                       if count else "")
            if st == "OK":
                clamav_text = f"✅  ClamAV  (màj : {lu}){count_s}"
            elif st == "OUTDATED":
                clamav_text = f"⚠   ClamAV : base obsolète  ({lu})"
            else:
                missing = info.get("missing", [])
                clamav_text = (f"❌  ClamAV : bases manquantes"
                               + (f" – {', '.join(missing)}" if missing else ""))

        # Avast
        avast_installed = self.engine.is_avast_installed()
        avast_licensed  = self.engine.is_avast_licensed()
        if not avast_installed:
            avast_text = "⭕  Avast : non installé"
        elif not avast_licensed:
            avast_text = "⚠   Avast : installé, sans licence"
        else:
            avast_text = "✅  Avast : actif"

        # YARA
        yara_ok, method = self.engine.detect_yara()
        if not yara_ok:
            yara_text = "⭕  YARA : non disponible"
        else:
            yi = self.db.get_yara_status()
            n  = yi["count"]
            lu2 = yi.get("last_update", "?")
            yara_text = (f"✅  YARA ({method}) : {n} règle(s)  (màj : {lu2})"
                         if n > 0 else f"⚠   YARA ({method}) : aucune règle")

        # Signatures tierces ClamAV
        import glob as _glob
        _TP_PATTERNS = [
            "*.ndb", "*.hdb", "*.hsb", "*.db",
            "*.ftm", "*.ldb", "*.cdb", "*.fp", "*.ign2"
        ]
        tp_count = sum(
            len(_glob.glob(f"/var/lib/clamav/{p}")) for p in _TP_PATTERNS
        )
        if tp_count > 0:
            tp_text = f"Sigs tierces : {tp_count} fichier(s)"
        else:
            tp_text = "⚠  Sigs tierces : aucune"

        def _apply():
            self.clamav_status_var.set(clamav_text)
            self.avast_status_var.set(avast_text)
            self.yara_status_var.set(yara_text)
            self.tp_status_var.set(tp_text)
            # Synchronise les vars d'options avec la réalité du système
            if avast_installed and avast_licensed:
                self.use_avast_var.set(True)
            elif not avast_installed:
                self.use_avast_var.set(False)
            if not yara_ok:
                self.use_yara_var.set(False)
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

        # Prépare les cibles
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
            self._active_scans   += len(targets_map)
            self._total_scanned   = 0
            self._total_infected  = 0

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
        def _progress(msg: str, tag: str = "normal") -> None:
            self.root.after(0, self._log, msg, tag)

        try:
            result = eng.scan(
                targets          = targets,
                use_clamav       = self.use_clamav_var.get(),
                use_avast        = self.use_avast_var.get(),
                use_yara         = self.use_yara_var.get(),
                remove_infected  = self.remove_var.get(),
                progress_cb      = _progress,
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
            if result:
                self._total_scanned  += result.scanned
                self._total_infected += result.infected

        if result:
            tag  = "threat" if result.infected > 0 else "ok"
            icon = "⚠" if result.infected > 0 else "✅"
            self._log(
                f"{icon} {dev} : {result.scanned} fichier(s), "
                f"{result.infected} menace(s)  ({result.duration:.1f}s)",
                tag
            )
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

        # Export PDF automatique sur le support analysé
        self._auto_export_to_device(dev, result)

        # Si plus aucun scan actif, bilan global
        if self._active_scans == 0:
            self._all_scans_done()

    def _all_scans_done(self) -> None:
        self.stop_btn.configure(state=tk.DISABLED, bg="#444")

        if self._total_infected > 0:
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
        else:
            self._anim_state = "ok"
            self.status_var.set("✅  Aucune menace détectée")
            messagebox.showinfo(
                "Analyse terminée",
                f"{self._total_scanned} fichier(s) analysé(s) — aucune menace.",
                parent=self.root
            )

        self.root.after(5000, self._reset_anim_idle)

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

            # Remontage RW
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
                                f"📄 Rapport PDF écrit : {os.path.basename(report_path)}",
                                "ok")
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
            # Système
            on_poweroff               = self._admin_poweroff,
            on_quit                   = self._quit,
            # Support exhaustif
            get_usb_partitions        = lambda: self._usb_partitions,
            refresh_usb               = self._refresh_usb,
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
        self.usb.umount_all()
        log_info("Application fermée.")
        self.root.destroy()