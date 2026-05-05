#!/usr/bin/env python3
"""
pdf_viewer.py – Moteur de défilement PDF cyclique.

Logique :
  • Charge ../pdf/ trié alphabétiquement (casefold).
  • Ouvre chaque PDF et lit ses pages une à une.
  • Chaque page est affichée PAGE_DURATION_S secondes (défaut : 35 s).
  • Fin de document → fermeture + ouverture du PDF suivant.
  • Fin de liste → retour au premier PDF (boucle infinie).
  • Navigation manuelle : next_page() / prev_page().

Ce module ne dépend pas de Tkinter directement ; il communique avec
l'interface via des callbacks fournis à l'instanciation.

Dépendances optionnelles :
  pip install pymupdf pillow
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

# ── Dépendances optionnelles ──────────────────────────────────────────────────
try:
    import fitz          # PyMuPDF
    _HAS_FITZ = True
except ImportError:
    _HAS_FITZ = False

try:
    from PIL import Image, ImageTk
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False

# ── Constantes ────────────────────────────────────────────────────────────────
PAGE_DURATION_S: float = 35.0   # secondes d'affichage par page
TICK_MS:         int   = 350    # résolution de la barre de progression (ms)
PDF_SUBDIR:      str   = "pdf"  # sous-dossier relatif au répertoire parent


# ── Données d'une page rendue ─────────────────────────────────────────────────

@dataclass
class RenderedPage:
    """Tout ce que l'UI a besoin de savoir pour afficher une page."""
    img_tk:     object          # ImageTk.PhotoImage ou None
    pdf_name:   str             # nom du fichier courant
    pdf_index:  int             # index dans la liste (0-based)
    pdf_count:  int             # nombre total de PDFs
    page_index: int             # index de page dans le document (0-based)
    page_count: int             # nombre total de pages du document


# ── Moteur ────────────────────────────────────────────────────────────────────

class PdfViewer:
    """
    Moteur de défilement PDF entièrement indépendant de l'interface.

    Paramètres
    ----------
    base_dir : str
        Répertoire du script appelant (utilisé pour localiser ../pdf/).
    canvas_size_cb : () -> (int, int)
        Retourne (largeur, hauteur) actuelles du canvas en pixels.
    on_page : (RenderedPage) -> None
        Appelé sur le thread Tkinter quand une nouvelle page est prête.
    on_progress : (float) -> None
        Appelé sur le thread Tkinter toutes les TICK_MS ms avec 0.0–100.0.
    on_no_files : () -> None
        Appelé quand aucun PDF n'est trouvé dans le dossier.
    after_cb : (delay_ms, fn, *args) -> id
        Équivalent de root.after – pour planifier sur le thread UI.
    cancel_cb : (id) -> None
        Équivalent de root.after_cancel.
    log_error_cb : (str) -> None
        Fonction de journalisation des erreurs.
    """

    def __init__(
        self,
        base_dir:      str,
        canvas_size_cb: Callable[[], Tuple[int, int]],
        on_page:       Callable[[RenderedPage], None],
        on_progress:   Callable[[float], None],
        on_no_files:   Callable[[], None],
        after_cb:      Callable,
        cancel_cb:     Callable,
        log_error_cb:  Callable[[str], None],
    ) -> None:

        self._pdf_dir      = os.path.normpath(
            os.path.join(base_dir, "..", PDF_SUBDIR))
        self._canvas_size  = canvas_size_cb
        self._on_page      = on_page
        self._on_progress  = on_progress
        self._on_no_files  = on_no_files
        self._after        = after_cb
        self._cancel       = cancel_cb
        self._log_error    = log_error_cb

        # ── État interne ───────────────────────────────────────────────────────
        self._files:      List[str]       = []
        self._doc:        Optional[object] = None   # fitz.Document en cours
        self._file_idx:   int  = 0    # index du PDF courant dans _files
        self._page_idx:   int  = 0    # index de la page courante dans _doc
        self._page_count: int  = 0    # nombre de pages du _doc courant
        self._tick_id:    Optional[str] = None
        self._start_ts:   float = 0.0
        self._stopped:    bool  = True

    # ══════════════════════════════════════════════════════════════════════════
    # API publique
    # ══════════════════════════════════════════════════════════════════════════

    def start(self) -> None:
        """Démarre le cycle. À appeler une fois l'UI entièrement construite."""
        self._stopped = False
        self._reload_files()
        if not self._files:
            self._on_no_files()
            return
        self._file_idx = 0
        self._open_doc(self._file_idx, first_page=0)

    def stop(self) -> None:
        """Arrête proprement le cycle (appeler à la fermeture de la fenêtre)."""
        self._stopped = True
        self._cancel_tick()
        self._close_doc()

    def next_page(self) -> None:
        """Navigation manuelle : page suivante (ou PDF suivant en fin de doc)."""
        if not self._files or self._stopped:
            return
        self._cancel_tick()
        self._advance()

    def prev_page(self) -> None:
        """Navigation manuelle : page précédente (ou dernière page du PDF précédent)."""
        if not self._files or self._stopped:
            return
        self._cancel_tick()
        if self._page_idx > 0:
            # Reculer d'une page dans le document courant
            self._page_idx -= 1
            self._render_and_display(self._page_idx)
        else:
            # Début du document → aller à la dernière page du PDF précédent
            self._close_doc()
            self._file_idx = (self._file_idx - 1) % len(self._files)
            self._open_doc(self._file_idx, first_page=-1)

    # ══════════════════════════════════════════════════════════════════════════
    # Gestion de la liste de fichiers
    # ══════════════════════════════════════════════════════════════════════════

    def _reload_files(self) -> None:
        """Relit le dossier PDF et trie alphabétiquement (insensible à la casse)."""
        if not os.path.isdir(self._pdf_dir):
            self._files = []
            return
        self._files = [
            os.path.join(self._pdf_dir, f)
            for f in sorted(os.listdir(self._pdf_dir), key=str.casefold)
            if f.lower().endswith(".pdf")
        ]

    # ══════════════════════════════════════════════════════════════════════════
    # Gestion du document
    # ══════════════════════════════════════════════════════════════════════════

    def _open_doc(self, file_idx: int, first_page: int = 0) -> None:
        """
        Ferme le document précédent, ouvre celui à *file_idx*.

        first_page :  0   → première page
                     -1   → dernière page
                      n   → page n
        """
        self._close_doc()
        path = self._files[file_idx]

        if not _HAS_FITZ:
            # Pas de PyMuPDF : on ne peut pas rendre ; on simule 1 page
            self._page_count = 1
            self._page_idx   = 0
            self._render_and_display(0)
            return

        try:
            self._doc        = fitz.open(path)
            self._page_count = self._doc.page_count
            if self._page_count == 0:
                raise ValueError("Document vide (0 pages)")
        except Exception as exc:
            self._log_error(f"PdfViewer – ouverture impossible ({path}): {exc}")
            self._doc        = None
            self._page_count = 0
            # Fichier corrompu : sauter immédiatement au suivant
            self._next_doc()
            return

        # Calcul de la page de départ
        if first_page == -1:
            self._page_idx = self._page_count - 1
        else:
            self._page_idx = max(0, min(first_page, self._page_count - 1))

        self._render_and_display(self._page_idx)

    def _close_doc(self) -> None:
        """Ferme le document fitz ouvert, si applicable."""
        if self._doc is not None:
            try:
                self._doc.close()
            except Exception:
                pass
            self._doc = None

    def _next_doc(self) -> None:
        """Ferme le document courant et ouvre le suivant (boucle)."""
        self._close_doc()
        if not self._files:
            return
        self._file_idx = (self._file_idx + 1) % len(self._files)
        self._open_doc(self._file_idx, first_page=0)

    # ══════════════════════════════════════════════════════════════════════════
    # Avancement de page
    # ══════════════════════════════════════════════════════════════════════════

    def _advance(self) -> None:
        """Passe à la page suivante ou au document suivant si fin de document."""
        next_page = self._page_idx + 1
        if next_page < self._page_count:
            self._page_idx = next_page
            self._render_and_display(self._page_idx)
        else:
            # Dernière page atteinte → document suivant
            self._next_doc()

    # ══════════════════════════════════════════════════════════════════════════
    # Rendu
    # ══════════════════════════════════════════════════════════════════════════

    def _render_and_display(self, page_idx: int) -> None:
        """
        Lance le rendu de la page *page_idx* dans un thread dédié.
        Le thread produit un PIL.Image (thread-safe).
        La conversion en ImageTk.PhotoImage se fait ensuite sur le thread
        principal dans _on_rendered(), via root.after(0, ...).
        """
        if self._stopped:
            return

        # Capture des valeurs courantes pour le thread
        doc        = self._doc
        file_idx   = self._file_idx
        page_count = self._page_count
        files      = self._files

        def _worker() -> None:
            pil_img = self._render_pil(doc, page_idx)   # PIL.Image ou None
            if self._stopped:
                return
            # On passe pil_img (pas encore ImageTk) ; la conversion a lieu
            # dans _on_rendered, sur le thread principal.
            self._after(0, self._on_rendered,
                        pil_img, file_idx, page_idx, page_count, files)

        threading.Thread(target=_worker, daemon=True).start()

    def _render_pil(self, doc, page_idx: int) -> Optional[object]:
        """
        Rend la page *page_idx* et retourne un PIL.Image mis à l'échelle
        pour remplir le canvas (ratio préservé).
        Retourne None si les dépendances manquent ou en cas d'erreur.

        ⚠  Ne pas appeler ImageTk.PhotoImage ici : cette méthode s'exécute
           dans un thread secondaire et Tkinter n'est pas thread-safe.
        """
        if not (_HAS_FITZ and _HAS_PIL) or doc is None:
            return None
        try:
            cw, ch = self._canvas_size()
            if cw < 10:
                cw = 595    # A4 à 72 dpi, largeur
            if ch < 10:
                ch = 842    # A4 à 72 dpi, hauteur

            page = doc.load_page(page_idx)
            rect = page.rect
            zoom = min(cw / rect.width, ch / rect.height)
            mat  = fitz.Matrix(zoom, zoom)
            pix  = page.get_pixmap(matrix=mat, alpha=False)
            # Retour d'un PIL.Image — pas d'ImageTk ici !
            return Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        except Exception as exc:
            self._log_error(
                f"PdfViewer – rendu page {page_idx} impossible: {exc}")
            return None

    # ══════════════════════════════════════════════════════════════════════════
    # Callback UI + minuterie
    # ══════════════════════════════════════════════════════════════════════════

    def _on_rendered(self, pil_img, file_idx: int, page_idx: int,
                     page_count: int, files: list) -> None:
        """
        Appelé sur le thread principal (via after).
        Convertit le PIL.Image en ImageTk.PhotoImage (obligatoirement ici),
        construit le RenderedPage, le transmet à l'UI puis démarre le timer.
        """
        if self._stopped:
            return

        # Conversion PIL → ImageTk sur le thread principal ─ obligatoire
        img_tk: Optional[object] = None
        if pil_img is not None and _HAS_PIL:
            try:
                img_tk = ImageTk.PhotoImage(pil_img)
            except Exception as exc:
                self._log_error(f"PdfViewer – ImageTk conversion error: {exc}")

        rp = RenderedPage(
            img_tk     = img_tk,
            pdf_name   = os.path.basename(files[file_idx]),
            pdf_index  = file_idx,
            pdf_count  = len(files),
            page_index = page_idx,
            page_count = page_count,
        )
        self._on_page(rp)
        self._start_ts = time.monotonic()
        self._tick()

    def _cancel_tick(self) -> None:
        if self._tick_id is not None:
            self._cancel(self._tick_id)
            self._tick_id = None

    def _tick(self) -> None:
        """Mis à jour toutes les TICK_MS ms ; déclenche _advance() à échéance."""
        if self._stopped:
            return
        elapsed = time.monotonic() - self._start_ts
        pct = min(100.0, elapsed / PAGE_DURATION_S * 100.0)
        self._on_progress(pct)
        if pct >= 100.0:
            self._advance()
        else:
            self._tick_id = self._after(TICK_MS, self._tick)