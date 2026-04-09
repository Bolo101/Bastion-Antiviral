#!/usr/bin/env python3
"""log_handler.py – Journalisation avec rotation par volumétrie et export PDF/USB."""

import logging
import os
import shutil
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import List, Tuple

from config import LOG_FILE

# ── Paramètres de rotation ─────────────────────────────────────────────────────
_LOG_MAX_BYTES  = 5 * 1024 * 1024   # 5 Mo par fichier
_LOG_BACKUP_CNT = 5                  # 5 archives conservées

# ── Configuration du logger ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("virusscanner")
logger.setLevel(logging.INFO)

try:
    _fh = RotatingFileHandler(
        LOG_FILE,
        maxBytes=_LOG_MAX_BYTES,
        backupCount=_LOG_BACKUP_CNT,
        encoding="utf-8",
        delay=False,
    )
    _fh.setLevel(logging.INFO)
    _fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(_fh)
except PermissionError:
    print("Erreur : permissions insuffisantes. Lancez avec sudo.", file=sys.stderr)
    sys.exit(1)


def log_info(msg: str)    -> None: logger.info(msg)
def log_error(msg: str)   -> None: logger.error(msg)
def log_warning(msg: str) -> None: logger.warning(msg)


# ── Gestion des fichiers de log ────────────────────────────────────────────────

def get_log_files() -> List[str]:
    """
    Retourne la liste des fichiers de log existants :
    le fichier actif + les archives de rotation (.1 … .N).
    """
    files: List[str] = []
    if os.path.exists(LOG_FILE):
        files.append(LOG_FILE)
    for i in range(1, _LOG_BACKUP_CNT + 1):
        rotated = f"{LOG_FILE}.{i}"
        if os.path.exists(rotated):
            files.append(rotated)
    return files


def get_log_size_info() -> str:
    """
    Retourne une chaîne lisible décrivant la volumétrie des logs,
    ex. : "3 fichier(s)  –  4,2 Mo"
    """
    files = get_log_files()
    total = sum(os.path.getsize(f) for f in files)
    mb    = total / (1024 * 1024)
    size_str = f"{mb:.1f} Mo" if mb >= 1.0 else f"{total // 1024} Ko"
    return f"{len(files)} fichier(s)  –  {size_str}"


def purge_logs() -> Tuple[bool, str]:
    """
    Supprime tous les fichiers de log (actif + archives de rotation).
    Recrée ensuite le fichier actif vide pour que le handler RotatingFileHandler
    puisse continuer d'écrire sans erreur.
    Retourne (ok, message).
    """
    deleted: List[str] = []
    errors:  List[str] = []

    for path in get_log_files():
        try:
            os.remove(path)
            deleted.append(path)
        except OSError as e:
            errors.append(f"{os.path.basename(path)}: {e}")

    # Recréer le fichier principal vide
    try:
        with open(LOG_FILE, "w", encoding="utf-8") as _f:
            pass
    except OSError:
        pass

    if errors:
        return False, "Erreurs lors de la purge : " + " ; ".join(errors)

    n = len(deleted)
    # On relogue APRÈS la purge pour avoir une trace
    log_info(f"Purge des logs effectuée : {n} fichier(s) supprimé(s).")
    return True, f"{n} fichier(s) de log supprimé(s) avec succès."


def export_logs_to_path(dest_dir: str) -> Tuple[bool, str]:
    """
    Copie tous les fichiers de log (actif + archives) dans dest_dir.
    Chaque fichier est préfixé d'un horodatage pour éviter les collisions.
    Retourne (ok, message).
    """
    if not os.path.isdir(dest_dir):
        return False, f"Répertoire de destination introuvable : {dest_dir}"

    files = get_log_files()
    if not files:
        return False, "Aucun fichier de log à exporter."

    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    copied: List[str] = []
    errors: List[str] = []

    for src in files:
        basename = os.path.basename(src)
        dst      = os.path.join(dest_dir, f"{ts}_{basename}")
        try:
            shutil.copy2(src, dst)
            copied.append(dst)
        except OSError as e:
            errors.append(f"{basename}: {e}")

    if errors:
        return False, "Erreurs lors de la copie : " + " ; ".join(errors)

    log_info(f"Export des logs vers {dest_dir} : {len(copied)} fichier(s) copié(s).")
    return True, f"{len(copied)} fichier(s) exporté(s) dans :\n{dest_dir}"


# ── Export PDF (bibliothèques standard uniquement) ────────────────────────────

def generate_session_pdf(session_logs: List[str]) -> str:
    out_dir = "/tmp/virusscanner_reports"
    os.makedirs(out_dir, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"scan_report_{ts}.pdf")
    _write_pdf(path, "Rapport de session – USB Antivirus Scanner", session_logs,
               f"Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
               f"Entrées de journal : {len(session_logs)}")
    log_info(f"PDF exporté : {path}")
    return path


def _write_pdf(path: str, title: str, lines: List[str], *info: str) -> None:
    content  = _build_stream(title, lines, *info)
    cb       = content.encode("latin-1", errors="replace")
    with open(path, "wb") as f:
        f.write(b"%PDF-1.4\n")
        pos: dict = {}

        def obj(n: int, raw: bytes) -> None:
            pos[n] = f.tell()
            f.write(raw)

        obj(1, b"1 0 obj\n<</Type /Catalog /Pages 2 0 R>>\nendobj\n")
        obj(2, b"2 0 obj\n<</Type /Pages /Kids [3 0 R] /Count 1>>\nendobj\n")
        obj(3, (
            b"3 0 obj\n<</Type /Page /Parent 2 0 R "
            b"/MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources <</Font <</F1 5 0 R>>>>>>\nendobj\n"
        ))
        obj(4, (
            f"4 0 obj\n<</Length {len(cb)}>>\nstream\n".encode()
            + cb + b"\nendstream\nendobj\n"
        ))
        obj(5, b"5 0 obj\n<</Type /Font /Subtype /Type1 /BaseFont /Courier>>\nendobj\n")

        xref = f.tell()
        f.write(b"xref\n0 6\n0000000000 65535 f \n")
        for i in range(1, 6):
            f.write(f"{pos[i]:010d} 00000 n \n".encode())
        f.write(
            f"trailer\n<</Size 6 /Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n".encode()
        )


def _build_stream(title: str, lines: List[str], *info: str) -> str:
    out = ["BT", "/F1 14 Tf", "50 750 Td", f"({_esc(title)}) Tj",
           "/F1 9 Tf"]
    y = 720
    for il in info:
        out += ["0 -15 Td", f"({_esc(il)}) Tj"]
        y -= 15
    out += ["/F1 8 Tf", "0 -20 Td"]
    y -= 20
    for ln in (lines or ["(vide)"]):
        if y < 50:
            out += ["ET", "BT", "/F1 8 Tf", "50 750 Td"]
            y = 750
        ln = ln[:90] + "…" if len(ln) > 90 else ln
        out += ["0 -12 Td", f"({_esc(ln)}) Tj"]
        y -= 12
    out.append("ET")
    return "\n".join(out)


def _esc(t: str) -> str:
    t = str(t).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return "".join(c if 32 <= ord(c) <= 126 else " " for c in t)


# ── Rapport de scan par support (export automatique) ──────────────────────────

def write_device_scan_report(mountpoint: str, device: str,
                              label: str, uuid: str, result) -> str:
    """
    Écrit un rapport de scan au format texte à la racine du support analysé.

    Nommage : scan_AV_YYYYMMDD_HHMMSS_<label>.txt
    Retourne le chemin complet du fichier créé.
    """
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_lbl = (label or device.replace("/dev/", "")).replace(" ", "_")
    # Caractères interdits dans les noms de fichiers FAT/NTFS
    for ch in r'\/:*?"<>|':
        safe_lbl = safe_lbl.replace(ch, "_")
    fname = f"scan_AV_{ts}_{safe_lbl}.txt"
    dest  = os.path.join(mountpoint, fname)

    sep  = "=" * 60
    dash = "-" * 60
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines: List[str] = [
        sep,
        "  USB Antivirus Scanner – Rapport de scan",
        sep,
        f"  Date      : {now}",
        f"  Support   : {device}",
    ]
    if label:
        lines.append(f"  Étiquette : {label}")
    if uuid:
        lines.append(f"  UUID      : {uuid}")
    lines += [dash, ""]

    # Résumé du scan
    lines.append(result.summary())
    lines.append("")
    lines.append(dash)

    # Détail des menaces
    if result.threats:
        lines.append("")
        lines.append("FICHIERS INFECTÉS :")
        for t in result.threats:
            lines.append(f"  [{t.engine}]  {t.threat}")
            lines.append(f"    → {t.path}")
    else:
        lines.append("")
        lines.append("✓  Aucune menace détectée sur ce support.")

    lines += [
        "",
        sep,
        "  Rapport généré automatiquement par USB Antivirus Scanner",
        sep,
        "",
    ]

    with open(dest, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    log_info(f"Rapport de scan écrit : {dest}")
    return dest