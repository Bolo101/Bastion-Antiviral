#!/usr/bin/env python3
"""log_handler.py – Journalisation avec rotation par volumétrie et export PDF/USB."""

import logging
import os
import shutil
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import List, Optional, Tuple

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


_PAGE_W, _PAGE_H = 612, 792
_MARGIN          = 50
_WRAP            = 100          # caractères par ligne (Courier 8 pt ≈ 106 max)
_LEADING         = 11           # interligne (pt)
_BODY_LINES_P1   = 52           # lignes de corps sur la 1re page (après l'en-tête)
_BODY_LINES_PN   = 62           # lignes de corps sur les pages suivantes


def _wrap_lines(lines: List[str]) -> List[str]:
    """Retour à la ligne (jamais de troncature : la fin d'un chemin compte)."""
    out: List[str] = []
    for ln in lines or ["(vide)"]:
        for part in (str(ln).replace("\t", "    ").splitlines() or [""]):
            width, first = _WRAP, True
            while True:
                chunk, part = part[:width], part[width:]
                out.append(chunk if first else "    " + chunk)
                if not part:
                    break
                first, width = False, _WRAP - 4
    return out


def _pdf_str(t: str) -> bytes:
    """
    Chaîne littérale PDF sûre. Les noms de fichiers viennent du support analysé
    donc sont hostiles : ASCII imprimable échappé, Latin-1 conservé (accents,
    police WinAnsi), tout le reste (contrôles, CJK…) remplacé par '?'. Aucun
    caractère ne peut sortir de la chaîne ni injecter d'opérateur PDF.
    """
    out = bytearray()
    for ch in str(t):
        o = ord(ch)
        if ch in "\\()":
            out += b"\\" + ch.encode()
        elif 32 <= o <= 126:
            out.append(o)
        elif 160 <= o <= 255:
            out += b"\\%03o" % o
        else:
            out.append(63)
    return bytes(out)


def _write_pdf(path: str, title: str, lines: List[str], *info: str,
               mode: int = 0o644) -> None:
    """PDF multi-pages (bibliothèque standard uniquement)."""
    body = _wrap_lines(lines)
    pages: List[List[str]] = [body[:_BODY_LINES_P1]]
    rest = body[_BODY_LINES_P1:]
    while rest:
        pages.append(rest[:_BODY_LINES_PN])
        rest = rest[_BODY_LINES_PN:]
    n = len(pages)

    contents: List[bytes] = []
    for idx, plines in enumerate(pages):
        c = bytearray()
        c += b"BT /F1 8 Tf %d TL " % _LEADING
        if idx == 0:
            c += b"/F1 14 Tf 50 750 Td (" + _pdf_str(title) + b") Tj /F1 9 Tf "
            for il in info:
                c += b"0 -15 Td (" + _pdf_str(il) + b") Tj "
            c += b"/F1 8 Tf 0 -20 Td "
        else:
            c += b"50 750 Td "
        for ln in plines:
            c += b"0 -%d Td (" % _LEADING + _pdf_str(ln) + b") Tj "
        c += b"ET\n"
        c += (b"BT /F1 8 Tf 50 28 Td (" + _pdf_str(f"Page {idx + 1}/{n}")
              + b") Tj ET")
        contents.append(bytes(c))

    objs: List[bytes] = []          # objets 1..N dans l'ordre
    kids = " ".join(f"{4 + 2 * i} 0 R" for i in range(n))
    objs.append(b"<</Type /Catalog /Pages 2 0 R>>")
    objs.append(f"<</Type /Pages /Kids [{kids}] /Count {n}>>".encode())
    objs.append(b"<</Type /Font /Subtype /Type1 /BaseFont /Courier "
                b"/Encoding /WinAnsiEncoding>>")
    for i, cb in enumerate(contents):
        page_no, cont_no = 4 + 2 * i, 5 + 2 * i
        objs.append(
            f"<</Type /Page /Parent 2 0 R /MediaBox [0 0 {_PAGE_W} {_PAGE_H}] "
            f"/Contents {cont_no} 0 R /Resources <</Font <</F1 3 0 R>>>>>>".encode())
        objs.append(f"<</Length {len(cb)}>>\nstream\n".encode() + cb
                    + b"\nendstream")

    out = bytearray(b"%PDF-1.4\n")
    offsets: List[int] = []
    for i, raw in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + raw + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<</Size {len(objs) + 1} /Root 1 0 R>>\n"
            f"startxref\n{xref}\n%%EOF\n").encode()

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(out)


# ── Rapport de scan par support (export automatique) ──────────────────────────

def safe_name_part(text: str, maxlen: int = 32) -> str:
    """Fragment de nom de fichier sûr (le libellé d'un support est contrôlé par
    l'attaquant) : [A-Za-z0-9._-] uniquement, longueur bornée, jamais vide."""
    out = "".join(c if (c.isascii() and (c.isalnum() or c in "._-")) else "_"
                  for c in str(text or ""))
    out = out.strip("._") or "support"
    return out[:maxlen]


def write_device_scan_report_pdf(
        mountpoint: str, device: str, label: str, uuid: str,
        result,
        clamav_info: dict,
        yara_info:   dict,
        avast_info:  dict,
        engines_used: dict,
        *,
        identity:     Optional[dict] = None,
        sandbox_info: str = "",
        filename:     Optional[str] = None,
        max_threats:  int = 500,
) -> str:
    """
    Génère un PDF de rapport de scan dans le répertoire `mountpoint` — ici un
    répertoire LOCAL de la borne : jamais le support analysé, qui reste en
    lecture seule.

    Nommage  : `filename` s'il est fourni, sinon scan_AV_<date>_<label>.pdf
    Contenu  : support (identité), bases utilisées, résumé, détail des menaces.
    Retourne : chemin complet du fichier créé (droits 600).
    """
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = filename or f"scan_AV_{ts}_{safe_name_part(label or device.replace('/dev/', ''))}.pdf"
    fname = os.path.basename(fname)
    dest  = os.path.join(mountpoint, fname)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Construction des lignes du rapport ────────────────────────────────────
    lines: List[str] = []

    # En-tête support
    lines.append(f"Support   : {device}")
    if label:
        lines.append(f"Etiquette : {label}")
    if uuid:
        lines.append(f"UUID      : {uuid}")
    if identity:
        ident = " ".join(x for x in (identity.get("vendor", ""),
                                     identity.get("model", "")) if x)
        if ident:
            lines.append(f"Materiel  : {ident}")
        if identity.get("serial"):
            lines.append(f"Serie USB : {identity['serial']}")
        if identity.get("size_bytes") not in (None, "", "0", 0):
            lines.append(f"Taille    : {identity['size_bytes']} octets")
        if identity.get("fstype"):
            lines.append(f"Systeme   : {identity['fstype']}")
    lines.append(f"Date      : {now}")
    lines.append("Montage   : lecture seule (aucune ecriture sur le support)")
    if sandbox_info:
        lines.append(f"Isolation : {sandbox_info}")
    lines.append("")

    # Moteurs utilisés
    engines_list = []
    if engines_used.get("clamav"):
        engines_list.append("ClamAV")
    if engines_used.get("avast"):
        engines_list.append("Avast")
    if engines_used.get("yara"):
        engines_list.append("YARA")
    lines.append(f"Moteurs   : {' + '.join(engines_list) or 'aucun'}")
    lines.append("")

    # Bases ClamAV
    lines.append("--- BASE CLAMAV ---")
    clamav_status = clamav_info.get("status", "MISSING")
    clamav_lu     = clamav_info.get("last_update", "inconnue")
    lines.append(f"Statut    : {clamav_status}  (MAJ : {clamav_lu})")
    official = {k: v for k, v in clamav_info.get("files", {}).items()
                if k in ("main.cvd","main.cld","daily.cvd","daily.cld",
                         "bytecode.cvd","bytecode.cld")}
    tp_count = len(clamav_info.get("files", {})) - len(official)
    for fname_db, info_db in official.items():
        lines.append(f"  {fname_db:<18} {info_db}")
    if tp_count > 0:
        lines.append(f"  Signatures tierces : {tp_count} fichier(s)")
    lines.append("")

    # Base YARA
    if engines_used.get("yara"):
        lines.append("--- BASE YARA ---")
        yara_count = yara_info.get("count", 0)
        yara_lu    = yara_info.get("last_update", "inconnue")
        lines.append(f"Regles    : {yara_count}  (MAJ : {yara_lu})")
        lines.append("")

    # Avast
    if engines_used.get("avast"):
        lines.append("--- AVAST BUSINESS ---")
        if avast_info.get("licensed"):
            lines.append("Statut    : installe et licence active")
        elif avast_info.get("installed"):
            lines.append("Statut    : installe - LICENCE REQUISE")
        else:
            lines.append("Statut    : non installe")
        lines.append("")

    # Résultats
    lines.append("--- RESULTATS DU SCAN ---")
    lines.append(f"Fichiers analyses  : {result.scanned}")
    lines.append(f"Menaces detectees  : {result.infected}")
    lines.append(f"Duree              : {result.duration:.1f}s")
    if result.scanned_clamav:
        lines.append(f"  ClamAV : {result.scanned_clamav} fichier(s)")
    if result.scanned_avast:
        lines.append(f"  Avast  : {result.scanned_avast} fichier(s)")
    if result.scanned_yara:
        lines.append(f"  YARA   : {result.scanned_yara} fichier(s)")
    if result.stopped:
        lines.append("  (scan interrompu par l'utilisateur)")
    lines.append("")

    if result.threats:
        lines.append("--- FICHIERS INFECTES (conserves sur le support) ---")
        for t in result.threats[:max_threats]:
            lines.append(f"[{t.engine}] {t.threat}")
            lines.append(f"  Chemin : {t.path}")
            sha = getattr(t, "hash", None) or "N/A"
            lines.append(f"  SHA256 : {sha}")
        if len(result.threats) > max_threats:
            lines.append(f"... et {len(result.threats) - max_threats} autre(s) "
                         "menace(s) non detaillee(s) (rapport tronque).")
    else:
        lines.append("Aucune menace detectee sur ce support.")

    lines += ["", "Rapport genere par USB Antivirus Scanner"]

    _write_pdf(dest, "Rapport de scan - USB Antivirus Scanner",
               lines,
               f"Support : {label or device}",
               f"Date    : {now}",
               f"Resultat: {'MENACES DETECTEES' if result.infected else 'SAIN'}",
               mode=0o600)

    log_info(f"Rapport PDF ecrit : {dest}")
    return dest