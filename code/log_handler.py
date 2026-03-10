#!/usr/bin/env python3
"""log_handler.py – Journalisation et export PDF."""

import logging
import os
import sys
from datetime import datetime
from typing import List

from config import LOG_FILE

# ── Configuration du logger ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("virusscanner")
logger.setLevel(logging.INFO)

try:
    _fh = logging.FileHandler(LOG_FILE)
    _fh.setLevel(logging.INFO)
    _fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(_fh)
except PermissionError:
    print("Erreur : permissions insuffisantes. Lancez avec sudo.", file=sys.stderr)
    sys.exit(1)


def log_info(msg: str)    -> None: logger.info(msg)
def log_error(msg: str)   -> None: logger.error(msg)
def log_warning(msg: str) -> None: logger.warning(msg)


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