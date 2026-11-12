#!/usr/bin/env python3
"""
scanner.py – Moteur de scan combiné ClamAV + Avast + YARA, chaque moteur étant
exécuté dans un sandbox éphémère (voir sandbox.py).

Moteurs :
  • ClamAV  – clamscan, dans le sandbox
  • Avast   – CLI `scan` / `avast scan` (licence requise), dans le sandbox
              (AVAST_SANDBOX_MODE = "strict") ou via le démon (mode "daemon",
              analyse faite hors sandbox : le support n'est alors PAS validé)
  • YARA    – yara_worker.py dans le sandbox : le GUI ne charge ni ne compile
              jamais de règles et n'ouvre aucun fichier du support

Le scan est séquentiel : ClamAV → Avast → YARA. Les résultats sont agrégés dans
un ScanResult unique.

Politique sandbox (config.py) :
  • sandbox actif                     → les moteurs y sont lancés
  • sandbox absent + SANDBOX_REQUIRED → échec fermé : AUCUNE analyse
  • sandbox absent + non requis       → analyse dégradée, support non validé

Tout ce que renvoient les moteurs (lignes de sortie, JSON du worker) est traité
comme NON FIABLE : texte nettoyé, taille limitée, et empreinte SHA-256 calculée
uniquement pour un fichier ordinaire situé DANS les cibles analysées.

ScanResult.engines_ran ne contient un moteur que si son analyse s'est terminée
normalement ; ScanResult.sandboxed n'est vrai que si TOUS les moteurs lancés
l'ont été dans le sandbox. Ce sont les deux conditions de validation d'un support.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from config import (
    CLAMAV_DB_DIR,
    YARA_RULES_DIR,
    AVAST_LICENSE_DIR,
    AVAST_LICENSE_PATH,
    AVAST_BIN_PATHS,
    AVAST_SCAN_BIN_PATHS,
    AVAST_SANDBOX_MODE,
    AVAST_DAEMON_SOCKET_DIRS,
)
from log_handler import log_error, log_info, log_warning
from sandbox import Sandbox, SandboxUnavailable, sandbox_active, sandbox_policy_ok

ProgressCB = Optional[Callable[[str, str], None]]   # (message, tag)

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORKER_HOST = os.path.join(_HERE, "yara_worker.py")
_WORKER_IN_SANDBOX = "/opt/bastion/yara_worker.py"

_MAX_LINE = 65536          # longueur max d'une ligne acceptée d'un moteur
_MAX_THREATS = 20000       # menaces conservées en mémoire (le compteur continue)
_MAX_MSG = 300             # longueur max d'un texte provenant d'un moteur
_SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/",
                    "/libx32/")
# ClamAV ≥ 1.2 vérifie la signature des bases avec le certificat racine de ce
# dossier ; sans lui, clamscan échoue dans le sandbox (qui ne monte que /usr et
# quelques fichiers de /etc). Seul ce dossier (certificat PUBLIC) est monté.
_CLAMAV_CERTS_DIR = "/etc/clamav/certs"


def _fmt_size(n: int) -> str:
    """Taille lisible : o, Ko ou Mo."""
    if n < 1024:
        return f"{n} o"
    if n < 1048576:
        return f"{n / 1024:.0f} Ko"
    return f"{n / 1048576:.1f} Mo"


def _clean(text, maxlen: int = _MAX_MSG) -> str:
    """Texte provenant d'un moteur : sans caractères de contrôle, longueur bornée."""
    if not isinstance(text, str):
        return ""
    out = []
    for c in text:
        if c == " " or c.isprintable():
            out.append(c)
        elif 0xDC80 <= ord(c) <= 0xDCFF:        # octet non UTF-8 d'un nom de fichier
            out.append("\ufffd")
    return "".join(out).strip()[:maxlen]


# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class ThreatInfo:
    path:   str
    threat: str
    engine: str   # "ClamAV" | "Avast" | "YARA"
    hash:   str   = ""   # SHA-256 calculé au moment de la détection


@dataclass
class ScanResult:
    scanned:  int               = 0
    infected: int               = 0
    threats:  List[ThreatInfo]  = field(default_factory=list)
    errors:   List[str]         = field(default_factory=list)
    duration: float             = 0.0
    stopped:  bool              = False

    # Compteurs par moteur (pour affichage détaillé)
    scanned_clamav:  int = 0
    scanned_avast:   int = 0
    scanned_yara:    int = 0

    # Conditions de validation d'un support (voir gui._eligible_for_validation)
    engines_ran: List[str] = field(default_factory=list)   # analyses terminées normalement
    sandboxed:   bool      = False                         # tout s'est exécuté dans le sandbox

    # Moteurs demandés pour ce scan (pour afficher ceux qui n'ont PAS tourné)
    engines_requested: List[str] = field(default_factory=list)

    # Preuves d'exploitation de YARA (renseignées par le worker, non fiables → bornées)
    yara_rule_files: int   = 0      # fichiers de règles compilés
    yara_rules:      int   = 0      # règles individuelles chargées
    yara_selftest:   Optional[bool] = None   # règle témoin détectée ? (None = non exécuté)
    yara_bytes:      int   = 0      # octets réellement passés à YARA
    yara_seconds:    float = 0.0    # durée de l'analyse (hors compilation)

    def mark_ran(self, engine: str) -> None:
        if engine not in self.engines_ran:
            self.engines_ran.append(engine)

    def engines_line(self) -> str:
        """Une ligne : état de chaque moteur demandé (✔ terminé / ✘ non terminé)."""
        counts = {"ClamAV": self.scanned_clamav, "Avast": self.scanned_avast,
                  "YARA": self.scanned_yara}
        parts = []
        for name in self.engines_requested:
            if name in self.engines_ran:
                extra = f"{counts.get(name, 0)} fichier(s)"
                if name == "YARA" and self.yara_rules:
                    extra += f", {self.yara_rules} règle(s)"
                parts.append(f"✔ {name} ({extra})")
            else:
                parts.append(f"✘ {name} NON TERMINÉ")
        return ("Moteurs : " + "  ·  ".join(parts)) if parts else ""

    def summary(self) -> str:
        lines = [
            f"Fichiers analysés : {self.scanned}",
            f"Menaces détectées : {self.infected}",
            f"Durée : {self.duration:.1f}s",
        ]
        if self.scanned_clamav or self.scanned_avast or self.scanned_yara:
            detail_parts = []
            if self.scanned_clamav:
                detail_parts.append(f"ClamAV:{self.scanned_clamav}")
            if self.scanned_avast:
                detail_parts.append(f"Avast:{self.scanned_avast}")
            if self.scanned_yara:
                detail_parts.append(f"YARA:{self.scanned_yara}")
            lines.append(f"  ({' | '.join(detail_parts)})")
        if self.yara_rules:
            lines.append(f"YARA : {self.yara_rules} règle(s) de {self.yara_rule_files} "
                         f"fichier(s), {_fmt_size(self.yara_bytes)} analysés"
                         + ("" if self.yara_selftest is None else
                            "  [auto-test OK]" if self.yara_selftest else "  [AUTO-TEST ÉCHOUÉ]"))
        if self.threats:
            lines.append("\nDétail des menaces :")
            for t in self.threats[:20]:
                lines.append(f"  [{t.engine}] {t.threat}  →  {t.path}")
            if len(self.threats) > 20:
                lines.append(f"  … et {len(self.threats) - 20} autre(s)")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
class ScanEngine:

    def __init__(self) -> None:
        self._stop   = False
        self._proc   = None          # subprocess en cours (ClamAV, Avast ou worker YARA)
        self._unsandboxed = False    # un moteur a tourné hors sandbox pendant ce scan

    # ── Contrôle ──────────────────────────────────────────────────────────────

    def request_stop(self) -> None:
        self._stop = True
        self._kill_proc()

    def _kill_proc(self) -> None:
        """terminate(), puis kill() si le processus ne s'arrête pas sous 5 s."""
        proc = self._proc
        if not proc:
            return
        try:
            proc.terminate()
        except Exception:                                         # noqa: BLE001
            pass

        def _reaper() -> None:
            try:
                proc.wait(timeout=5)
            except Exception:                                     # noqa: BLE001
                try:
                    proc.kill()
                except Exception:                                 # noqa: BLE001
                    pass
        threading.Thread(target=_reaper, daemon=True).start()

    def _reset(self) -> None:
        self._stop = False
        self._proc = None
        self._unsandboxed = False

    # ── Hash SHA-256 ───────────────────────────────────────────────────────────

    @staticmethod
    def _compute_hash(path: str) -> str:
        """Calcule le SHA-256 d'un fichier. Retourne '' en cas d'erreur."""
        import hashlib
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:                                         # noqa: BLE001
            return ""

    @staticmethod
    def _hash_if_in_targets(path: str, targets: List[str]) -> str:
        """SHA-256 d'un fichier signalé par un moteur NON FIABLE : uniquement si
        c'est un fichier ordinaire (pas un lien) situé dans une cible analysée."""
        try:
            if not isinstance(path, str) or "\0" in path or not os.path.isabs(path):
                return ""
            p = os.path.abspath(path)
            roots = {os.path.abspath(t) for t in targets}
            roots |= {os.path.realpath(t) for t in targets}
            if not any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots):
                return ""
            if os.path.islink(p) or not os.path.isfile(p):
                return ""
            return ScanEngine._compute_hash(p)
        except Exception:                                         # noqa: BLE001
            return ""

    def _add_threat(self, result: ScanResult, targets: List[str],
                    path: str, threat: str, engine: str) -> None:
        result.infected += 1
        if len(result.threats) < _MAX_THREATS:
            result.threats.append(ThreatInfo(
                path=_clean(path, 1024), threat=_clean(threat),
                engine=engine, hash=self._hash_if_in_targets(path, targets)))

    # ── Détection : ClamAV ────────────────────────────────────────────────────

    @staticmethod
    def is_clamav_installed() -> bool:
        return shutil.which("clamscan") is not None

    @staticmethod
    def is_freshclam_available() -> bool:
        return shutil.which("freshclam") is not None

    # ── Détection : Avast ─────────────────────────────────────────────────────

    @staticmethod
    def is_avast_installed() -> bool:
        """True si le binaire avast ou scan est trouvé sur le système."""
        if shutil.which("avast") or shutil.which("scan"):
            return True
        for p in AVAST_BIN_PATHS + AVAST_SCAN_BIN_PATHS:
            if os.path.exists(p):
                return True
        return False

    @staticmethod
    def is_avast_licensed() -> bool:
        """True si le fichier de licence existe et n'est pas vide."""
        try:
            return (os.path.exists(AVAST_LICENSE_PATH)
                    and os.path.getsize(AVAST_LICENSE_PATH) > 0)
        except OSError:
            return False

    @staticmethod
    def get_avast_scan_binary() -> Optional[str]:
        """
        Retourne le binaire de scan Avast.
        Priorité : 'scan' (CLI scan dédié) → 'avast' (daemon avec sous-cmd).
        """
        found = shutil.which("scan")
        if found:
            return found
        for p in AVAST_SCAN_BIN_PATHS:
            if os.path.exists(p):
                return p
        found = shutil.which("avast")
        if found:
            return found
        for p in AVAST_BIN_PATHS:
            if os.path.exists(p):
                return p
        return None

    def avast_status_summary(self) -> str:
        """Résumé court de l'état d'Avast Business pour la barre de statut."""
        if not self.is_avast_installed():
            return "❌  Avast Business : non installé"
        if not self.is_avast_licensed():
            return "⚠   Avast Business : installé — licence requise pour scanner"
        try:
            mtime = os.path.getmtime(AVAST_LICENSE_PATH)
            date  = time.strftime("%Y-%m-%d", time.localtime(mtime))
            return f"✅  Avast Business : prêt  (licence : {date})"
        except OSError:
            return "✅  Avast Business : prêt"

    # ── Détection : YARA ──────────────────────────────────────────────────────

    def detect_yara(self) -> Tuple[bool, str]:
        """(dispo, méthode). Test SANS importer yara : le GUI ne charge pas YARA,
        l'analyse est faite par yara_worker.py dans le sandbox."""
        try:
            found = importlib.util.find_spec("yara") is not None
        except (ImportError, ValueError):
            found = False
        return (True, "python") if found else (False, "")

    def yara_rules_count(self) -> int:
        return len(self._collect_rules())

    def _collect_rules(self) -> List[str]:
        rules: List[str] = []
        for root, dirs, files in os.walk(YARA_RULES_DIR):
            # dossiers cachés ignorés (ex. reliquat d'une mise à jour interrompue)
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            for f in sorted(files):
                if f.endswith((".yar", ".yara")) and not f.startswith("."):
                    rules.append(os.path.join(root, f))
        return rules

    @staticmethod
    def _clamav_ro_binds() -> List[str]:
        """Chemins hôte montés en lecture seule dans le sandbox de ClamAV."""
        binds = [CLAMAV_DB_DIR]
        if os.path.isdir(_CLAMAV_CERTS_DIR):
            binds.append(_CLAMAV_CERTS_DIR)
        return binds

    # ── Lancement d'un moteur ─────────────────────────────────────────────────

    def _launch(self, label: str, cmd: List[str], *, targets: List[str],
                sandboxed: bool, ro_binds=(), exec_paths=(), extra_ro=None,
                **popen_kw):
        """Popen d'un moteur : dans le sandbox si `sandboxed`, sinon (mode dégradé
        autorisé par la configuration) en direct. Pas de repli silencieux : si le
        sandbox échoue, SandboxUnavailable remonte et le moteur n'est pas lancé."""
        if sandboxed:
            return Sandbox(label).popen(
                cmd, ro_binds=ro_binds, targets=targets, extra_ro=extra_ro,
                exec_paths=exec_paths, **popen_kw)
        self._unsandboxed = True
        return subprocess.Popen(cmd, **popen_kw)

    # ══════════════════════════════════════════════════════════════════════════
    # Scan principal
    # ══════════════════════════════════════════════════════════════════════════

    def scan(self,
             targets:          List[str],
             use_clamav:       bool,
             use_avast:        bool,
             use_yara:         bool,
             progress_cb:      ProgressCB = None,
             file_count_cb:    Optional[Callable[[int, int], None]] = None,
             *,
             remove_infected:  bool = False) -> ScanResult:
        """
        Lance le scan complet et retourne le résultat agrégé.
        Ordre : ClamAV → Avast → YARA.

        file_count_cb(scanned, infected) est appelé après chaque fichier traité
        pour permettre une mise à jour temps réel du compteur dans l'UI.

        remove_infected est conservé pour compatibilité mais IGNORÉ : les supports
        sont toujours analysés en lecture seule, rien n'y est jamais écrit.
        """
        self._reset()
        result = ScanResult()
        start  = time.time()
        cb     = progress_cb
        result.engines_requested = [n for n, wanted in (
            ("ClamAV", use_clamav), ("Avast", use_avast), ("YARA", use_yara)) if wanted]

        if remove_infected:
            log_warning("scan(remove_infected=True) ignoré : supports en lecture seule.")

        # ── Politique sandbox : échec fermé si requis et indisponible ─────────
        if not sandbox_policy_ok():
            reason = Sandbox.unavailable_reason() or "désactivé par la configuration"
            msg = (f"❌ Sandbox indisponible ({reason}) — analyse refusée "
                   "(les moteurs ne tournent jamais hors sandbox si il est requis).")
            result.errors.append(msg)
            if cb:
                cb(msg, "threat")
            log_error(msg)
            result.duration = time.time() - start
            return result

        use_sb = sandbox_active()
        if cb:
            if use_sb:
                cb(f"Sandbox actif : {Sandbox.describe()}", "info")
            else:
                cb("⚠ Sandbox non actif : analyse SANS isolation "
                   "(support non validable).", "warning")

        if use_clamav:
            self._scan_clamav(targets, result, cb, file_count_cb, use_sb)

        if use_avast and not result.stopped:
            self._scan_avast(targets, result, cb, file_count_cb, use_sb)

        if use_yara and not result.stopped:
            self._scan_yara(targets, result, cb, file_count_cb, use_sb)

        result.sandboxed = bool(use_sb and not self._unsandboxed)
        result.duration = time.time() - start

        # Synthèse : quels moteurs ont réellement terminé leur analyse ?
        line = result.engines_line()
        if cb and line and not result.stopped:
            all_ran = all(n in result.engines_ran for n in result.engines_requested)
            cb(line, "ok" if all_ran else "warning")
        log_info(
            f"Scan terminé : {result.scanned} fichiers, "
            f"{result.infected} menace(s), {result.duration:.1f}s  "
            f"[ClamAV:{result.scanned_clamav} | "
            f"Avast:{result.scanned_avast} | "
            f"YARA:{result.scanned_yara}]  "
            f"sandbox={'oui' if result.sandboxed else 'NON'} "
            f"moteurs={','.join(result.engines_ran) or '—'}"
        )
        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Moteur ClamAV
    # ══════════════════════════════════════════════════════════════════════════

    def _check_clamav_db(self, cb: ProgressCB, use_sb: bool) -> Tuple[bool, str]:
        """
        Vérifie que la base ClamAV se charge correctement en scannant un petit
        fichier ordinaire (jamais /dev/null : clamscan le rejette toujours avec le
        code 2, ce qui donnerait un faux « base invalide »).

        Retourne (ok, message_d_erreur).
        Code 0/1 = OK ; code 2 + messages d'erreur de base = base invalide.
        """
        tmp_path: Optional[str] = None
        try:
            if use_sb:
                # Dans le sandbox, /tmp est un tmpfs vide : on scanne un fichier
                # système lisible qui y est monté (voir Sandbox._ETC_FILES).
                r = Sandbox("clamav-db").run(
                    ["clamscan", "--no-summary", f"--database={CLAMAV_DB_DIR}",
                     "/etc/group"],
                    ro_binds=self._clamav_ro_binds(), timeout=120)
            else:
                fd, tmp_path = tempfile.mkstemp(prefix="clamav_check_", suffix=".tmp")
                os.close(fd)
                r = subprocess.run(
                    ["clamscan", "--no-summary", f"--database={CLAMAV_DB_DIR}", tmp_path],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=120)
        except SandboxUnavailable as e:
            return False, f"ClamAV : sandbox indisponible — {_clean(str(e))}"
        except Exception as e:                                    # noqa: BLE001
            log_warning(f"ClamAV pré-validation impossible : {e}")
            return True, ""
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        if r.returncode in (0, 1):
            return True, ""

        # Tué par le système (SIGKILL = 137) pendant le chargement : presque toujours
        # le manque de mémoire. Inutile de réessayer dans le scan (même chargement,
        # même mort, et ~1 à 2 min perdues) : on s'arrête avec la vraie cause.
        if r.returncode in (137, -9):
            msg = (f"❌ ClamAV : chargement de la base tué par le système "
                   f"(code {r.returncode}) — mémoire insuffisante ?\n"
                   "   clamscan charge toute la base en RAM : libérez de la mémoire, "
                   "réduisez les signatures tierces ou ajoutez de la RAM.")
            if cb:
                cb(msg, "threat")
            log_error(msg)
            return False, (f"ClamAV : base trop lourde pour la mémoire disponible "
                           f"(code {r.returncode}) — scan annulé.")

        combined = (r.stdout + r.stderr).strip()
        bad_lines = [l for l in combined.splitlines()
                     if any(k in l for k in
                            ("Error loading", "Can't load", "Invalid",
                             "Corrupt", "corrupt", "Can't open"))]

        if not bad_lines:
            log_warning(f"ClamAV pré-validation : code 2 sans erreur DB "
                        f"({_clean(combined, 120)}). Scan autorisé.")
            return True, ""

        detail = "\n   ".join(_clean(l) for l in bad_lines[:5])
        msg = ("❌ ClamAV : échec de chargement de la base (code 2).\n"
               "   Cause : une signature tierce est probablement corrompue.\n"
               f"   {detail}\n"
               "   → Relancez une mise à jour depuis le panneau Admin.")
        if cb:
            cb(msg, "threat")
        log_error(msg)
        return False, ("ClamAV : base invalide (code 2) — scan annulé. "
                       "Lancez une mise à jour depuis le panneau Admin.")

    @staticmethod
    def _count_files(targets: List[str]) -> int:
        """Compte les fichiers réguliers dans les cibles (filet de sécurité)."""
        total = 0
        for t in targets:
            if os.path.isfile(t):
                total += 1
            elif os.path.isdir(t):
                for _, _, files in os.walk(t):
                    total += len(files)
        return total

    def _scan_clamav(self, targets: List[str], result: ScanResult,
                     cb: ProgressCB, fcc: Optional[Callable[[int, int], None]],
                     use_sb: bool) -> None:

        if not self.is_clamav_installed():
            msg = "⚠ ClamAV : non installé — moteur ignoré."
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return

        # ── 1. Pré-validation : base chargeable ? ─────────────────────────────
        ok, err = self._check_clamav_db(cb, use_sb)
        if not ok:
            result.errors.append(err)
            return

        # ── 2. Scan ───────────────────────────────────────────────────────────
        # --max-filesize=0 / --max-scansize=0 / --max-files=0 : lèvent les limites
        #   silencieuses (25 Mo/fichier, 100 Mo/total, 10 000 fichiers), sinon les
        #   gros échantillons sont ignorés sans avertissement (faux « sain »).
        # --scan-archive=yes : analyse des archives (hors ZIP chiffrés).
        # --alert-broken : PE/archives corrompus ou tronqués signalés.
        # --detect-pua=yes : logiciels potentiellement indésirables.
        # Pas de --remove : le support est en lecture seule.
        cmd = [
            "clamscan",
            "--recursive",
            "--stdout",
            "--verbose",                     # « /path: OK » par fichier sain → comptage temps réel
            f"--database={CLAMAV_DB_DIR}",   # TOUTES les signatures du répertoire (tierces incluses)
            "--max-filesize=0",
            "--max-scansize=0",
            "--max-files=0",
            "--scan-archive=yes",
            "--alert-broken",
            "--detect-pua=yes",
        ]
        cmd.extend(targets)

        if cb:
            cb("ClamAV : démarrage de l'analyse…", "info")

        rc = -99
        try:
            self._proc = self._launch(
                "clamav", cmd, targets=targets, sandboxed=use_sb,
                ro_binds=self._clamav_ro_binds(),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors="surrogateescape", bufsize=1)
            assert self._proc.stdout
            for line in self._proc.stdout:
                if self._stop:
                    result.stopped = True
                    break
                if len(line) > _MAX_LINE:
                    continue
                self._parse_clamav(line.rstrip(), targets, result, cb, fcc)
            self._proc.wait()
            rc = self._proc.returncode
            if self._stop:                  # arrêt demandé : le processus a été tué
                result.stopped = True
        except SandboxUnavailable as e:
            result.errors.append(f"ClamAV : sandbox indisponible — {_clean(str(e))}")
            log_error(f"ClamAV sandbox : {e}")
        except Exception as e:                                    # noqa: BLE001
            result.errors.append(f"ClamAV : {_clean(str(e))}")
            log_error(f"ClamAV scan : {e}")
        finally:
            self._proc = None

        # ── 3. Analyse du code de retour ──────────────────────────────────────
        # 0 = propre, 1 = menace(s) détectée(s), 2 = erreur DB / I/O
        if rc == 2:
            msg = ("⚠ ClamAV : erreur pendant le scan (code 2). "
                   "Mettez à jour la base depuis le panneau Admin.")
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            log_error(msg)
        elif rc not in (0, 1, -99) and not result.stopped:
            hint = (" (mémoire insuffisante ?)" if rc in (137, -9) else "")
            msg = f"⚠ ClamAV : arrêt anormal (code {rc}){hint} — analyse incomplète."
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            log_warning(f"ClamAV : code de retour inattendu {rc}")

        # ── 4. Filet de sécurité : compteur nul alors que le scan a tourné ────
        if result.scanned_clamav == 0 and not result.stopped and rc in (0, 1):
            estimated = self._count_files(targets)
            if estimated > 0:
                result.scanned_clamav = estimated
                result.scanned = max(result.scanned, estimated)
                if cb:
                    cb(f"[ClamAV] {estimated} fichier(s) parcourus (comptage direct).",
                       "info")

        # ── 5. Analyse terminée normalement ? ─────────────────────────────────
        if rc in (0, 1) and not result.stopped:
            result.mark_ran("ClamAV")

    def _parse_clamav(self, line: str, targets: List[str], result: ScanResult,
                      cb: ProgressCB,
                      fcc: Optional[Callable[[int, int], None]] = None) -> None:
        if not line:
            return

        line = line.strip()  # robustesse : CR résiduels, espaces

        # ── Menace détectée ───────────────────────────────────────────────────
        if " FOUND" in line:
            parts  = line.rsplit(":", 1)
            path   = parts[0].strip()
            threat = parts[1].replace(" FOUND", "").strip() if len(parts) == 2 else line
            result.scanned_clamav += 1
            result.scanned        += 1
            self._add_threat(result, targets, path, threat, "ClamAV")
            if cb:
                cb(f"🚨 ClamAV : {_clean(threat)}  →  {_clean(path, 300)}", "threat")
            if fcc:
                fcc(result.scanned, result.infected)
            return

        # ── Résumé final : "Scanned files: N" ────────────────────────────────
        if line.startswith("Scanned files:"):
            try:
                n = int(line.split(":")[1].strip())
                if n > 0:
                    result.scanned_clamav = max(result.scanned_clamav, n)
                    result.scanned        = max(result.scanned, n)
                    if fcc:
                        fcc(result.scanned, result.infected)
            except (ValueError, IndexError):
                pass
            return

        # ── Fichier sain (activé par --verbose) ───────────────────────────────
        if line.endswith(": OK") or line.endswith(": Empty file"):
            result.scanned_clamav += 1
            result.scanned        += 1
            if fcc and result.scanned_clamav % 20 == 0:
                fcc(result.scanned, result.infected)
            return

        # ── Erreurs de chargement DB (à logger sans bloquer) ─────────────────
        if "LibClamAV Error" in line or "LibClamAV Warning" in line:
            if cb:
                cb(f"[ClamAV] {_clean(line)}", "warning")
            log_warning(f"ClamAV DB : {_clean(line)}")
            return

        # ── Lignes d'info du résumé ───────────────────────────────────────────
        if any(k in line for k in ("Engine version:", "Known viruses:",
                                    "Scan time:", "Scanned directories:",
                                    "Data scanned:", "Start Date:")):
            if cb:
                cb(f"[ClamAV] {_clean(line)}", "info")

    # ══════════════════════════════════════════════════════════════════════════
    # Moteur Avast
    # ══════════════════════════════════════════════════════════════════════════

    def _avast_sandbox_args(self, avast_bin: str) -> Tuple[List[str], List[str]]:
        """(ro_binds, exec_paths) pour lancer Avast dans le sandbox : répertoire
        d'installation s'il est hors des répertoires système (exécution permise
        par Landlock), licence, base VPS et, en mode « daemon », sockets du démon."""
        ro: List[str] = []
        exec_paths: List[str] = []
        real_bin = os.path.realpath(avast_bin)
        if not real_bin.startswith(_SYSTEM_PREFIXES):
            root = "/opt/avast" if real_bin.startswith("/opt/avast/") \
                else os.path.dirname(real_bin)
            ro.append(root)
            exec_paths.append(root)
        for p in (AVAST_LICENSE_DIR, "/var/lib/avast", "/opt/avast"):
            if os.path.isdir(p) and p not in ro:
                ro.append(p)
        if AVAST_SANDBOX_MODE == "daemon":
            ro.extend(d for d in AVAST_DAEMON_SOCKET_DIRS if os.path.isdir(d))
        return ro, exec_paths

    def _scan_avast(self, targets: List[str], result: ScanResult,
                    cb: ProgressCB, fcc: Optional[Callable[[int, int], None]],
                    use_sb: bool) -> None:
        """
        Lance le scan Avast Business via la commande `scan` (CLI Avast Linux).

        Une licence Business active est requise : sans licence le binaire démarre
        mais refuse le scan (code 126 ou message d'erreur). On tente dans tous les
        cas et on remonte l'erreur précisément.

        Format de sortie Avast :
          Fichier sain    :  /chemin/fichier [+]
          Fichier infecté :  /chemin/fichier\\tNom-Menace [L]\\t0

        Mode « strict » (défaut) : tout le scan tourne dans le sandbox.
        Mode « daemon »          : le démon Avast fait l'analyse, hors sandbox →
                                   le support ne peut pas être validé.
        """
        if not self.is_avast_installed():
            msg = "⚠ Avast : non installé — moteur ignoré."
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return

        avast_bin = self.get_avast_scan_binary()
        if not avast_bin:
            msg = "⚠ Avast : binaire de scan introuvable."
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return

        if not self.is_avast_licensed() and cb:
            cb("⚠ Avast : licence Business manquante — le scan risque d'être refusé."
               "  Activez une licence depuis le panneau Administration.", "warning")

        # `scan` est le CLI dédié ; sinon `avast scan -r` (interface daemon)
        if os.path.basename(avast_bin) == "scan":
            cmd = [avast_bin, "-p"]           # -p : afficher chemin + statut
        else:
            cmd = [avast_bin, "scan", "-r"]
        cmd.extend(targets)

        ro_binds, exec_paths = self._avast_sandbox_args(avast_bin)
        daemon_mode = (AVAST_SANDBOX_MODE == "daemon")
        if daemon_mode:
            # L'analyse est faite par le démon, hors sandbox : support non validable.
            self._unsandboxed = True
            if cb:
                cb("⚠ Avast en mode « daemon » : analyse faite par le démon, "
                   "hors sandbox (support non validable).", "warning")

        if cb:
            cb("Avast : démarrage de l'analyse…", "info")

        rc = -99
        tail: deque = deque(maxlen=4)       # dernières lignes (diagnostic)
        n_before = len([t for t in result.threats if t.engine == "Avast"])
        try:
            self._proc = self._launch(
                "avast", cmd, targets=targets, sandboxed=use_sb,
                ro_binds=ro_binds, exec_paths=exec_paths,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors="surrogateescape", bufsize=1)
            assert self._proc.stdout
            for line in self._proc.stdout:
                if self._stop:
                    result.stopped = True
                    break
                if len(line) > _MAX_LINE:
                    continue
                clean = _clean(line.rstrip(), 200)
                if clean:
                    tail.append(clean)
                self._parse_avast(line.rstrip(), targets, result, cb, fcc)
            self._proc.wait()
            rc = self._proc.returncode
            if self._stop:
                result.stopped = True
        except SandboxUnavailable as e:
            result.errors.append(f"Avast : sandbox indisponible — {_clean(str(e))}")
            log_error(f"Avast sandbox : {e}")
            return
        except Exception as e:                                    # noqa: BLE001
            result.errors.append(f"Avast : {_clean(str(e))}")
            log_error(f"Avast scan : {e}")
            return
        finally:
            self._proc = None

        # Code 126 = scan refusé par Avast Business (licence manquante)
        if rc == 126:
            msg = ("⚠ Avast Business : scan refusé (code 126) — licence requise.\n"
                   "  Obtenez une licence sur https://www.avast.com/business/linux\n"
                   "  et activez-la depuis le panneau Administration.")
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return

        if result.stopped:
            return

        found = len([t for t in result.threats if t.engine == "Avast"]) - n_before
        expected = self._count_files(targets)
        if rc != 0 and found == 0:
            # Conservateur : un code de retour non nul sans menace n'est pas une
            # analyse saine (en mode strict, c'est ici que l'erreur sandbox s'affiche).
            detail = (" | ".join(tail))[:300]
            msg = (f"⚠ Avast : arrêt anormal (code {rc}) — analyse incomplète."
                   + (f"\n  {detail}" if detail else ""))
            if use_sb and AVAST_SANDBOX_MODE == "strict":
                msg += ("\n  (mode sandbox « strict » : si Avast ne fonctionne pas "
                        "ainsi, voir AVAST_SANDBOX_MODE dans config.py)")
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return
        if expected > 0 and result.scanned_avast == 0:
            msg = "⚠ Avast : aucun fichier analysé — sortie non reconnue."
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return

        if cb:
            cb(f"Avast : analyse terminée ({result.scanned_avast} fichier(s)).", "info")
        result.mark_ran("Avast")

    def _parse_avast(self, line: str, targets: List[str], result: ScanResult,
                     cb: ProgressCB,
                     fcc: Optional[Callable[[int, int], None]] = None) -> None:
        """
        Parse une ligne de sortie du CLI Avast for Linux.

          Sain     : "/chemin/fichier [+]"
          Infecté  : "/chemin/fichier\\tNom-Menace [L]\\t0"
                   ou "/chemin/fichier: Nom-Menace"
        """
        if not line:
            return

        # Format tab-séparé (commande scan)
        if "\t" in line:
            parts = line.split("\t")
            path  = parts[0].strip()
            if len(parts) >= 2 and parts[1].strip():
                threat = parts[1].strip()
                # Nettoyer le suffixe " [L]  0" ou similaire
                for suffix in (" [L]  0", " [L] 0", " [L]", " [S]"):
                    threat = threat.replace(suffix, "")
                threat = threat.strip()
                if threat and threat != "[+]":
                    result.scanned_avast += 1
                    result.scanned       += 1
                    self._add_threat(result, targets, path, threat, "Avast")
                    if cb:
                        cb(f"🚨 Avast : {_clean(threat)}  →  {_clean(path, 300)}", "threat")
                    if fcc:
                        fcc(result.scanned, result.infected)
                    return
            # Sain
            if len(parts) >= 2 and parts[1].strip() in ("[+]", "OK", ""):
                result.scanned_avast += 1
                result.scanned       += 1
                if fcc:
                    fcc(result.scanned, result.infected)
            return

        # Format "[+]" sans tabulation
        stripped = line.strip()
        if stripped.endswith("[+]"):
            result.scanned_avast += 1
            result.scanned       += 1
            if fcc:
                fcc(result.scanned, result.infected)
            return

        # Format "chemin: Menace" (certaines versions)
        if stripped.startswith("/") and ": " in stripped:
            path, _, threat = stripped.partition(": ")
            threat = threat.strip()
            if threat and threat.upper() not in ("OK", "CLEAN", ""):
                result.scanned_avast += 1
                result.scanned       += 1
                self._add_threat(result, targets, path.strip(), threat, "Avast")
                if cb:
                    cb(f"🚨 Avast : {_clean(threat)}  →  {_clean(path.strip(), 300)}", "threat")
                if fcc:
                    fcc(result.scanned, result.infected)
            return

        # Lignes d'info (version, statistiques)
        if any(k in stripped for k in ("Avast", "VPS", "Scan", "Files")):
            if cb:
                cb(f"[Avast] {_clean(stripped)}", "info")

    # ══════════════════════════════════════════════════════════════════════════
    # Moteur YARA (yara_worker.py dans le sandbox)
    # ══════════════════════════════════════════════════════════════════════════

    def _scan_yara(self, targets: List[str], result: ScanResult,
                   cb: ProgressCB, fcc: Optional[Callable[[int, int], None]],
                   use_sb: bool) -> None:
        if not os.path.isfile(_WORKER_HOST):
            msg = "⚠ YARA : yara_worker.py introuvable — moteur ignoré."
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return

        count = self.yara_rules_count()
        if count == 0:
            msg = ("⚠ YARA : aucune règle installée — "
                   "utilisez le panneau Admin pour en importer.")
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return

        if cb:
            cb(f"YARA : démarrage ({count} fichier(s) de règles, "
               f"worker {'sandboxé' if use_sb else 'SANS sandbox'})…", "info")

        py = sys.executable or "/usr/bin/python3"
        worker = _WORKER_IN_SANDBOX if use_sb else _WORKER_HOST
        # -I : mode isolé (ni variables d'environnement, ni site utilisateur) ; -B : pas de .pyc
        cmd = [py, "-I", "-B", worker, YARA_RULES_DIR] + list(targets)

        rc = -99
        done: Optional[Tuple[int, int]] = None      # (analysés, illisibles)
        worker_error = False
        n_warn = 0
        selftest: Optional[bool] = None             # règle témoin détectée ?
        stats = {"rules": 0, "files": 0, "bytes": 0, "hits": 0, "secs": 0.0}
        expected = self._count_files(targets)       # pour la progression (approximatif)
        next_pct = 25
        stderr_f = tempfile.TemporaryFile()
        try:
            self._proc = self._launch(
                "yara", cmd, targets=targets, sandboxed=use_sb,
                ro_binds=[YARA_RULES_DIR],
                extra_ro={_WORKER_HOST: _WORKER_IN_SANDBOX},
                stdout=subprocess.PIPE, stderr=stderr_f,
                text=True, errors="surrogateescape", bufsize=1)
            assert self._proc.stdout
            for raw in self._proc.stdout:
                if self._stop:
                    result.stopped = True
                    break
                if len(raw) > _MAX_LINE:
                    continue
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(msg, dict):
                    continue                              # le worker n'est pas fiable
                kind = msg.get("type")

                if kind == "hit":
                    rule = _clean(msg.get("rule"))
                    path = msg.get("path")
                    if rule and isinstance(path, str):
                        self._add_threat(result, targets, path, rule, "YARA")
                        if cb:
                            cb(f"🚨 YARA : {rule}  →  {_clean(path, 300)}", "threat")
                elif kind == "progress":
                    n = msg.get("scanned")
                    if isinstance(n, int) and 0 <= n < 10 ** 9:
                        result.scanned_yara = n
                        if fcc:
                            fcc(max(result.scanned, n), result.infected)
                        if cb and expected > 0:
                            pct = min(100, n * 100 // expected)
                            if pct >= next_pct and n < expected:
                                cb(f"YARA : {n}/{expected} fichier(s) analysé(s) ({pct} %)…",
                                   "info")
                                next_pct = (pct // 25 + 1) * 25
                elif kind == "compiled":
                    n, r = msg.get("count"), msg.get("rules")
                    if isinstance(n, int) and 0 <= n < 10 ** 7:
                        stats["files"] = n
                    if isinstance(r, int) and 0 <= r < 10 ** 8:
                        stats["rules"] = r
                    if cb and isinstance(n, int):
                        cb(f"YARA : {n} fichier(s) de règles compilé(s)"
                           + (f" — {stats['rules']} règle(s) chargée(s)."
                              if stats["rules"] else "."), "info")
                elif kind == "selftest":
                    selftest = msg.get("ok") is True
                    if cb:
                        if selftest:
                            cb("YARA : auto-test OK — la règle témoin est détectée par "
                               "l'ensemble chargé (le moteur détecte réellement).", "ok")
                        else:
                            cb("❌ YARA : auto-test ÉCHOUÉ — règle témoin non détectée.",
                               "threat")
                elif kind == "warn":
                    n_warn += 1
                    log_warning(f"YARA : {_clean(msg.get('msg'))}")
                elif kind == "error":
                    worker_error = True
                    text = _clean(msg.get("msg")) or "erreur du worker"
                    result.errors.append(f"YARA : {text}")
                    if cb:
                        cb(f"⚠ YARA : {text}", "warning")
                elif kind == "done":
                    s, u = msg.get("scanned"), msg.get("unreadable")
                    if isinstance(s, int) and isinstance(u, int) and s >= 0 and u >= 0:
                        done = (s, u)
                        b, h, t = msg.get("bytes"), msg.get("hits"), msg.get("secs")
                        if isinstance(b, int) and 0 <= b < 10 ** 14:
                            stats["bytes"] = b
                        if isinstance(h, int) and 0 <= h < 10 ** 9:
                            stats["hits"] = h
                        if isinstance(t, (int, float)) and 0 <= t < 10 ** 7:
                            stats["secs"] = float(t)
            self._proc.wait()
            rc = self._proc.returncode
            if self._stop:
                result.stopped = True
        except SandboxUnavailable as e:
            result.errors.append(f"YARA : sandbox indisponible — {_clean(str(e))}")
            log_error(f"YARA sandbox : {e}")
            return
        except Exception as e:                                    # noqa: BLE001
            result.errors.append(f"YARA : {_clean(str(e))}")
            log_error(f"YARA scan : {e}")
            return
        finally:
            self._proc = None

        tail = ""
        try:
            stderr_f.seek(0)
            tail = _clean(stderr_f.read(2000).decode("utf-8", "replace"), 200)
        except Exception:                                         # noqa: BLE001
            pass
        finally:
            stderr_f.close()

        if n_warn and cb:
            cb(f"YARA : {n_warn} règle(s) ignorée(s) à la compilation (voir le journal).",
               "warning")

        if result.stopped:
            return

        if rc != 0 or done is None:
            if not worker_error:
                if rc == 3:
                    msg = ("⚠ YARA non disponible dans le sandbox.\n"
                           "Installez : sudo apt install python3-yara")
                else:
                    hint = (" (mémoire insuffisante ?)" if rc in (137, -9) else "")
                    msg = (f"❌ YARA : le worker s'est terminé avec le code {rc}{hint} "
                           "— analyse incomplète."
                           + (f"\n  {tail}" if tail else ""))
                result.errors.append(msg)
                if cb:
                    cb(msg, "threat")
                log_error(f"YARA worker : code {rc} {tail}")
            return

        scanned, unreadable = done
        analysed = scanned - unreadable
        result.scanned_yara = scanned
        result.scanned = max(result.scanned, scanned)
        result.yara_rule_files = stats["files"]
        result.yara_rules = stats["rules"]
        result.yara_selftest = selftest
        result.yara_bytes = stats["bytes"]
        result.yara_seconds = stats["secs"]
        if fcc:
            fcc(result.scanned, result.infected)
        if unreadable:
            # Un fichier non lu ne doit jamais passer pour sain
            msg = (f"⚠ YARA : {analysed} fichier(s) analysé(s), {unreadable} illisible(s) ou "
                   "non analysé(s) — analyse incomplète.")
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return
        if expected > 0 and analysed == 0:
            msg = "⚠ YARA : AUCUN fichier analysé alors que le support en contient."
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return
        if cb:
            hits = stats["hits"]
            if analysed == 0:
                cb("✅ YARA : analyse terminée — aucun fichier à analyser sur ce support "
                   "(les règles sont chargées et l'auto-test est passé).", "ok")
            else:
                size = (f" ({_fmt_size(stats['bytes'])})" if stats["bytes"] else "")
                rules = (f" avec {stats['rules']} règle(s)" if stats["rules"] else "")
                cb(("⚠" if hits else "✅")
                   + f" YARA : analyse TERMINÉE — {analysed} fichier(s) analysé(s){size}"
                   f"{rules} en {stats['secs']:.1f}s — "
                   + (f"{hits} détection(s)." if hits else "aucune détection."),
                   "threat" if hits else "ok")
        result.mark_ran("YARA")