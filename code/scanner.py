#!/usr/bin/env python3
"""
scanner.py – Moteur de scan combiné ClamAV + Avast + YARA.

Moteurs disponibles :
  • ClamAV  – clamscan (toujours disponible si installé)
  • Avast   – binaire scan/avast (requiert licence dans /etc/avast/)
  • YARA    – python-yara (prioritaire) ou binaire yara (secours)

Le scan est séquentiel : ClamAV → Avast → YARA.
Les résultats des trois moteurs sont agrégés dans un ScanResult unique.
"""

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from config import (
    YARA_RULES_DIR,
    AVAST_LICENSE_PATH,
    AVAST_BIN_PATHS,
    AVAST_SCAN_BIN_PATHS,
)
from log_handler import log_error, log_info, log_warning

ProgressCB = Optional[Callable[[str, str], None]]   # (message, tag)


# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class ThreatInfo:
    path:   str
    threat: str
    engine: str   # "ClamAV" | "Avast" | "YARA"


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
        self._proc   = None    # subprocess en cours (ClamAV ou Avast)
        self._yara_method: Optional[str] = None   # "python" | "binary" | None

    # ── Contrôle ──────────────────────────────────────────────────────────────

    def request_stop(self) -> None:
        self._stop = True
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def _reset(self) -> None:
        self._stop = False
        self._proc = None

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
        """Résumé court de l'état d'Avast pour la barre de statut de la GUI."""
        if not self.is_avast_installed():
            return "❌  Avast : non installé"
        if not self.is_avast_licensed():
            return "⚠   Avast : installé — licence manquante"
        try:
            mtime = os.path.getmtime(AVAST_LICENSE_PATH)
            date  = time.strftime("%Y-%m-%d", time.localtime(mtime))
            return f"✅  Avast : prêt  (licence : {date})"
        except OSError:
            return "✅  Avast : prêt"

    # ── Détection : YARA ──────────────────────────────────────────────────────

    def detect_yara(self) -> Tuple[bool, str]:
        """Retourne (dispo, méthode) : méthode = 'python' | 'binary' | ''."""
        try:
            import yara   # noqa: F401
            self._yara_method = "python"
            return True, "python"
        except ImportError:
            pass
        if shutil.which("yara"):
            self._yara_method = "binary"
            return True, "binary"
        self._yara_method = None
        return False, ""

    def yara_rules_count(self) -> int:
        if not os.path.isdir(YARA_RULES_DIR):
            return 0
        return sum(
            1 for _, _, files in os.walk(YARA_RULES_DIR)
            for f in files
            if f.endswith((".yar", ".yara")) and not f.startswith(".")
        )

    def _collect_rules(self) -> List[str]:
        rules: List[str] = []
        for root, _, files in os.walk(YARA_RULES_DIR):
            for f in sorted(files):
                if f.endswith((".yar", ".yara")) and not f.startswith("."):
                    rules.append(os.path.join(root, f))
        return rules

    # ══════════════════════════════════════════════════════════════════════════
    # Scan principal
    # ══════════════════════════════════════════════════════════════════════════

    def scan(self,
             targets:          List[str],
             use_clamav:       bool,
             use_avast:        bool,
             use_yara:         bool,
             remove_infected:  bool,
             progress_cb:      ProgressCB) -> ScanResult:
        """
        Lance le scan complet et retourne le résultat agrégé.
        Ordre : ClamAV → Avast → YARA.
        """
        self._reset()
        result = ScanResult()
        start  = time.time()

        if use_clamav:
            self._scan_clamav(targets, remove_infected, result, progress_cb)

        if use_avast and not result.stopped:
            self._scan_avast(targets, remove_infected, result, progress_cb)

        if use_yara and not result.stopped:
            self._scan_yara(targets, result, progress_cb)

        result.duration = time.time() - start
        log_info(
            f"Scan terminé : {result.scanned} fichiers, "
            f"{result.infected} menace(s), {result.duration:.1f}s  "
            f"[ClamAV:{result.scanned_clamav} | "
            f"Avast:{result.scanned_avast} | "
            f"YARA:{result.scanned_yara}]"
        )
        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Moteur ClamAV
    # ══════════════════════════════════════════════════════════════════════════

    def _scan_clamav(self, targets: List[str], remove: bool,
                     result: ScanResult, cb: ProgressCB) -> None:
        cmd = ["clamscan", "--recursive", "--stdout"]
        if remove:
            cmd.append("--remove")
        cmd.extend(targets)

        if cb:
            cb("ClamAV : démarrage de l'analyse…", "info")
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            assert self._proc.stdout
            for line in self._proc.stdout:
                if self._stop:
                    result.stopped = True
                    break
                self._parse_clamav(line.rstrip(), result, cb)
            self._proc.wait()
        except Exception as e:
            result.errors.append(f"ClamAV : {e}")
            log_error(f"ClamAV scan : {e}")
        finally:
            self._proc = None

    def _parse_clamav(self, line: str, result: ScanResult, cb: ProgressCB) -> None:
        if not line:
            return
        if " FOUND" in line:
            parts  = line.rsplit(":", 1)
            path   = parts[0].strip()
            threat = parts[1].replace(" FOUND", "").strip() if len(parts) == 2 else line
            result.infected += 1
            result.scanned_clamav += 1
            result.threats.append(ThreatInfo(path=path, threat=threat, engine="ClamAV"))
            if cb:
                cb(f"🚨 ClamAV : {threat}  →  {path}", "threat")
            return
        if line.startswith("Scanned files:"):
            try:
                n = int(line.split(":")[1].strip())
                result.scanned_clamav = max(result.scanned_clamav, n)
                result.scanned        = max(result.scanned, n)
            except (ValueError, IndexError):
                pass
            return
        if line.endswith(": OK") or line.endswith(": Empty file"):
            result.scanned_clamav += 1
            result.scanned        += 1
            return
        if any(k in line for k in ("Engine version:", "Known viruses:", "Scan time:")):
            if cb:
                cb(f"[ClamAV] {line}", "info")

    # ══════════════════════════════════════════════════════════════════════════
    # Moteur Avast
    # ══════════════════════════════════════════════════════════════════════════

    def _scan_avast(self, targets: List[str], remove: bool,
                    result: ScanResult, cb: ProgressCB) -> None:
        """
        Lance le scan Avast via la commande `scan` (CLI de l'agent Avast Linux).

        Format de sortie Avast :
          Fichier sain    :  /chemin/fichier [+]
          Fichier infecté :  /chemin/fichier\tNom-Menace [L]\t0
        """
        if not self.is_avast_installed():
            msg = "⚠ Avast : non installé — moteur ignoré."
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return

        if not self.is_avast_licensed():
            msg = ("⚠ Avast : licence manquante — moteur ignoré.\n"
                   "Importez une licence depuis le panneau Administration.")
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

        # Construction de la commande
        # `scan` est le CLI dédié ; s'il n'est pas disponible, on utilise
        # `avast scan` (interface daemon)
        scan_binary_name = os.path.basename(avast_bin)
        if scan_binary_name == "scan":
            cmd = [avast_bin, "-p"]           # -p : afficher chemin + statut
            if remove:
                cmd.append("-a")              # -a action=delete (selon version)
            cmd.extend(targets)
        else:
            cmd = [avast_bin, "scan", "-r"]   # avast scan --recursive
            if remove:
                cmd += ["--action", "remove"]
            cmd.extend(targets)

        if cb:
            cb("Avast : démarrage de l'analyse…", "info")

        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            assert self._proc.stdout
            for line in self._proc.stdout:
                if self._stop:
                    result.stopped = True
                    break
                self._parse_avast(line.rstrip(), result, cb)
            self._proc.wait()

            if cb:
                cb(f"Avast : analyse terminée ({result.scanned_avast} fichier(s)).",
                   "info")
        except Exception as e:
            result.errors.append(f"Avast : {e}")
            log_error(f"Avast scan : {e}")
        finally:
            self._proc = None

    def _parse_avast(self, line: str, result: ScanResult, cb: ProgressCB) -> None:
        """
        Parse une ligne de sortie du CLI Avast for Linux.

          Sain     : "/chemin/fichier [+]"
          Infecté  : "/chemin/fichier\tNom-Menace [L]\t0"
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
                    result.infected += 1
                    result.scanned_avast += 1
                    result.scanned       += 1
                    result.threats.append(
                        ThreatInfo(path=path, threat=threat, engine="Avast")
                    )
                    if cb:
                        cb(f"🚨 Avast : {threat}  →  {path}", "threat")
                    return
            # Sain
            if len(parts) >= 2 and parts[1].strip() in ("[+]", "OK", ""):
                result.scanned_avast += 1
                result.scanned       += 1
            return

        # Format "[+]" sans tabulation
        stripped = line.strip()
        if stripped.endswith("[+]"):
            result.scanned_avast += 1
            result.scanned       += 1
            return

        # Format "chemin: Menace" (certaines versions)
        if stripped.startswith("/") and ": " in stripped:
            path, _, threat = stripped.partition(": ")
            threat = threat.strip()
            if threat and threat.upper() not in ("OK", "CLEAN", ""):
                result.infected      += 1
                result.scanned_avast += 1
                result.scanned       += 1
                result.threats.append(
                    ThreatInfo(path=path.strip(), threat=threat, engine="Avast")
                )
                if cb:
                    cb(f"🚨 Avast : {threat}  →  {path.strip()}", "threat")
            return

        # Lignes d'info (version, statistiques)
        if any(k in stripped for k in ("Avast", "VPS", "Scan", "Files")):
            if cb:
                cb(f"[Avast] {stripped}", "info")

    # ══════════════════════════════════════════════════════════════════════════
    # Moteur YARA
    # ══════════════════════════════════════════════════════════════════════════

    def _scan_yara(self, targets: List[str],
                   result: ScanResult, cb: ProgressCB) -> None:
        ok, method = self.detect_yara()
        if not ok:
            msg = ("⚠ YARA non disponible.\n"
                   "Installez : sudo apt install python3-yara  "
                   "ou  sudo pip3 install yara-python")
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
            cb(f"YARA : démarrage ({count} règle(s), méthode : {method})…", "info")

        if method == "python":
            self._yara_python(targets, result, cb)
        else:
            self._yara_binary(targets, result, cb)

    # ── YARA / python-yara ────────────────────────────────────────────────────

    def _yara_python(self, targets: List[str],
                     result: ScanResult, cb: ProgressCB) -> None:
        import yara   # type: ignore

        rule_files    = self._collect_rules()
        compiled_sets: List = []

        if cb:
            cb(f"YARA : compilation de {len(rule_files)} fichier(s) de règles…", "info")

        for rf in rule_files:
            if self._stop:
                return
            try:
                compiled_sets.append(
                    yara.compile(
                        filepath=rf,
                        externals={
                            "filename": "", "filepath": "",
                            "extension": "", "filetype": "",
                        }
                    )
                )
            except yara.SyntaxError as e:
                log_warning(f"Règle ignorée ({os.path.basename(rf)}) : {e}")
            except Exception as e:
                log_warning(f"Erreur compilation ({os.path.basename(rf)}) : {e}")

        if not compiled_sets:
            if cb:
                cb("⚠ YARA : aucune règle valide après compilation.", "warning")
            return

        if cb:
            cb(f"YARA : {len(compiled_sets)} ensemble(s) compilé(s).", "info")

        scanned_yara = [0]

        def _scan_file(fpath: str) -> None:
            try:
                ext  = os.path.splitext(fpath)[1].lstrip(".").lower()
                exts = {
                    "filename":  os.path.basename(fpath),
                    "filepath":  fpath,
                    "extension": ext,
                    "filetype":  ext.upper(),
                }
                for rules in compiled_sets:
                    matches = rules.match(fpath, externals=exts, timeout=15)
                    for m in matches:
                        result.infected      += 1
                        result.scanned_yara  += 1
                        result.threats.append(
                            ThreatInfo(path=fpath, threat=m.rule, engine="YARA")
                        )
                        if cb:
                            cb(f"🚨 YARA : {m.rule}  →  {fpath}", "threat")
            except Exception:
                pass
            finally:
                scanned_yara[0] += 1
                result.scanned_yara = scanned_yara[0]
                if scanned_yara[0] % 200 == 0 and cb:
                    cb(f"YARA : {scanned_yara[0]} fichiers analysés…", "info")

        for target in targets:
            if self._stop:
                result.stopped = True
                return
            if os.path.isfile(target):
                _scan_file(target)
            elif os.path.isdir(target):
                for dirpath, _, files in os.walk(target):
                    if self._stop:
                        result.stopped = True
                        return
                    for fname in files:
                        if self._stop:
                            result.stopped = True
                            return
                        fp = os.path.join(dirpath, fname)
                        if os.path.isfile(fp) and not os.path.islink(fp):
                            _scan_file(fp)

    # ── YARA / binaire ────────────────────────────────────────────────────────

    def _yara_binary(self, targets: List[str],
                     result: ScanResult, cb: ProgressCB) -> None:
        rule_files = self._collect_rules()
        for rf in rule_files:
            if self._stop:
                result.stopped = True
                return
            for target in targets:
                if self._stop:
                    result.stopped = True
                    return
                try:
                    self._proc = subprocess.Popen(
                        ["yara", "-r", rf, target],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, bufsize=1
                    )
                    assert self._proc.stdout
                    for line in self._proc.stdout:
                        if self._stop:
                            self._proc.terminate()
                            result.stopped = True
                            return
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split(None, 1)
                            if len(parts) == 2:
                                rule_name, fpath = parts
                                result.infected      += 1
                                result.scanned_yara  += 1
                                result.scanned       += 1
                                result.threats.append(
                                    ThreatInfo(path=fpath,
                                               threat=rule_name,
                                               engine="YARA")
                                )
                                if cb:
                                    cb(f"🚨 YARA : {rule_name}  →  {fpath}", "threat")
                    self._proc.wait()
                except Exception as e:
                    log_warning(f"YARA binaire ({os.path.basename(rf)}) : {e}")
                finally:
                    self._proc = None