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
    CLAMAV_DB_DIR,
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
             progress_cb:      ProgressCB,
             file_count_cb:    Optional[Callable[[int, int], None]] = None) -> ScanResult:
        """
        Lance le scan complet et retourne le résultat agrégé.
        Ordre : ClamAV → Avast → YARA.

        file_count_cb(scanned, infected) est appelé après chaque fichier traité
        pour permettre une mise à jour temps réel du compteur dans l'UI.
        """
        self._reset()
        result = ScanResult()
        start  = time.time()

        if use_clamav:
            self._scan_clamav(targets, remove_infected, result, progress_cb, file_count_cb)

        if use_avast and not result.stopped:
            self._scan_avast(targets, remove_infected, result, progress_cb, file_count_cb)

        if use_yara and not result.stopped:
            self._scan_yara(targets, result, progress_cb, file_count_cb)

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

    # ── Pré-validation de la base ClamAV ──────────────────────────────────────

    def _check_clamav_db(self, cb: ProgressCB) -> bool:
        """
        Vérifie que la base ClamAV se charge correctement en scannant un fichier
        vide temporaire.

        Note : /dev/null NE doit PAS être utilisé — c'est un fichier spécial que
        clamscan rejette systématiquement avec le code 2 ("Not supported file type"),
        déclenchant un faux positif d'erreur de base.

        Code 0 = OK, code 1 = OK, code 2 + messages d'erreur DB = base invalide.
        """
        import tempfile

        tmp_path: Optional[str] = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix="clamav_check_", suffix=".tmp")
            os.close(fd)

            r = subprocess.run(
                ["clamscan", "--no-summary",
                 f"--database={CLAMAV_DB_DIR}", tmp_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=60
            )
        except Exception as e:
            log_warning(f"ClamAV pré-validation impossible : {e}")
            return True
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        if r.returncode in (0, 1):
            return True

        combined = (r.stdout + r.stderr).strip()
        bad_lines = [l for l in combined.splitlines()
                     if any(k in l for k in
                            ("Error loading", "Can't load", "Invalid",
                             "Corrupt", "corrupt", "Can't open"))]

        if not bad_lines:
            log_warning(f"ClamAV pré-validation : code 2 sans erreur DB "
                        f"({combined[:120]}). Scan autorisé.")
            return True

        detail = "\n   ".join(bad_lines[:5])
        msg = ("❌ ClamAV : échec de chargement de la base (code 2).\n"
               "   Cause : une signature tierce est probablement corrompue.\n"
               f"   {detail}\n"
               "   → Relancez une mise à jour depuis le panneau Admin.")
        if cb:
            cb(msg, "threat")
        log_error(msg)
        return False

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

    def _scan_clamav(self, targets: List[str], remove: bool,
                     result: ScanResult, cb: ProgressCB,
                     fcc: Optional[Callable[[int, int], None]] = None) -> None:

        # ── 1. Pré-validation : base chargeable ? ─────────────────────────────
        if not self._check_clamav_db(cb):
            result.errors.append(
                "ClamAV : base invalide (code 2) — scan annulé. "
                "Lancez une mise à jour depuis le panneau Admin."
            )
            return

        # ── 2. Scan ───────────────────────────────────────────────────────────
        # Notes sur les options :
        #   --max-filesize=0 / --max-scansize=0 / --max-files=0
        #     Lève les limites silencieuses par défaut (25 Mo/fichier, 100 Mo/total,
        #     10 000 fichiers). Sans ces options, les samples volumineux sont
        #     simplement ignorés sans avertissement → faux "aucune menace".
        #   --scan-archive=yes
        #     Force le scan des archives (tar, zip non chiffrés, etc.).
        #     Note : les ZIP protégés par mot de passe ne peuvent PAS être scannés
        #     par ClamAV (ni par aucun autre moteur AV sans le mot de passe).
        #   --alert-broken
        #     Signale les PE/archives corrompus ou tronqués comme suspects.
        #   --detect-pua=yes
        #     Détecte les logiciels potentiellement indésirables (adware,
        #     downloaders, packers, outils d'administration, etc.).
        cmd = [
            "clamscan",
            "--recursive",
            "--stdout",
            "--verbose",                     # émet "/path: OK" pour chaque fichier sain
                                             # → permet le comptage en temps réel
            f"--database={CLAMAV_DB_DIR}",  # charge TOUTES les sigs du répertoire,
                                             # officielles ET tierces (.ndb/.hdb/.ldb…)
            "--max-filesize=0",
            "--max-scansize=0",
            "--max-files=0",
            "--scan-archive=yes",
            "--alert-broken",
            "--detect-pua=yes",
        ]
        if remove:
            cmd.append("--remove")
        cmd.extend(targets)

        if cb:
            cb("ClamAV : démarrage de l'analyse…", "info")

        rc = -99
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
                self._parse_clamav(line.rstrip(), result, cb, fcc)
            self._proc.wait()
            rc = self._proc.returncode
        except Exception as e:
            result.errors.append(f"ClamAV : {e}")
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
            log_warning(f"ClamAV : code de retour inattendu {rc}")

        # ── 4. Filet de sécurité : compteur nul alors que le scan a tourné ────
        # Arrive si clamscan n'émet pas la ligne "Scanned files:" (version
        # ancienne, scan vide, stderr non capturé, etc.)
        if result.scanned_clamav == 0 and not result.stopped and rc in (0, 1):
            estimated = self._count_files(targets)
            if estimated > 0:
                result.scanned_clamav = estimated
                result.scanned = max(result.scanned, estimated)
                if cb:
                    cb(f"[ClamAV] {estimated} fichier(s) parcourus (comptage direct).",
                       "info")

    def _parse_clamav(self, line: str, result: ScanResult, cb: ProgressCB,
                      fcc: Optional[Callable[[int, int], None]] = None) -> None:
        if not line:
            return

        line = line.strip()  # robustesse : CR résiduels, espaces

        # ── Menace détectée ───────────────────────────────────────────────────
        if " FOUND" in line:
            parts  = line.rsplit(":", 1)
            path   = parts[0].strip()
            threat = parts[1].replace(" FOUND", "").strip() if len(parts) == 2 else line
            result.infected       += 1
            result.scanned_clamav += 1
            result.scanned        += 1
            result.threats.append(ThreatInfo(path=path, threat=threat, engine="ClamAV"))
            if cb:
                cb(f"🚨 ClamAV : {threat}  →  {path}", "threat")
            if fcc:
                fcc(result.scanned, result.infected)
            return

        # ── Résumé final : "Scanned files: N" ────────────────────────────────
        # Source principale du compteur ; prioritaire sur le comptage ligne à ligne
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
        # Avec --verbose, ClamAV émet "/chemin/fichier: OK" pour chaque fichier propre.
        # On compte sans loguer (évite de saturer le journal).
        if line.endswith(": OK") or line.endswith(": Empty file"):
            result.scanned_clamav += 1
            result.scanned        += 1
            # Mise à jour UI toutes les 20 lignes pour limiter les appels callback
            if fcc and result.scanned_clamav % 20 == 0:
                fcc(result.scanned, result.infected)
            return

        # ── Erreurs de chargement DB (à logger sans bloquer) ─────────────────
        if "LibClamAV Error" in line or "LibClamAV Warning" in line:
            if cb:
                cb(f"[ClamAV] {line}", "warning")
            log_warning(f"ClamAV DB : {line}")
            return

        # ── Lignes d'info du résumé ───────────────────────────────────────────
        if any(k in line for k in ("Engine version:", "Known viruses:",
                                    "Scan time:", "Scanned directories:",
                                    "Data scanned:", "Start Date:")):
            if cb:
                cb(f"[ClamAV] {line}", "info")

    # ══════════════════════════════════════════════════════════════════════════
    # Moteur Avast
    # ══════════════════════════════════════════════════════════════════════════

    def _scan_avast(self, targets: List[str], remove: bool,
                    result: ScanResult, cb: ProgressCB,
                    fcc: Optional[Callable[[int, int], None]] = None) -> None:
        """
        Lance le scan Avast Business via la commande `scan` (CLI Avast Linux).

        Avast Business for Linux est la seule version disponible sur Linux.
        Une licence Business active est requise pour scanner — sans licence
        le binaire démarre mais refuse le scan (code 126 ou message d'erreur).
        On tente dans tous les cas et on remonte l'erreur précisément.

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

        avast_bin = self.get_avast_scan_binary()
        if not avast_bin:
            msg = "⚠ Avast : binaire de scan introuvable."
            result.errors.append(msg)
            if cb:
                cb(msg, "warning")
            return

        # Licence requise pour Avast Business for Linux.
        # On avertit mais on tente quand même le scan — certaines versions
        # tolèrent un scan partiel ; d'autres retournent code 126.
        licensed = self.is_avast_licensed()
        if not licensed and cb:
            cb("⚠ Avast : licence Business manquante — le scan risque d'être refusé."
               "  Activez une licence depuis le panneau Administration.", "warning")

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

        rc = -99
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
                self._parse_avast(line.rstrip(), result, cb, fcc)
            self._proc.wait()
            rc = self._proc.returncode

            # Code 126 = scan refusé par Avast Business (licence manquante)
            if rc == 126:
                msg = ("⚠ Avast Business : scan refusé (code 126) — licence requise.\n"
                       "  Obtenez une licence sur https://www.avast.com/business/linux\n"
                       "  et activez-la depuis le panneau Administration.")
                result.errors.append(msg)
                if cb:
                    cb(msg, "warning")
                return

            if cb:
                cb(f"Avast : analyse terminée ({result.scanned_avast} fichier(s)).",
                   "info")
        except Exception as e:
            result.errors.append(f"Avast : {e}")
            log_error(f"Avast scan : {e}")
        finally:
            self._proc = None

    def _parse_avast(self, line: str, result: ScanResult, cb: ProgressCB,
                     fcc: Optional[Callable[[int, int], None]] = None) -> None:
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
                result.infected      += 1
                result.scanned_avast += 1
                result.scanned       += 1
                result.threats.append(
                    ThreatInfo(path=path.strip(), threat=threat, engine="Avast")
                )
                if cb:
                    cb(f"🚨 Avast : {threat}  →  {path.strip()}", "threat")
                if fcc:
                    fcc(result.scanned, result.infected)
            return

        # Lignes d'info (version, statistiques)
        if any(k in stripped for k in ("Avast", "VPS", "Scan", "Files")):
            if cb:
                cb(f"[Avast] {stripped}", "info")

    # ══════════════════════════════════════════════════════════════════════════
    # Moteur YARA
    # ══════════════════════════════════════════════════════════════════════════

    def _scan_yara(self, targets: List[str],
                   result: ScanResult, cb: ProgressCB,
                   fcc: Optional[Callable[[int, int], None]] = None) -> None:
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
            self._yara_python(targets, result, cb, fcc)
        else:
            self._yara_binary(targets, result, cb, fcc)

    # ── YARA / python-yara ────────────────────────────────────────────────────

    def _yara_python(self, targets: List[str],
                     result: ScanResult, cb: ProgressCB,
                     fcc: Optional[Callable[[int, int], None]] = None) -> None:
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
                # Notification UI toutes les 20 lignes
                if fcc and scanned_yara[0] % 20 == 0:
                    fcc(result.scanned, result.infected)
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
                     result: ScanResult, cb: ProgressCB,
                     fcc: Optional[Callable[[int, int], None]] = None) -> None:
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
                                if fcc:
                                    fcc(result.scanned, result.infected)
                    self._proc.wait()
                except Exception as e:
                    log_warning(f"YARA binaire ({os.path.basename(rf)}) : {e}")
                finally:
                    self._proc = None