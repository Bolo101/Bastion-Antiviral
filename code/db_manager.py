#!/usr/bin/env python3
"""
db_manager.py – Gestion des bases ClamAV, Avast et des règles YARA.

Opérations disponibles :
  ClamAV  – freshclam (en ligne) / import USB (.cvd/.cld)
  Avast   – licence (activation par code ou import .avastlic) / VPS (en ligne ou USB)
  YARA    – signature-base GitHub / import USB (.yar/.yara/.zip)
"""

import glob
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from typing import Callable, Dict, List, Optional, Tuple

from config import (
    CLAMAV_DB_DIR,
    YARA_RULES_DIR,
    YARA_SIGBASE_SUBDIR,
    YARA_CUSTOM_SUBDIR,
    SIGBASE_ZIP_URL,
    SIGBASE_YARA_PREFIX,
    AVAST_LICENSE_DIR,
    AVAST_LICENSE_PATH,
    AVAST_VPS_DIR,
    AVAST_BIN_PATHS,
    AVAST_LIC_BIN_PATHS,
)
from log_handler import log_error, log_info, log_warning

ProgressCB = Optional[Callable[[str], None]]

# ── Sources de signatures tierces téléchargeables gratuitement ────────────────
# Noms de fichiers IDENTIQUES à ceux installés par le hook 0150 de l'ISO build.
# Miroir HTTP Sanesecurity : mirror.ihost.md (vérifié opérationnel)
# Fallback                 : ftp.swin.edu.au/sanesecurity
_SANE = "https://mirror.ihost.md/clamav/sanesecurity"
_SANE2 = "https://ftp.swin.edu.au/sanesecurity"

THIRD_PARTY_SIGNATURES: List[Dict] = [
    # ── URLhaus (abuse.ch) ────────────────────────────────────────────────────
    {"name": "URLhaus",                 "file": "urlhaus-filter.ndb",
     "url":  "https://urlhaus.abuse.ch/downloads/urlhaus.ndb",
     "url2": "https://curbengh.github.io/malware-filter/urlhaus-filter-clam.ndb",
     "desc": "URLs malveillantes actives (abuse.ch)", "min_bytes": 1000},

    # ── InterServer ──────────────────────────────────────────────────────────
    {"name": "InterServer hashes",      "file": "interserver256.hdb",
     "url":  "http://sigs.interserver.net/interserver256.hdb",
     "desc": "Hashes SHA-256 (InterServer)", "min_bytes": 500},
    {"name": "InterServer topline",     "file": "topline.db",
     "url":  "http://sigs.interserver.net/topline.db",
     "desc": "Signatures topline (InterServer)", "min_bytes": 500},

    # ── Sanesecurity – fichiers requis ────────────────────────────────────────
    {"name": "Sanesecurity FTM",        "file": "sanesecurity.ftm",
     "url":  f"{_SANE}/sanesecurity.ftm",
     "desc": "Magic file types (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity whitelist",  "file": "sigwhitelist.ign2",
     "url":  f"{_SANE}/sigwhitelist.ign2",
     "desc": "Liste blanche (Sanesecurity)", "min_bytes": 64},

    # ── Sanesecurity – phishing / spam ────────────────────────────────────────
    {"name": "Sanesecurity phish",      "file": "phish.ndb",
     "url":  f"{_SANE}/phish.ndb",
     "desc": "Hameçonnage (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity junk",       "file": "junk.ndb",
     "url":  f"{_SANE}/junk.ndb",
     "desc": "Spam générique (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity jurlbl",     "file": "jurlbl.ndb",
     "url":  f"{_SANE}/jurlbl.ndb",
     "desc": "URLs de junk (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity jurlbla",    "file": "jurlbla.ndb",
     "url":  f"{_SANE}/jurlbla.ndb",
     "desc": "URLs de junk avancées (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity lott",       "file": "lott.ndb",
     "url":  f"{_SANE}/lott.ndb",
     "desc": "Loteries / arnaques (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity scam",       "file": "scam.ndb",
     "url":  f"{_SANE}/scam.ndb",
     "desc": "Arnaques (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity blurl",      "file": "blurl.ndb",
     "url":  f"{_SANE}/blurl.ndb",
     "desc": "URLs blacklistées (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity spam.ldb",   "file": "spam.ldb",
     "url":  f"{_SANE}/spam.ldb",
     "desc": "Signatures logiques spam (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity shelter",    "file": "shelter.ldb",
     "url":  f"{_SANE}/shelter.ldb",
     "desc": "Fichiers suspects hébergés (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity spear",      "file": "spear.ndb",
     "url":  f"{_SANE}/spear.ndb",
     "desc": "Spear-phishing (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity spearl",     "file": "spearl.ndb",
     "url":  f"{_SANE}/spearl.ndb",
     "desc": "Spear-phishing liens (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity badmacro",   "file": "badmacro.ndb",
     "url":  f"{_SANE}/badmacro.ndb",
     "desc": "Macros malveillantes (Sanesecurity)", "min_bytes": 64},

    # ── Sanesecurity – malwares / hashes ──────────────────────────────────────
    {"name": "Sanesecurity rogue",      "file": "rogue.hdb",
     "url":  f"{_SANE}/rogue.hdb",
     "desc": "Rogues / faux AV (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity spamimg",    "file": "spamimg.hdb",
     "url":  f"{_SANE}/spamimg.hdb",
     "desc": "Images spam (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity spamattach", "file": "spamattach.hdb",
     "url":  f"{_SANE}/spamattach.hdb",
     "desc": "Pièces jointes spam (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity malwarehash","file": "malwarehash.hsb",
     "url":  f"{_SANE}/malwarehash.hsb",
     "desc": "Hashes SHA-256 malwares (Sanesecurity)", "min_bytes": 64},
    {"name": "Sanesecurity hackingteam","file": "hackingteam.hsb",
     "url":  f"{_SANE}/hackingteam.hsb",
     "desc": "Outils Hacking Team (Sanesecurity)", "min_bytes": 64},

    # ── Sanesecurity – Foxhole ────────────────────────────────────────────────
    {"name": "Foxhole generic",         "file": "foxhole_generic.cdb",
     "url":  f"{_SANE}/foxhole_generic.cdb",
     "desc": "Fichiers génériques suspects (Foxhole)", "min_bytes": 64},
    {"name": "Foxhole filename",        "file": "foxhole_filename.cdb",
     "url":  f"{_SANE}/foxhole_filename.cdb",
     "desc": "Noms de fichiers suspects (Foxhole)", "min_bytes": 64},
    {"name": "Foxhole JS (cdb)",        "file": "foxhole_js.cdb",
     "url":  f"{_SANE}/foxhole_js.cdb",
     "desc": "JavaScript suspects (Foxhole)", "min_bytes": 64},
    {"name": "Foxhole JS (ndb)",        "file": "foxhole_js.ndb",
     "url":  f"{_SANE}/foxhole_js.ndb",
     "desc": "JavaScript malveillants (Foxhole)", "min_bytes": 64},
    {"name": "Foxhole all (cdb)",       "file": "foxhole_all.cdb",
     "url":  f"{_SANE}/foxhole_all.cdb",
     "desc": "Tous types suspects (Foxhole)", "min_bytes": 64},
    {"name": "Foxhole all (ndb)",       "file": "foxhole_all.ndb",
     "url":  f"{_SANE}/foxhole_all.ndb",
     "desc": "Tous types suspects ndb (Foxhole)", "min_bytes": 64},
    {"name": "Foxhole mail",            "file": "foxhole_mail.cdb",
     "url":  f"{_SANE}/foxhole_mail.cdb",
     "desc": "Pièces jointes mail (Foxhole)", "min_bytes": 64},
    {"name": "Foxhole links",           "file": "foxhole_links.ldb",
     "url":  f"{_SANE}/foxhole_links.ldb",
     "desc": "Liens malveillants (Foxhole)", "min_bytes": 64},

    # ── Sanesecurity – MiscreantPunch ─────────────────────────────────────────
    {"name": "MiscreantPunch Low",      "file": "MiscreantPunch099-Low.ldb",
     "url":  f"{_SANE}/MiscreantPunch099-Low.ldb",
     "desc": "Faible taux de FP (MiscreantPunch)", "min_bytes": 64},
    {"name": "MiscreantPunch INFO",     "file": "MiscreantPunch099-INFO-Low.ldb",
     "url":  f"{_SANE}/MiscreantPunch099-INFO-Low.ldb",
     "desc": "Informatif faible FP (MiscreantPunch)", "min_bytes": 64},

    # ── Sanesecurity – Porcupine ──────────────────────────────────────────────
    {"name": "Porcupine ndb",           "file": "porcupine.ndb",
     "url":  f"{_SANE}/porcupine.ndb",
     "desc": "Malwares (Porcupine)", "min_bytes": 64},
    {"name": "Porcupine hsb",           "file": "porcupine.hsb",
     "url":  f"{_SANE}/porcupine.hsb",
     "desc": "Hashes malwares (Porcupine)", "min_bytes": 64},
    {"name": "PhishTank",               "file": "phishtank.ndb",
     "url":  f"{_SANE}/phishtank.ndb",
     "desc": "URLs phishing vérifiées (PhishTank)", "min_bytes": 64},

    # ── Sanesecurity – bofhland ───────────────────────────────────────────────
    {"name": "bofhland cracked URL",    "file": "bofhland_cracked_URL.ndb",
     "url":  f"{_SANE}/bofhland_cracked_URL.ndb",
     "desc": "URLs de warez/crack (bofhland)", "min_bytes": 64},
    {"name": "bofhland malware URL",    "file": "bofhland_malware_URL.ndb",
     "url":  f"{_SANE}/bofhland_malware_URL.ndb",
     "desc": "URLs malware (bofhland)", "min_bytes": 64},
    {"name": "bofhland phishing URL",   "file": "bofhland_phishing_URL.ndb",
     "url":  f"{_SANE}/bofhland_phishing_URL.ndb",
     "desc": "URLs phishing (bofhland)", "min_bytes": 64},
    {"name": "bofhland malware attach", "file": "bofhland_malware_attach.hdb",
     "url":  f"{_SANE}/bofhland_malware_attach.hdb",
     "desc": "Pièces jointes malware (bofhland)", "min_bytes": 64},

    # ── Sanesecurity – winnow (OITC) ──────────────────────────────────────────
    {"name": "winnow malware",          "file": "winnow_malware.hdb",
     "url":  f"{_SANE}/winnow_malware.hdb",
     "desc": "Hashes malwares (winnow)", "min_bytes": 64},
    {"name": "winnow malware links",    "file": "winnow_malware_links.ndb",
     "url":  f"{_SANE}/winnow_malware_links.ndb",
     "desc": "Liens malwares (winnow)", "min_bytes": 64},
    {"name": "winnow spam",             "file": "winnow_spam_complete.ndb",
     "url":  f"{_SANE}/winnow_spam_complete.ndb",
     "desc": "Spam complet (winnow)", "min_bytes": 64},
    {"name": "winnow phish URL",        "file": "winnow_phish_complete_url.ndb",
     "url":  f"{_SANE}/winnow_phish_complete_url.ndb",
     "desc": "URLs phishing (winnow)", "min_bytes": 64},
    {"name": "winnow patterns",         "file": "winnow.complex.patterns.ldb",
     "url":  f"{_SANE}/winnow.complex.patterns.ldb",
     "desc": "Patterns complexes (winnow)", "min_bytes": 64},
    {"name": "winnow ext malware",      "file": "winnow_extended_malware.hdb",
     "url":  f"{_SANE}/winnow_extended_malware.hdb",
     "desc": "Malwares étendus (winnow)", "min_bytes": 64},
    {"name": "winnow ext links",        "file": "winnow_extended_malware_links.ndb",
     "url":  f"{_SANE}/winnow_extended_malware_links.ndb",
     "desc": "Liens malwares étendus (winnow)", "min_bytes": 64},
    {"name": "winnow attachments",      "file": "winnow.attachments.hdb",
     "url":  f"{_SANE}/winnow.attachments.hdb",
     "desc": "Pièces jointes (winnow)", "min_bytes": 64},

    # ── Sanesecurity – doppelstern / crdfam / scamnailer ─────────────────────
    {"name": "doppelstern ndb",         "file": "doppelstern.ndb",
     "url":  f"{_SANE}/doppelstern.ndb",
     "desc": "Malwares (doppelstern)", "min_bytes": 64},
    {"name": "doppelstern hdb",         "file": "doppelstern.hdb",
     "url":  f"{_SANE}/doppelstern.hdb",
     "desc": "Hashes (doppelstern)", "min_bytes": 64},
    {"name": "doppelstern phishtank",   "file": "doppelstern-phishtank.ndb",
     "url":  f"{_SANE}/doppelstern-phishtank.ndb",
     "desc": "PhishTank (doppelstern)", "min_bytes": 64},
    {"name": "crdfam",                  "file": "crdfam.clamav.hdb",
     "url":  f"{_SANE}/crdfam.clamav.hdb",
     "desc": "Fraude carte bancaire (crdfam)", "min_bytes": 64},
    {"name": "scamnailer",              "file": "scamnailer.ndb",
     "url":  f"{_SANE}/scamnailer.ndb",
     "desc": "Scams (scamnailer)", "min_bytes": 64},

    # ── Sanesecurity – malware.expert ─────────────────────────────────────────
    {"name": "malware.expert ndb",      "file": "malware.expert.ndb",
     "url":  f"{_SANE}/malware.expert.ndb",
     "desc": "Malwares (malware.expert)", "min_bytes": 64},
    {"name": "malware.expert hdb",      "file": "malware.expert.hdb",
     "url":  f"{_SANE}/malware.expert.hdb",
     "desc": "Hashes malwares (malware.expert)", "min_bytes": 64},
    {"name": "malware.expert ldb",      "file": "malware.expert.ldb",
     "url":  f"{_SANE}/malware.expert.ldb",
     "desc": "Logique malwares (malware.expert)", "min_bytes": 64},
    {"name": "malware.expert fp",       "file": "malware.expert.fp",
     "url":  f"{_SANE}/malware.expert.fp",
     "desc": "Faux-positifs (malware.expert)", "min_bytes": 64},
]

# Extensions reconnues comme signatures tierces ClamAV
_THIRD_PARTY_EXTS = frozenset([
    ".ndb", ".ndu", ".hdb", ".hdu", ".hsb", ".hsu",
    ".mdb", ".mdu", ".msb", ".msu", ".ldb", ".ldu",
    ".cdb", ".db",  ".ftm", ".fp",  ".sfp",
    ".ign", ".ign2",".pdb", ".wdb", ".gdb", ".crb",
])

# Bases officielles à ne pas comptabiliser comme tierces
_OFFICIAL_FILES = frozenset([
    "main.cvd", "main.cld", "daily.cvd", "daily.cld",
    "bytecode.cvd", "bytecode.cld",
])


def _run(cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"commande introuvable : {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


# ══════════════════════════════════════════════════════════════════════════════
class DBManager:
    """
    Gère :
     - La base ClamAV (freshclam / import USB)
     - La licence et la base VPS Avast (code d'activation / fichier / import USB)
     - Les règles YARA (téléchargement signature-base / import USB)
    """

    def __init__(self, usb_manager=None) -> None:
        self._usb = usb_manager   # UsbManager optionnel

    # ══════════════════════════════════════════════════════════════════════════
    # ClamAV
    # ══════════════════════════════════════════════════════════════════════════

    def get_clamav_status(self) -> Dict:
        """
        Retourne status (OK/OUTDATED/MISSING), fichiers détectés, bases manquantes
        et date de dernière mise à jour.

        Clés du dict retourné :
          status      – "OK" | "OUTDATED" | "MISSING"
          files       – {nom_fichier: "X.X Mo  (YYYY-MM-DD HH:MM)"}
          missing     – liste des groupes requis absents ("main", "daily", "bytecode")
          last_update – date la plus récente parmi tous les fichiers trouvés
        """
        # ── Groupes officiels requis (au moins un fichier par groupe) ──────────
        REQUIRED_GROUPS: Dict[str, Tuple[str, ...]] = {
            "main":     ("main.cvd",     "main.cld"),
            "daily":    ("daily.cvd",    "daily.cld"),
            "bytecode": ("bytecode.cvd", "bytecode.cld"),
        }

        # ── Toutes les extensions reconnues par ClamAV ─────────────────────────
        CLAMAV_EXTS = (
            ".cvd", ".cld",                         # bases officielles compressées
            ".ndb", ".ndu",                         # signatures NDB (hash + motif)
            ".hdb", ".hdu", ".hsb", ".hsu",         # MD5 / SHA-1 / SHA-256
            ".mdb", ".mdu", ".msb", ".msu",         # PE section hashes
            ".ldb", ".ldu",                         # signatures logiques
            ".cdb",                                  # signatures container
            ".idb",                                  # icônes PE
            ".fp",  ".sfp",                         # faux-positifs
            ".ign", ".ign2",                        # listes d'ignorés
            ".wdb",                                 # whitelists d'URL
            ".gdb",                                 # hashes graphiques
            ".pdb",                                 # listes de phishing
            ".crb",                                 # certificats révoqués
        )

        result: Dict = {
            "status":      "MISSING",
            "files":       {},
            "missing":     [],
            "last_update": None,
        }
        newest = 0.0

        # ── 1. Vérification des groupes officiels ─────────────────────────────
        for group, candidates in REQUIRED_GROUPS.items():
            group_found = False
            for fname in candidates:
                fpath = os.path.join(CLAMAV_DB_DIR, fname)
                if os.path.exists(fpath):
                    try:
                        st    = os.stat(fpath)
                        size  = f"{st.st_size / (1024*1024):.1f} Mo"
                        mtime = time.strftime("%Y-%m-%d %H:%M",
                                              time.localtime(st.st_mtime))
                        result["files"][fname] = f"{size}  ({mtime})"
                        if st.st_mtime > newest:
                            newest = st.st_mtime
                        group_found = True
                    except OSError:
                        pass
            if not group_found:
                result["missing"].append(group)

        # ── 2. Signatures tierces et supplémentaires dans le répertoire ────────
        if os.path.isdir(CLAMAV_DB_DIR):
            for fname in sorted(os.listdir(CLAMAV_DB_DIR)):
                if fname in result["files"]:
                    continue          # déjà compté dans les groupes officiels
                if not any(fname.endswith(ext) for ext in CLAMAV_EXTS):
                    continue
                fpath = os.path.join(CLAMAV_DB_DIR, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    st    = os.stat(fpath)
                    size  = f"{st.st_size / (1024*1024):.1f} Mo"
                    mtime = time.strftime("%Y-%m-%d %H:%M",
                                          time.localtime(st.st_mtime))
                    result["files"][fname] = f"{size}  ({mtime})"
                    if st.st_mtime > newest:
                        newest = st.st_mtime
                except OSError:
                    pass

        # ── 3. Calcul du statut global ─────────────────────────────────────────
        # main ET daily doivent être présents pour considérer la base utilisable
        has_main  = "main"  not in result["missing"]
        has_daily = "daily" not in result["missing"]

        if has_main and has_daily:
            days_old         = (time.time() - newest) / 86400
            result["status"] = "OK" if days_old < 7 else "OUTDATED"
        # sinon status reste "MISSING"

        if newest > 0:
            result["last_update"] = time.strftime(
                "%Y-%m-%d %H:%M", time.localtime(newest)
            )
        return result

    def update_clamav_online(self, progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        """
        Lance freshclam après avoir arrêté le service pour libérer le verrou PID.
        Redémarre le service dans tous les cas (bloc finally).
        """
        if not shutil.which("freshclam"):
            return False, "freshclam introuvable. Installez : apt install clamav-freshclam"

        SERVICE    = "clamav-freshclam"
        was_active = False
        rc, out, _ = _run(["systemctl", "is-active", SERVICE], timeout=5)
        if rc == 0 and out.strip() == "active":
            was_active = True
            if progress_cb:
                progress_cb(f"Arrêt temporaire du service {SERVICE}…")
            _run(["systemctl", "stop", SERVICE], timeout=20)

        success, message = False, ""
        try:
            if progress_cb:
                progress_cb("Lancement de freshclam…")
            proc = subprocess.Popen(
                ["freshclam", "--stdout", "--datadir", CLAMAV_DB_DIR],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            assert proc.stdout
            for line in proc.stdout:
                line = line.rstrip()
                if line and progress_cb:
                    progress_cb(line)
            proc.wait()

            if proc.returncode in (0, 1):
                success, message = True, "Base ClamAV mise à jour avec succès."
            elif proc.returncode == 2:
                success, message = False, (
                    "freshclam code 2 : conflit de verrou ou erreur réseau.\n"
                    "Vérifiez /var/log/clamav/freshclam.log."
                )
            else:
                success, message = False, f"freshclam a quitté avec le code {proc.returncode}."

        except Exception as e:
            success, message = False, f"Erreur : {e}"
        finally:
            if was_active:
                if progress_cb:
                    progress_cb(f"Redémarrage du service {SERVICE}…")
                _run(["systemctl", "start", SERVICE], timeout=20)

        (log_info if success else log_error)(message)
        return success, message

    def download_third_party_sigs(
            self,
            progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        """
        Télécharge les signatures ClamAV tierces définies dans THIRD_PARTY_SIGNATURES
        et les installe dans CLAMAV_DB_DIR, en validant chaque fichier individuellement.

        Pour chaque signature :
          1. Téléchargement via urllib (avec fallback sur url2 si présent)
          2. Vérification contenu (taille minimum + non-HTML)
          3. Copie atomique dans CLAMAV_DB_DIR
          4. Validation immédiate : clamscan --database=$DB_DIR sur le répertoire
             complet — si le nouveau fichier casse le chargement, il est supprimé

        Retourne (True, résumé) si au moins une signature a été installée.
        """
        import shutil as _shutil

        os.makedirs(CLAMAV_DB_DIR, exist_ok=True)
        clamav_ok = _shutil.which("clamscan") is not None

        installed: List[str] = []
        rejected:  List[str] = []
        failed:    List[str] = []

        def _is_valid_content(path: str) -> bool:
            try:
                with open(path, "rb") as f:
                    header = f.read(64)
                if not header:
                    return False
                # Rejeter pages HTML/HTTP/JSON servies en 200 OK
                h = header[:16]
                if h.startswith(b"<") or h.startswith(b"HTTP/") or h.startswith(b'{"'):
                    return False
                return True
            except Exception:
                return False

        def _db_loads_ok() -> bool:
            """Teste que le répertoire complet se charge sans erreur."""
            if not clamav_ok:
                return True   # pas de clamscan → on accepte sans valider
            import tempfile as _tmpmod
            try:
                fd2, probe = _tmpmod.mkstemp(prefix="clamav_probe_", suffix=".tmp")
                os.close(fd2)
                r = subprocess.run(
                    ["clamscan", "--no-summary",
                     f"--database={CLAMAV_DB_DIR}", probe],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=60
                )
                os.unlink(probe)
                if r.returncode == 2:
                    combined = r.stdout + r.stderr
                    return not any(k in combined for k in
                                   ("Error loading", "Can't load", "Invalid",
                                    "Corrupt", "corrupt", "Can't open"))
                return True
            except Exception:
                return True

        def _fetch(url: str, suffix: str) -> Optional[str]:
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(
                        delete=False, suffix=suffix, dir="/tmp") as tmp:
                    tmp_path = tmp.name
                urllib.request.urlretrieve(url, tmp_path)
                return tmp_path
            except Exception:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass
                return None

        for sig in THIRD_PARTY_SIGNATURES:
            name      = sig["name"]
            dest      = os.path.join(CLAMAV_DB_DIR, sig["file"])
            min_bytes = sig.get("min_bytes", 64)
            suffix    = os.path.splitext(sig["file"])[1]

            if progress_cb:
                progress_cb(f"⬇  {name} …")

            # ── Téléchargement (URL principale + fallback) ────────────────────
            tmp_path = _fetch(sig["url"], suffix)
            if tmp_path is None and "url2" in sig:
                if progress_cb:
                    progress_cb(f"   ↩ fallback URL pour {name}…")
                tmp_path = _fetch(sig["url2"], suffix)

            if tmp_path is None:
                msg = f"   ⚠ {name} : inaccessible (réseau ?)"
                log_warning(msg)
                failed.append(name)
                if progress_cb:
                    progress_cb(msg)
                continue

            size = os.path.getsize(tmp_path)

            # ── Validation contenu ────────────────────────────────────────────
            if size < min_bytes or not _is_valid_content(tmp_path):
                msg = f"   ⚠ {name} : contenu invalide ({size} o)"
                log_warning(msg)
                failed.append(name)
                if progress_cb:
                    progress_cb(msg)
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
                continue

            # ── Installation atomique ─────────────────────────────────────────
            shutil.move(tmp_path, dest)
            os.chmod(dest, 0o644)
            _run(["chown", "clamav:clamav", dest], timeout=5)

            # ── Validation base complète ──────────────────────────────────────
            if _db_loads_ok():
                size_kb = size / 1024
                log_info(f"Signature tierce installée : {sig['file']} ({size_kb:.0f} Ko)")
                installed.append(f"{sig['file']} ({size_kb:.0f} Ko)")
                if progress_cb:
                    progress_cb(f"   ✅ {name} : {size_kb:.0f} Ko")
            else:
                msg = f"   ⚠ {name} : conflit de format — supprimé"
                log_warning(msg)
                rejected.append(name)
                if progress_cb:
                    progress_cb(msg)
                try:
                    os.unlink(dest)
                except Exception:
                    pass

        # ── Rechargement du daemon ClamAV ─────────────────────────────────────
        if installed:
            if progress_cb:
                progress_cb("Rechargement du daemon ClamAV…")
            _run(["systemctl", "reload-or-restart", "clamav-daemon"], timeout=30)

        # ── Résumé ────────────────────────────────────────────────────────────
        lines: List[str] = []
        if installed:
            lines.append(f"✅ {len(installed)} signature(s) installée(s) :")
            lines.extend(f"   • {f}" for f in installed)
        if rejected:
            lines.append(f"⚠ {len(rejected)} fichier(s) rejeté(s) (conflit ClamAV) :")
            lines.extend(f"   • {r}" for r in rejected)
        if failed:
            lines.append(f"⚠ {len(failed)} source(s) inaccessible(s) :")
            lines.extend(f"   • {f}" for f in failed)

        summary = "\n".join(lines) if lines else "Aucune signature traitée."
        success = len(installed) > 0
        (log_info if success else log_error)(
            f"Signatures tierces : {len(installed)} OK, "
            f"{len(rejected)} rejetés, {len(failed)} échoués"
        )
        return success, summary

    def get_known_virus_count(self) -> Optional[int]:
        """
        Retourne le nombre de signatures chargées par clamscan (toutes bases
        confondues : officielles + tierces), en lançant un scan rapide sur un
        fichier vide temporaire et en parsant la ligne "Known viruses: N".

        Retourne None si clamscan n'est pas disponible ou en cas d'erreur.
        Ce compteur est la seule source fiable pour savoir si les bases tierces
        sont réellement prises en compte.

        Note : --database force le chargement de TOUT le contenu de CLAMAV_DB_DIR,
        y compris les .ndb/.hdb/.ldb tiers — sans cette option, clamscan peut
        utiliser son chemin compilé par défaut et ignorer les signatures tierces.
        """
        import tempfile, shutil
        if not shutil.which("clamscan"):
            return None

        tmp_path: Optional[str] = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix="clamav_count_", suffix=".tmp")
            os.close(fd)
            r = subprocess.run(
                ["clamscan", f"--database={CLAMAV_DB_DIR}", tmp_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=60
            )
            combined = r.stdout + r.stderr
            for line in combined.splitlines():
                if line.startswith("Known viruses:"):
                    try:
                        return int(line.split(":")[1].strip().replace(",", ""))
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        return None

    def get_third_party_sig_status(self) -> Dict:
        """
        Retourne l'état des signatures tierces en deux passes :

        1. Passe liste : vérifie chaque fichier de THIRD_PARTY_SIGNATURES
           (installed / missing).
        2. Passe répertoire : compte les fichiers tiers supplémentaires présents
           dans CLAMAV_DB_DIR mais absents de la liste (ex. fichiers installés
           manuellement ou via USB).

        Clés du dict :
          installed   – [{name, file, size_kb, date}]  fichiers de la liste présents
          missing     – [name]                          fichiers de la liste absents
          extra       – [{file, size_kb, date}]         fichiers tiers hors-liste
          total_size  – taille totale en Ko (liste + extra)
          total_count – nombre total de fichiers tiers présents
        """
        # Noms attendus par la liste (pour ne pas les compter deux fois)
        expected_files = {sig["file"] for sig in THIRD_PARTY_SIGNATURES}

        result: Dict = {
            "installed":   [],
            "missing":     [],
            "extra":       [],
            "total_size":  0,
            "total_count": 0,
        }

        # ── Passe 1 : vérification de la liste connue ─────────────────────────
        for sig in THIRD_PARTY_SIGNATURES:
            dest = os.path.join(CLAMAV_DB_DIR, sig["file"])
            if os.path.exists(dest):
                try:
                    st      = os.stat(dest)
                    size_kb = st.st_size / 1024
                    mtime   = time.strftime("%Y-%m-%d", time.localtime(st.st_mtime))
                    result["installed"].append(
                        {"name": sig["name"], "file": sig["file"],
                         "size_kb": size_kb, "date": mtime}
                    )
                    result["total_size"]  += size_kb
                    result["total_count"] += 1
                except OSError:
                    result["missing"].append(sig["name"])
            else:
                result["missing"].append(sig["name"])

        # ── Passe 2 : fichiers tiers non référencés dans la liste ─────────────
        if os.path.isdir(CLAMAV_DB_DIR):
            for fname in sorted(os.listdir(CLAMAV_DB_DIR)):
                if fname in _OFFICIAL_FILES or fname in expected_files:
                    continue
                ext = os.path.splitext(fname)[1].lower()
                if ext not in _THIRD_PARTY_EXTS:
                    continue
                fpath = os.path.join(CLAMAV_DB_DIR, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    st      = os.stat(fpath)
                    size_kb = st.st_size / 1024
                    mtime   = time.strftime("%Y-%m-%d", time.localtime(st.st_mtime))
                    result["extra"].append(
                        {"file": fname, "size_kb": size_kb, "date": mtime}
                    )
                    result["total_size"]  += size_kb
                    result["total_count"] += 1
                except OSError:
                    pass

        return result

    def find_clamav_on_usb(self) -> List[str]:
        files: List[str] = []
        for mp in self._usb_mountpoints():
            for ext in ("*.cvd", "*.cld"):
                files += glob.glob(os.path.join(mp, ext))
                files += glob.glob(os.path.join(mp, "**", ext), recursive=True)
        return list(set(files))

    def import_clamav_from_usb(self, db_files: List[str],
                                progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        try:
            os.makedirs(CLAMAV_DB_DIR, exist_ok=True)
            imported: List[str] = []
            for src in db_files:
                fname = os.path.basename(src)
                dst   = os.path.join(CLAMAV_DB_DIR, fname)
                if progress_cb:
                    progress_cb(f"Copie de {fname}…")
                shutil.copy2(src, dst)
                os.chmod(dst, 0o644)
                imported.append(fname)
                log_info(f"ClamAV DB importée : {fname}")

            _run(["chown", "clamav:clamav"] +
                 [os.path.join(CLAMAV_DB_DIR, f) for f in imported])
            _run(["systemctl", "reload", "clamav-daemon"], timeout=15)
            return True, f"{len(imported)} fichier(s) importé(s) : {', '.join(imported)}"
        except Exception as e:
            log_error(f"Import ClamAV : {e}")
            return False, f"Échec de l'import : {e}"

    # ══════════════════════════════════════════════════════════════════════════
    # Avast – Licence
    # ══════════════════════════════════════════════════════════════════════════

    def get_avast_status(self) -> Dict:
        """
        Retourne un dict décrivant l'état complet d'Avast :
          {
            "installed":    bool,
            "licensed":     bool,
            "license_date": str | None,   # date d'import du fichier .avastlic
            "vps_date":     str | None,   # date de la base VPS
            "status":       "OK" | "NO_LICENSE" | "NOT_INSTALLED"
          }
        """
        from scanner import ScanEngine
        eng = ScanEngine()

        result: Dict = {
            "installed":    eng.is_avast_installed(),
            "licensed":     False,
            "license_date": None,
            "vps_date":     None,
            "status":       "NOT_INSTALLED",
        }

        if not result["installed"]:
            return result

        # Licence
        if os.path.exists(AVAST_LICENSE_PATH):
            try:
                mtime = os.path.getmtime(AVAST_LICENSE_PATH)
                result["licensed"]     = True
                result["license_date"] = time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(mtime)
                )
            except OSError:
                pass

        # Base VPS
        if os.path.isdir(AVAST_VPS_DIR):
            newest = 0.0
            for f in os.listdir(AVAST_VPS_DIR):
                try:
                    mtime = os.path.getmtime(os.path.join(AVAST_VPS_DIR, f))
                    if mtime > newest:
                        newest = mtime
                except OSError:
                    pass
            if newest > 0:
                result["vps_date"] = time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(newest)
                )

        result["status"] = "OK" if result["licensed"] else "NO_LICENSE"
        return result

    def find_avast_license_on_usb(self) -> List[str]:
        """Retourne tous les fichiers license.avastlic trouvés sur les clés USB."""
        found: List[str] = []
        for mp in self._usb_mountpoints():
            # Racine de la clé
            candidate = os.path.join(mp, "license.avastlic")
            if os.path.exists(candidate):
                found.append(candidate)
            # Sous-répertoires (max 2 niveaux)
            for entry in glob.glob(os.path.join(mp, "**", "license.avastlic"),
                                   recursive=True):
                if entry not in found:
                    found.append(entry)
        return found

    def import_avast_license_from_file(
            self,
            license_path: str,
            progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        """
        Installe une licence Avast depuis un fichier .avastlic.

        Stratégie :
          1. Essai via `avastlic import <path>` (outil officiel)
          2. Fallback : copie directe vers /etc/avast/license.avastlic
        """
        if progress_cb:
            progress_cb(f"Import de la licence depuis {os.path.basename(license_path)}…")

        # Cherche l'outil avastlic
        avastlic = self._find_avastlic()

        if avastlic:
            rc, out, err = _run([avastlic, "import", license_path], timeout=30)
            if rc == 0:
                log_info(f"Licence Avast importée via avastlic : {license_path}")
                return True, "Licence Avast importée avec succès (avastlic)."
            log_warning(f"avastlic import échoué (code {rc}) : {err.strip()} — copie directe…")

        # Fallback : copie directe
        try:
            os.makedirs(AVAST_LICENSE_DIR, exist_ok=True)
            shutil.copy2(license_path, AVAST_LICENSE_PATH)
            os.chmod(AVAST_LICENSE_PATH, 0o644)
            # Redémarrage du service pour prendre en compte la licence
            _run(["systemctl", "restart", "avast"], timeout=60)
            log_info(f"Licence Avast copiée vers {AVAST_LICENSE_PATH}")
            return True, f"Licence copiée vers {AVAST_LICENSE_PATH}.\nService Avast redémarré."
        except Exception as e:
            log_error(f"Import licence Avast : {e}")
            return False, f"Impossible d'importer la licence : {e}"

    def activate_avast_with_code(
            self,
            activation_code: str,
            progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        """
        Active Avast avec un code d'activation (utilise l'outil avastlic).
        Requiert une connexion Internet.
        """
        code = activation_code.strip()
        if not code:
            return False, "Le code d'activation est vide."

        avastlic = self._find_avastlic()
        if not avastlic:
            return False, (
                "L'outil avastlic est introuvable.\n"
                "Installez : apt install avast-license\n"
                "ou utilisez l'import de fichier .avastlic."
            )

        if progress_cb:
            progress_cb(f"Activation du code {code[:4]}…{'*' * (len(code) - 4)}…")

        rc, out, err = _run([avastlic, "activate", code], timeout=120)
        combined = (out + err).strip()

        if rc == 0:
            log_info(f"Avast activé avec le code {code[:4]}****")
            _run(["systemctl", "restart", "avast"], timeout=60)
            return True, "Code activé avec succès. Service Avast redémarré."

        log_error(f"Activation Avast échouée (code {rc}) : {combined}")
        return False, f"Échec de l'activation (code {rc}) :\n{combined or 'Vérifiez le code et la connexion Internet.'}"

    # ══════════════════════════════════════════════════════════════════════════
    # Avast – Base VPS
    # ══════════════════════════════════════════════════════════════════════════

    def update_avast_vps_online(
            self,
            progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        """
        Met à jour la base VPS Avast.

        Stratégie :
          1. `avast update`          – mise à jour directe via le daemon
          2. `systemctl restart avast` – redémarrage force le téléchargement de la VPS
        """
        from scanner import ScanEngine
        if not ScanEngine.is_avast_installed():
            return False, "Avast n'est pas installé."

        avast_bin = self._find_avast_bin()

        if avast_bin:
            if progress_cb:
                progress_cb("Lancement de la mise à jour Avast VPS…")
            try:
                proc = subprocess.Popen(
                    [avast_bin, "update"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                assert proc.stdout
                for line in proc.stdout:
                    line = line.rstrip()
                    if line and progress_cb:
                        progress_cb(f"[Avast] {line}")
                proc.wait()
                if proc.returncode == 0:
                    log_info("Base VPS Avast mise à jour avec succès.")
                    return True, "Base VPS Avast mise à jour avec succès."
            except Exception as e:
                log_warning(f"avast update : {e} — essai via systemctl…")

        # Fallback : redémarrage du service
        if progress_cb:
            progress_cb("Redémarrage du service Avast pour forcer la mise à jour…")
        rc, _, err = _run(["systemctl", "restart", "avast"], timeout=90)
        if rc == 0:
            log_info("Service Avast redémarré (mise à jour VPS en cours).")
            return True, ("Service Avast redémarré.\n"
                          "La base VPS sera mise à jour au démarrage du service.")
        log_error(f"Redémarrage Avast échoué : {err.strip()}")
        return False, f"Impossible de mettre à jour Avast : {err.strip()}"

    def find_avast_vps_on_usb(self) -> List[str]:
        """Retourne les fichiers VPS Avast trouvés sur les clés USB."""
        found: List[str] = []
        patterns = ("*.vps", "vps*.zip", "avast_vps*", "*.vpz")
        for mp in self._usb_mountpoints():
            for pat in patterns:
                found += glob.glob(os.path.join(mp, pat))
                found += glob.glob(os.path.join(mp, "**", pat), recursive=True)
        return list(set(found))

    def import_avast_vps_from_usb(
            self,
            vps_file: str,
            progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        """Installe un fichier VPS Avast depuis une clé USB."""
        try:
            os.makedirs(AVAST_VPS_DIR, exist_ok=True)
            fname = os.path.basename(vps_file)
            dst   = os.path.join(AVAST_VPS_DIR, fname)
            if progress_cb:
                progress_cb(f"Copie de {fname} vers {AVAST_VPS_DIR}…")
            shutil.copy2(vps_file, dst)
            log_info(f"VPS Avast copié : {dst}")

            avast_bin = self._find_avast_bin()
            if avast_bin:
                rc, _, _ = _run([avast_bin, "vpsupdate", dst], timeout=120)
                if rc == 0:
                    return True, "Base VPS Avast mise à jour depuis la clé USB."

            _run(["systemctl", "restart", "avast"], timeout=60)
            return True, f"{fname} installé. Service Avast redémarré."
        except Exception as e:
            log_error(f"Import VPS Avast : {e}")
            return False, f"Échec de l'import VPS : {e}"

    # ══════════════════════════════════════════════════════════════════════════
    # YARA
    # ══════════════════════════════════════════════════════════════════════════

    def get_yara_status(self) -> Dict:
        result = {"count": 0, "last_update": None, "sources": {}}
        if not os.path.isdir(YARA_RULES_DIR):
            return result

        newest = 0.0
        for root, _, files in os.walk(YARA_RULES_DIR):
            src_name = os.path.relpath(root, YARA_RULES_DIR).split(os.sep)[0]
            for fname in files:
                if fname.endswith((".yar", ".yara")) and not fname.startswith("."):
                    result["count"] += 1
                    result["sources"][src_name] = result["sources"].get(src_name, 0) + 1
                    try:
                        mtime = os.path.getmtime(os.path.join(root, fname))
                        if mtime > newest:
                            newest = mtime
                    except OSError:
                        pass

        if newest > 0:
            result["last_update"] = time.strftime(
                "%Y-%m-%d %H:%M", time.localtime(newest)
            )
        return result

    def update_yara_online(self, progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        if progress_cb:
            progress_cb("Connexion à GitHub (signature-base)…")

        out_dir = os.path.join(YARA_RULES_DIR, YARA_SIGBASE_SUBDIR)

        try:
            with tempfile.TemporaryDirectory() as tmp:
                zip_path = os.path.join(tmp, "signature-base.zip")

                def _reporthook(block, block_size, total):
                    if total > 0 and progress_cb:
                        pct = min(100, int(block * block_size * 100 / total))
                        progress_cb(f"Téléchargement… {pct}%")

                if progress_cb:
                    progress_cb(f"Téléchargement de {SIGBASE_ZIP_URL}…")
                urllib.request.urlretrieve(SIGBASE_ZIP_URL, zip_path, _reporthook)

                if progress_cb:
                    progress_cb("Extraction des règles .yar…")

                if os.path.isdir(out_dir):
                    shutil.rmtree(out_dir)
                os.makedirs(out_dir, exist_ok=True)

                count = 0
                with zipfile.ZipFile(zip_path) as zf:
                    for member in zf.namelist():
                        if (member.startswith(SIGBASE_YARA_PREFIX)
                                and member.endswith((".yar", ".yara"))
                                and not member.endswith("/")):
                            fname  = os.path.basename(member)
                            target = os.path.join(out_dir, fname)
                            with zf.open(member) as src, open(target, "wb") as dst:
                                dst.write(src.read())
                            count += 1

                log_info(f"YARA signature-base : {count} règles → {out_dir}")
                return True, f"{count} fichiers de règles installés dans {out_dir}"

        except urllib.error.URLError as e:
            log_error(f"YARA download : {e}")
            return False, f"Erreur réseau : {e.reason}"
        except Exception as e:
            log_error(f"YARA update : {e}")
            return False, f"Erreur : {e}"

    def find_yara_on_usb(self) -> List[str]:
        found: List[str] = []
        for mp in self._usb_mountpoints():
            for ext in ("*.yar", "*.yara"):
                found += glob.glob(os.path.join(mp, ext))
                found += glob.glob(os.path.join(mp, "**", ext), recursive=True)
            for z in glob.glob(os.path.join(mp, "*.zip")):
                try:
                    with zipfile.ZipFile(z) as zf:
                        if any(n.endswith((".yar", ".yara")) for n in zf.namelist()):
                            found.append(z)
                except Exception:
                    pass
        return list(set(found))

    def import_yara_from_usb(self, sources: List[str],
                              progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        out_dir = os.path.join(YARA_RULES_DIR, YARA_CUSTOM_SUBDIR)
        os.makedirs(out_dir, exist_ok=True)
        imported = 0

        try:
            for src in sources:
                if src.endswith(".zip"):
                    if progress_cb:
                        progress_cb(f"Extraction de {os.path.basename(src)}…")
                    with zipfile.ZipFile(src) as zf:
                        for member in zf.namelist():
                            if member.endswith((".yar", ".yara")):
                                fname  = os.path.basename(member)
                                target = os.path.join(out_dir, fname)
                                with zf.open(member) as zs, open(target, "wb") as fd:
                                    fd.write(zs.read())
                                imported += 1
                else:
                    fname  = os.path.basename(src)
                    target = os.path.join(out_dir, fname)
                    if progress_cb:
                        progress_cb(f"Copie de {fname}…")
                    shutil.copy2(src, target)
                    imported += 1

            log_info(f"YARA import USB : {imported} fichier(s) → {out_dir}")
            return True, f"{imported} fichier(s) importé(s) dans {out_dir}"
        except Exception as e:
            log_error(f"Import YARA USB : {e}")
            return False, f"Erreur lors de l'import : {e}"

    def clear_yara_rules(self, source: str = "all") -> Tuple[bool, str]:
        try:
            if source == "all":
                if os.path.isdir(YARA_RULES_DIR):
                    shutil.rmtree(YARA_RULES_DIR)
                os.makedirs(YARA_RULES_DIR, exist_ok=True)
                return True, "Toutes les règles YARA supprimées."
            target = os.path.join(YARA_RULES_DIR, source)
            if os.path.isdir(target):
                shutil.rmtree(target)
                return True, f"Règles '{source}' supprimées."
            return True, f"Aucune règle '{source}' à supprimer."
        except Exception as e:
            return False, f"Erreur : {e}"

    # ══════════════════════════════════════════════════════════════════════════
    # Helpers privés
    # ══════════════════════════════════════════════════════════════════════════

    def _usb_mountpoints(self) -> List[str]:
        if self._usb:
            return self._usb.get_all_usb_mountpoints()
        mps: List[str] = []
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].startswith("/dev/"):
                        mp = parts[1]
                        if "/media" in mp or "/mnt" in mp or "/run/media" in mp:
                            mps.append(mp)
        except Exception:
            pass
        return mps

    def _find_avastlic(self) -> Optional[str]:
        """Retourne le chemin de l'outil avastlic, ou None."""
        found = shutil.which("avastlic")
        if found:
            return found
        for p in AVAST_LIC_BIN_PATHS:
            if os.path.exists(p):
                return p
        return None

    def _find_avast_bin(self) -> Optional[str]:
        """Retourne le chemin du binaire avast (daemon), ou None."""
        found = shutil.which("avast")
        if found:
            return found
        for p in AVAST_BIN_PATHS:
            if os.path.exists(p):
                return p
        return None