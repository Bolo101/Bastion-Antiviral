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
# Chaque entrée : url, nom de fichier local dans CLAMAV_DB_DIR, description courte.
THIRD_PARTY_SIGNATURES: List[Dict] = [
    # abuse.ch / URLhaus – URLs malveillantes actives
    {
        "name": "URLhaus",
        "url":  "https://urlhaus-filter.abuse.ch/urlhaus-filter-clam.ndb",
        "file": "urlhaus-filter.ndb",
        "desc": "URLs malveillantes actives (abuse.ch / URLhaus)",
    },
    # Sanesecurity – phishing, scam, spam, macros, rogues
    {
        "name": "Sanesecurity – phishing",
        "url":  "https://mirror.sanewall.org/sanesecurity/phish.ndb",
        "file": "sanesecurity-phish.ndb",
        "desc": "Hameçonnage (Sanesecurity)",
    },
    {
        "name": "Sanesecurity – scam",
        "url":  "https://mirror.sanewall.org/sanesecurity/scam.ndb",
        "file": "sanesecurity-scam.ndb",
        "desc": "Arnaques (Sanesecurity)",
    },
    {
        "name": "Sanesecurity – junk",
        "url":  "https://mirror.sanewall.org/sanesecurity/junk.ndb",
        "file": "sanesecurity-junk.ndb",
        "desc": "Spam / courrier indésirable (Sanesecurity)",
    },
    {
        "name": "Sanesecurity – sigpack",
        "url":  "https://mirror.sanewall.org/sanesecurity/sigpack.ndb",
        "file": "sanesecurity-sigpack.ndb",
        "desc": "Pack de signatures génériques (Sanesecurity)",
    },
    {
        "name": "Sanesecurity – malware (hdb)",
        "url":  "https://mirror.sanewall.org/sanesecurity/malware.expert.hdb",
        "file": "sanesecurity-malware.hdb",
        "desc": "Hashes de malwares (Sanesecurity)",
    },
    {
        "name": "Sanesecurity – malware (db)",
        "url":  "https://mirror.sanewall.org/sanesecurity/malware.expert.db",
        "file": "sanesecurity-malware.db",
        "desc": "Base malwares généraliste (Sanesecurity)",
    },
    {
        "name": "Sanesecurity – FTM",
        "url":  "https://mirror.sanewall.org/sanesecurity/sanesecurity.ftm",
        "file": "sanesecurity.ftm",
        "desc": "Magic file types (Sanesecurity)",
    },
    # InterServer – base complémentaire généraliste
    {
        "name": "InterServer",
        "url":  "https://www.interserver.net/virus-l/interserver.ndb",
        "file": "interserver.ndb",
        "desc": "Signatures génériques InterServer",
    },
]


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
        et les installe dans CLAMAV_DB_DIR.

        Pour chaque source :
          - Téléchargement via urllib dans un fichier temporaire
          - Vérification que le fichier n'est pas vide
          - Copie atomique vers CLAMAV_DB_DIR avec les bons droits
          - En cas d'échec individuel, on continue avec les autres sources

        Retourne (True, résumé) si au moins une signature a été installée.
        """
        os.makedirs(CLAMAV_DB_DIR, exist_ok=True)

        installed:  List[str] = []
        failed:     List[str] = []

        for sig in THIRD_PARTY_SIGNATURES:
            name = sig["name"]
            url  = sig["url"]
            dest = os.path.join(CLAMAV_DB_DIR, sig["file"])

            if progress_cb:
                progress_cb(f"⬇  {name} …")

            try:
                with tempfile.NamedTemporaryFile(
                        delete=False,
                        suffix=os.path.splitext(sig["file"])[1],
                        dir="/tmp") as tmp:
                    tmp_path = tmp.name

                def _hook(blocks: int, block_size: int, total: int) -> None:
                    if total > 0 and progress_cb:
                        pct = min(100, blocks * block_size * 100 // total)
                        progress_cb(f"   {name} : {pct}%")

                urllib.request.urlretrieve(url, tmp_path, _hook)

                size = os.path.getsize(tmp_path)
                if size < 64:
                    raise ValueError(f"fichier trop petit ({size} octets) — source indisponible ?")

                shutil.move(tmp_path, dest)
                os.chmod(dest, 0o644)
                _run(["chown", "clamav:clamav", dest], timeout=5)

                size_kb = size / 1024
                log_info(f"Signature tierce installée : {sig['file']}  ({size_kb:.0f} Ko)")
                installed.append(f"{sig['file']} ({size_kb:.0f} Ko)")
                if progress_cb:
                    progress_cb(f"   ✅ {name} : {size_kb:.0f} Ko installé")

            except urllib.error.URLError as e:
                reason = getattr(e, "reason", str(e))
                msg = f"   ⚠ {name} : erreur réseau – {reason}"
                log_warning(msg)
                failed.append(name)
                if progress_cb:
                    progress_cb(msg)
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

            except Exception as e:
                msg = f"   ⚠ {name} : {e}"
                log_warning(msg)
                failed.append(name)
                if progress_cb:
                    progress_cb(msg)
                try:
                    os.unlink(tmp_path)
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
        if failed:
            lines.append(f"⚠ {len(failed)} source(s) inaccessible(s) :")
            lines.extend(f"   • {f}" for f in failed)

        summary = "\n".join(lines) if lines else "Aucune signature traitée."
        success = len(installed) > 0
        (log_info if success else log_error)(
            f"Signatures tierces : {len(installed)} OK, {len(failed)} échoué(s)"
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
        """
        import tempfile, shutil
        if not shutil.which("clamscan"):
            return None

        tmp_path: Optional[str] = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix="clamav_count_", suffix=".tmp")
            os.close(fd)
            r = subprocess.run(
                ["clamscan", tmp_path],
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
        Retourne un dict décrivant l'état des signatures tierces installées :
          installed  – liste de (nom_fichier, taille_Ko, date)
          missing    – liste des noms de fichiers attendus mais absents
          total_size – taille totale en Ko
        """
        result: Dict = {"installed": [], "missing": [], "total_size": 0}
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
                    result["total_size"] += size_kb
                except OSError:
                    result["missing"].append(sig["name"])
            else:
                result["missing"].append(sig["name"])
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