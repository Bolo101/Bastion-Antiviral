#!/usr/bin/env python3
"""
db_manager.py – Gestion des bases ClamAV et des règles YARA.
Mise à jour en ligne, import hors-ligne depuis clé USB.
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
    CLAMAV_DB_DIR, YARA_RULES_DIR,
    YARA_SIGBASE_SUBDIR, YARA_CUSTOM_SUBDIR,
    SIGBASE_ZIP_URL, SIGBASE_YARA_PREFIX,
)
from log_handler import log_error, log_info, log_warning

ProgressCB = Optional[Callable[[str], None]]


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
     - Les règles YARA (téléchargement signature-base / import USB)
    """

    def __init__(self, usb_manager=None) -> None:
        self._usb = usb_manager   # UsbManager optionnel pour trouver les fichiers

    # ══════════════════════════════════════════════════════════════════════════
    # ClamAV
    # ══════════════════════════════════════════════════════════════════════════

    def get_clamav_status(self) -> Dict:
        """Retourne un dict avec status (OK/OUTDATED/MISSING), fichiers, date."""
        db_files  = ["main.cvd", "main.cld", "daily.cvd",
                     "daily.cld", "bytecode.cvd", "bytecode.cld"]
        result    = {"status": "MISSING", "files": {}, "last_update": None}
        newest    = 0.0
        found     = 0

        for fname in db_files:
            fpath = os.path.join(CLAMAV_DB_DIR, fname)
            if os.path.exists(fpath):
                try:
                    st    = os.stat(fpath)
                    size  = f"{st.st_size / (1024*1024):.1f} Mo"
                    mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))
                    result["files"][fname] = f"{size}  ({mtime})"
                    if st.st_mtime > newest:
                        newest = st.st_mtime
                    found += 1
                except OSError:
                    pass

        if found >= 2:
            days_old        = (time.time() - newest) / 86400
            result["status"] = "OK" if days_old < 7 else "OUTDATED"

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

        SERVICE       = "clamav-freshclam"
        was_active    = False
        rc, out, _    = _run(["systemctl", "is-active", SERVICE], timeout=5)
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
                    "freshclam code 2 : conflit persistant ou erreur réseau.\n"
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

        if success:
            log_info(message)
        else:
            log_error(message)
        return success, message

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
    # YARA
    # ══════════════════════════════════════════════════════════════════════════

    def get_yara_status(self) -> Dict:
        """Retourne count des règles, date de la plus récente, sous-sources."""
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
        """
        Télécharge le dépôt signature-base de Florian Roth (GitHub) et extrait
        uniquement les fichiers .yar dans YARA_RULES_DIR/signature-base/.
        """
        if progress_cb:
            progress_cb("Connexion à GitHub (signature-base)…")

        out_dir = os.path.join(YARA_RULES_DIR, YARA_SIGBASE_SUBDIR)

        try:
            with tempfile.TemporaryDirectory() as tmp:
                zip_path = os.path.join(tmp, "signature-base.zip")

                # Téléchargement avec progression
                def _reporthook(block, block_size, total):
                    if total > 0 and progress_cb:
                        pct = min(100, int(block * block_size * 100 / total))
                        progress_cb(f"Téléchargement… {pct}%")

                if progress_cb:
                    progress_cb(f"Téléchargement de {SIGBASE_ZIP_URL}…")
                urllib.request.urlretrieve(SIGBASE_ZIP_URL, zip_path, _reporthook)

                if progress_cb:
                    progress_cb("Extraction des règles .yar…")

                # Efface l'ancienne version
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

                log_info(f"YARA signature-base : {count} règles installées → {out_dir}")
                return True, f"{count} fichiers de règles installés dans {out_dir}"

        except urllib.error.URLError as e:
            log_error(f"YARA download : {e}")
            return False, f"Erreur réseau : {e.reason}"
        except Exception as e:
            log_error(f"YARA update : {e}")
            return False, f"Erreur : {e}"

    def find_yara_on_usb(self) -> List[str]:
        """Trouve des .yar, .yara ou .zip contenant des règles sur les clés USB."""
        found: List[str] = []
        for mp in self._usb_mountpoints():
            for ext in ("*.yar", "*.yara"):
                found += glob.glob(os.path.join(mp, ext))
                found += glob.glob(os.path.join(mp, "**", ext), recursive=True)
            # Aussi chercher les zips pouvant contenir des règles
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
        """
        Importe des fichiers .yar/.yara ou des zips contenant des règles.
        Les copie dans YARA_RULES_DIR/custom/.
        """
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
            return True, f"{imported} fichier(s) de règles importé(s) dans {out_dir}"
        except Exception as e:
            log_error(f"Import YARA USB : {e}")
            return False, f"Erreur lors de l'import : {e}"

    def clear_yara_rules(self, source: str = "all") -> Tuple[bool, str]:
        """Supprime les règles d'une source ('all', 'signature-base', 'custom')."""
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

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _usb_mountpoints(self) -> List[str]:
        if self._usb:
            return self._usb.get_all_usb_mountpoints()
        # Fallback : lire /proc/mounts
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