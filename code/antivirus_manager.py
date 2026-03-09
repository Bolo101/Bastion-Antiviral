#!/usr/bin/env python3
"""
antivirus_manager.py
Handles ClamAV and Avast antivirus engines: detection, licensing,
database management (online & offline USB import), and scan execution.
"""

import os
import shutil
import subprocess
import glob
import json
import time
from typing import Callable, Dict, List, Optional, Tuple

from log_handler import log_error, log_info, log_warning

# ── paths ──────────────────────────────────────────────────────────────────────
CLAMAV_DB_DIR        = "/var/lib/clamav"
AVAST_LICENSE_PATH   = "/etc/avast/license.avastlic"
AVAST_LICENSE_DIR    = "/etc/avast"
AVAST_VPS_DIR        = "/var/lib/avast/Setup"
AVAST_SCAN_BIN_PATHS = ["/usr/bin/avast", "/opt/avast/bin/avast",
                         "/usr/local/bin/avast"]

ProgressCB = Optional[Callable[[str], None]]


# ── helpers ────────────────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Run a command; return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


# ══════════════════════════════════════════════════════════════════════════════
class AntivirusManager:
    """
    Abstraction layer for ClamAV and Avast.
    All public methods return (success: bool, message: str) unless noted.
    """

    def __init__(self) -> None:
        self.current_engine: str = "clamav"   # "clamav" | "avast"

    # ── engine detection ───────────────────────────────────────────────────────

    def is_clamav_installed(self) -> bool:
        return shutil.which("clamscan") is not None

    def is_avast_installed(self) -> bool:
        if shutil.which("avast") is not None:
            return True
        return any(os.path.exists(p) for p in AVAST_SCAN_BIN_PATHS)

    def is_freshclam_available(self) -> bool:
        return shutil.which("freshclam") is not None

    def get_avast_binary(self) -> Optional[str]:
        """Return the path to the avast binary, or None."""
        found = shutil.which("avast")
        if found:
            return found
        for p in AVAST_SCAN_BIN_PATHS:
            if os.path.exists(p):
                return p
        return None

    def engine_status_summary(self, engine: str) -> str:
        """Short human-readable status for the requested engine."""
        if engine == "clamav":
            if not self.is_clamav_installed():
                return "❌ Non installé (apt install clamav)"
            db_info = self.get_clamav_db_info()
            status = db_info["status"]
            if status == "OK":
                return f"✅ Installé – base {db_info.get('last_update', 'à jour')}"
            elif status == "OUTDATED":
                return "⚠️  Installé – base obsolète"
            else:
                return "⚠️  Installé – base manquante"
        else:  # avast
            if not self.is_avast_installed():
                return "❌ Non installé"
            lic = self.get_avast_license_status()
            return f"✅ Installé – licence : {lic}"

    # ── ClamAV database info ───────────────────────────────────────────────────

    def get_clamav_db_info(self) -> Dict:
        db_files = ["main.cvd", "main.cld", "daily.cvd",
                    "daily.cld", "bytecode.cvd", "bytecode.cld"]
        result: Dict = {"status": "MISSING", "files": {}, "last_update": None}
        newest_mtime = 0.0
        found = 0

        for fname in db_files:
            fpath = os.path.join(CLAMAV_DB_DIR, fname)
            if os.path.exists(fpath):
                try:
                    st = os.stat(fpath)
                    size_mb = st.st_size / (1024 * 1024)
                    mtime_str = time.strftime('%Y-%m-%d %H:%M:%S',
                                             time.localtime(st.st_mtime))
                    result["files"][fname] = f"{size_mb:.1f} Mo  ({mtime_str})"
                    if st.st_mtime > newest_mtime:
                        newest_mtime = st.st_mtime
                    found += 1
                except OSError:
                    pass

        if found >= 2:
            days_old = (time.time() - newest_mtime) / 86400
            result["status"] = "OK" if days_old < 7 else "OUTDATED"

        if newest_mtime > 0:
            result["last_update"] = time.strftime('%Y-%m-%d %H:%M:%S',
                                                  time.localtime(newest_mtime))
        return result

    # ── Avast license ──────────────────────────────────────────────────────────

    def get_avast_license_status(self) -> str:
        if os.path.exists(AVAST_LICENSE_PATH):
            mtime = os.path.getmtime(AVAST_LICENSE_PATH)
            date_str = time.strftime('%Y-%m-%d', time.localtime(mtime))
            return f"Importée ({date_str})"

        avast_bin = self.get_avast_binary()
        if avast_bin:
            rc, out, err = _run([avast_bin, "status"], timeout=10)
            combined = (out + err).lower()
            if "license" in combined:
                return out.strip() or "voir sortie avast"
        return "Aucune licence trouvée"

    def find_avast_licenses_on_usb(self) -> List[str]:
        """Return all license.avastlic paths found at USB mount-point roots."""
        found: List[str] = []
        for mount in self._get_usb_mount_points():
            candidate = os.path.join(mount, "license.avastlic")
            if os.path.exists(candidate):
                found.append(candidate)
        return found

    def import_avast_license(self, license_path: str) -> Tuple[bool, str]:
        avast_bin = self.get_avast_binary()

        # Try avast applylicense first
        if avast_bin:
            rc, out, err = _run([avast_bin, "applylicense", license_path],
                                timeout=30)
            if rc == 0:
                log_info(f"Avast licence appliquée via CLI : {license_path}")
                return True, "Licence Avast appliquée avec succès."

        # Fallback: plain file copy
        try:
            os.makedirs(AVAST_LICENSE_DIR, exist_ok=True)
            shutil.copy2(license_path, AVAST_LICENSE_PATH)
            os.chmod(AVAST_LICENSE_PATH, 0o644)
            log_info(f"Licence Avast copiée vers {AVAST_LICENSE_PATH}")
            return True, f"Licence copiée vers {AVAST_LICENSE_PATH}."
        except Exception as e:
            log_error(f"Échec copie licence Avast : {e}")
            return False, f"Impossible de copier la licence : {e}"

    # ── Online database updates ────────────────────────────────────────────────

    def update_clamav_online(self,
                             progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        """Run freshclam and stream output to progress_cb."""
        if not self.is_freshclam_available():
            return False, "freshclam introuvable. Installez clamav-freshclam."
        try:
            proc = subprocess.Popen(
                ["freshclam", "--stdout"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            lines: List[str] = []
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    lines.append(line)
                    if progress_cb:
                        progress_cb(line)
            proc.wait()

            if proc.returncode in (0, 1):   # 1 = already up-to-date
                return True, "Base ClamAV mise à jour avec succès."
            return False, f"freshclam a quitté avec le code {proc.returncode}."
        except Exception as e:
            return False, f"Échec de la mise à jour : {e}"

    def update_avast_online(self,
                            progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        """Trigger Avast VPS update."""
        avast_bin = self.get_avast_binary()
        if not avast_bin:
            return False, "Avast non trouvé."

        # Try 'avast update'
        try:
            proc = subprocess.Popen(
                [avast_bin, "update"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip()
                if line and progress_cb:
                    progress_cb(line)
            proc.wait()
            if proc.returncode == 0:
                return True, "Base Avast mise à jour avec succès."
            # fall through to systemctl restart
        except Exception:
            pass

        # Fallback: restart the avast daemon
        rc, _, err = _run(["systemctl", "restart", "avast"], timeout=60)
        if rc == 0:
            return True, "Service Avast redémarré (mise à jour appliquée)."
        return False, f"Impossible de mettre à jour Avast : {err}"

    # ── Offline USB database import ────────────────────────────────────────────

    def find_clamav_db_on_usb(self) -> List[str]:
        """Return ClamAV .cvd / .cld files found on any USB drive."""
        found: List[str] = []
        for mount in self._get_usb_mount_points():
            for ext in ("*.cvd", "*.cld"):
                found += glob.glob(os.path.join(mount, ext))
                found += glob.glob(os.path.join(mount, "**", ext), recursive=True)
        return list(set(found))

    def import_clamav_db_from_usb(
            self,
            db_files: List[str],
            progress_cb: ProgressCB = None) -> Tuple[bool, str]:

        try:
            os.makedirs(CLAMAV_DB_DIR, exist_ok=True)
            imported: List[str] = []

            for src in db_files:
                fname = os.path.basename(src)
                dst = os.path.join(CLAMAV_DB_DIR, fname)
                if progress_cb:
                    progress_cb(f"Copie de {fname} …")
                shutil.copy2(src, dst)
                os.chmod(dst, 0o644)
                imported.append(fname)
                log_info(f"DB ClamAV importée : {fname}")

            # Fix ownership
            _run(["chown", "clamav:clamav"] +
                 [os.path.join(CLAMAV_DB_DIR, f) for f in imported])

            # Reload daemon
            _run(["systemctl", "reload", "clamav-daemon"], timeout=15)
            _run(["systemctl", "reload", "clamav-freshclam"], timeout=15)

            return True, (f"{len(imported)} fichier(s) importé(s) : "
                          f"{', '.join(imported)}")
        except Exception as e:
            log_error(f"Import DB ClamAV : {e}")
            return False, f"Échec de l'import : {e}"

    def find_avast_vps_on_usb(self) -> List[str]:
        """Return Avast VPS/update files found on any USB drive."""
        found: List[str] = []
        patterns = ("*.vps", "vps*.zip", "avast_vps*", "*.vpz")
        for mount in self._get_usb_mount_points():
            for pat in patterns:
                found += glob.glob(os.path.join(mount, pat))
                found += glob.glob(os.path.join(mount, "**", pat),
                                   recursive=True)
        return list(set(found))

    def import_avast_vps_from_usb(
            self,
            vps_file: str,
            progress_cb: ProgressCB = None) -> Tuple[bool, str]:

        try:
            os.makedirs(AVAST_VPS_DIR, exist_ok=True)
            fname = os.path.basename(vps_file)
            dst = os.path.join(AVAST_VPS_DIR, fname)
            if progress_cb:
                progress_cb(f"Copie de {fname} …")
            shutil.copy2(vps_file, dst)
            log_info(f"VPS Avast copié : {dst}")

            avast_bin = self.get_avast_binary()
            if avast_bin:
                rc, _, _ = _run([avast_bin, "vpsupdate", dst], timeout=120)
                if rc == 0:
                    return True, "Mise à jour VPS Avast appliquée avec succès."

            _run(["systemctl", "restart", "avast"], timeout=60)
            return True, (f"{fname} copié. Service Avast redémarré pour "
                          "appliquer la mise à jour.")
        except Exception as e:
            log_error(f"Import VPS Avast : {e}")
            return False, f"Échec de l'import VPS : {e}"

    # ── Scan command builders ──────────────────────────────────────────────────

    def build_scan_command(self,
                           targets: List[str],
                           remove_infected: bool = False) -> List[str]:
        if self.current_engine == "clamav":
            cmd = ["clamscan", "--recursive", "--verbose", "--stdout"]
            if remove_infected:
                cmd.append("--remove")
        else:
            avast_bin = self.get_avast_binary() or "avast"
            cmd = [avast_bin, "scan", "-r"]
            if remove_infected:
                cmd += ["-a", "remove"]

        cmd.extend(targets)
        return cmd

    def parse_avast_line(self, line: str) -> Optional[Dict]:
        """
        Parse one line of Avast scan output.
        Returns dict with keys 'type' ('threat'|'ok'|'stat') and 'value'.
        Returns None if the line is not interesting.
        """
        # Avast outputs: "/path/to/file\tVirus-name [L]  0" on threat
        if "\t" in line:
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1].strip():
                return {"type": "threat", "value": line.strip()}
        if line.strip().startswith("/") and line.strip().endswith("[+]"):
            return {"type": "ok", "value": line.strip()}
        return None

    # ── USB mount-point discovery ──────────────────────────────────────────────

    def _get_usb_mount_points(self) -> List[str]:
        """Return a deduplicated list of active USB/removable mount points."""
        mounts: List[str] = []
        skip_fs = {"tmpfs", "devtmpfs", "sysfs", "proc",
                   "devpts", "cgroup", "cgroup2", "pstore",
                   "efivarfs", "debugfs", "tracefs", "fusectl",
                   "securityfs", "hugetlbfs", "mqueue", "bpf",
                   "configfs", "autofs"}
        skip_roots = {"/", "/boot", "/boot/efi", "/home",
                      "/var", "/tmp", "/usr", "/opt", "/srv"}

        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    device, mount_point, fstype = parts[0], parts[1], parts[2]

                    if not device.startswith("/dev/"):
                        continue
                    if fstype in skip_fs:
                        continue
                    if mount_point in skip_roots:
                        continue

                    in_media = ("/media" in mount_point or
                                "/mnt" in mount_point or
                                "/run/media" in mount_point)
                    is_removable = any(
                        f"/dev/sd{c}" in device for c in "bcdefghij"
                    )

                    if in_media or is_removable:
                        if mount_point not in mounts:
                            mounts.append(mount_point)
        except Exception as e:
            log_error(f"Lecture /proc/mounts : {e}")

        # Also check lsblk for USB transport
        try:
            rc, out, _ = _run(
                ["lsblk", "-o", "TRAN,MOUNTPOINT", "-J"], timeout=10
            )
            if rc == 0:
                data = json.loads(out)
                for dev in data.get("blockdevices", []):
                    self._collect_usb_mounts(dev, mounts)
        except Exception:
            pass

        return mounts

    def _collect_usb_mounts(self, node: Dict, acc: List[str]) -> None:
        if node.get("tran") == "usb" or node.get("tran") is None:
            mp = node.get("mountpoint") or ""
            if mp and mp not in acc:
                acc.append(mp)
        for child in node.get("children", []):
            self._collect_usb_mounts(child, acc)

    def get_usb_devices(self) -> List[Dict]:
        """Return list of USB block-device info dicts from lsblk."""
        try:
            rc, out, _ = _run(
                ["lsblk", "-o", "NAME,SIZE,TRAN,MOUNTPOINT,LABEL", "-J"],
                timeout=10
            )
            if rc == 0:
                data = json.loads(out)
                return [d for d in data.get("blockdevices", [])
                        if d.get("tran") == "usb"]
        except Exception:
            pass
        return []


# ══════════════════════════════════════════════════════════════════════════════
class UsbMountManager:
    """
    Détecte, monte et démonte les clés USB et disques amovibles.

    Chaque périphérique USB est représenté par un dict :
        {
          "device":     "/dev/sdb1"   – partition ou disque entier,
          "parent":     "/dev/sdb"    – disque parent,
          "label":      "SANDISK"     – étiquette de volume (peut être vide),
          "size":       "14.9G",
          "fstype":     "vfat",
          "mountpoint": "/mnt/usb_sdb1"  ou None si non monté,
          "managed":    True           – True si monté par nous,
        }
    """

    # Répertoire de base pour nos points de montage
    MOUNT_BASE = "/mnt/avscan_usb"

    def __init__(self) -> None:
        # {device_path: mount_point}  – garde trace des montages qu'on gère
        self._managed: Dict[str, str] = {}

    # ── énumération ──────────────────────────────────────────────────────────

    def list_usb_partitions(self) -> List[Dict]:
        """
        Retourne la liste de toutes les partitions USB disponibles
        (montées ou non) avec leurs informations.
        """
        partitions: List[Dict] = []

        try:
            rc, out, err = _run(
                ["lsblk", "-J", "-o",
                 "NAME,SIZE,TRAN,FSTYPE,MOUNTPOINT,LABEL,TYPE,HOTPLUG"],
                timeout=10
            )
            if rc != 0:
                log_error(f"lsblk failed: {err}")
                return []

            data = json.loads(out)

            for disk in data.get("blockdevices", []):
                tran    = disk.get("tran", "") or ""
                hotplug = str(disk.get("hotplug", "0"))

                # On garde les disques USB ou hotplug (SD cards, etc.)
                if tran != "usb" and hotplug != "1":
                    continue

                parent_dev = f"/dev/{disk['name']}"

                # Partitions enfants
                children = disk.get("children", [])
                if children:
                    for child in children:
                        if child.get("type") not in ("part", "lvm"):
                            continue
                        partitions.append(
                            self._build_entry(child, parent_dev)
                        )
                else:
                    # Disque sans table de partition (FAT32 direct, etc.)
                    if disk.get("fstype"):
                        partitions.append(
                            self._build_entry(disk, parent_dev)
                        )

        except json.JSONDecodeError as e:
            log_error(f"Parsing lsblk JSON : {e}")
        except Exception as e:
            log_error(f"list_usb_partitions : {e}")

        return partitions

    def _build_entry(self, node: Dict, parent: str) -> Dict:
        dev = f"/dev/{node['name']}"
        mp  = node.get("mountpoint") or self._managed.get(dev)
        return {
            "device":     dev,
            "parent":     parent,
            "label":      node.get("label") or "",
            "size":       node.get("size") or "?",
            "fstype":     node.get("fstype") or "inconnu",
            "mountpoint": mp,
            "managed":    dev in self._managed,
        }

    # ── montage ───────────────────────────────────────────────────────────────

    def mount(self, device: str,
              progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        """
        Monte le périphérique en lecture seule dans MOUNT_BASE/<device_name>.
        Retourne (succès, message).
        """
        # Déjà monté ?
        current_mp = self._get_current_mountpoint(device)
        if current_mp:
            return True, f"Déjà monté sur {current_mp}"

        dev_name = device.replace("/dev/", "").replace("/", "_")
        mount_point = os.path.join(self.MOUNT_BASE, dev_name)

        try:
            os.makedirs(mount_point, exist_ok=True)
        except OSError as e:
            return False, f"Impossible de créer le point de montage : {e}"

        if progress_cb:
            progress_cb(f"Montage de {device} → {mount_point} …")

        # Détecte le système de fichiers
        fstype = self._detect_fstype(device)
        extra_opts: List[str] = []
        if fstype in ("vfat", "exfat", "ntfs", "ntfs3"):
            extra_opts = ["-t", fstype]

        rc, out, err = _run(
            ["mount", "-o", "ro"] + extra_opts + [device, mount_point],
            timeout=30
        )

        if rc == 0:
            self._managed[device] = mount_point
            log_info(f"USB monté : {device} → {mount_point}")
            return True, f"{device} monté en lecture seule sur {mount_point}"
        else:
            # Nettoie le répertoire vide
            try:
                os.rmdir(mount_point)
            except OSError:
                pass
            err_clean = err.strip() or out.strip()
            log_error(f"Échec montage {device} : {err_clean}")
            return False, f"Échec du montage : {err_clean}"

    # ── démontage ────────────────────────────────────────────────────────────

    def umount(self, device: str,
               progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        """
        Démonte le périphérique.
        Retourne (succès, message).
        """
        mp = self._managed.get(device) or self._get_current_mountpoint(device)
        if not mp:
            return False, f"{device} n'est pas monté."

        if progress_cb:
            progress_cb(f"Démontage de {device} ({mp}) …")

        # Tentative normale
        rc, _, err = _run(["umount", mp], timeout=20)
        if rc != 0:
            # Essai forcé
            rc, _, err = _run(["umount", "-f", mp], timeout=20)

        if rc == 0:
            self._managed.pop(device, None)
            # Supprime le répertoire si c'est un des nôtres
            if mp.startswith(self.MOUNT_BASE):
                try:
                    os.rmdir(mp)
                except OSError:
                    pass
            log_info(f"USB démonté : {device}")
            return True, f"{device} démonté avec succès."
        else:
            log_error(f"Échec démontage {device} : {err.strip()}")
            return False, (f"Impossible de démonter {device} : {err.strip()}\n"
                           "Des fichiers sont peut-être encore en cours d'accès.")

    def umount_all_managed(self) -> None:
        """Démonte tous les périphériques gérés (appelé à la fermeture)."""
        for dev in list(self._managed.keys()):
            self.umount(dev)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _get_current_mountpoint(self, device: str) -> Optional[str]:
        """Retourne le point de montage actuel du périphérique, ou None."""
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == device:
                        return parts[1]
        except Exception:
            pass
        return None

    def _detect_fstype(self, device: str) -> str:
        """Détecte le système de fichiers via blkid."""
        rc, out, _ = _run(
            ["blkid", "-o", "value", "-s", "TYPE", device], timeout=10
        )
        if rc == 0 and out.strip():
            return out.strip()
        return ""

    def get_mountpoint(self, device: str) -> Optional[str]:
        """Retourne le point de montage actuel (géré ou externe)."""
        return self._managed.get(device) or self._get_current_mountpoint(device)