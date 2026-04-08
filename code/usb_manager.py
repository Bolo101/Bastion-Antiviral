#!/usr/bin/env python3
"""usb_manager.py – Détection, montage RO/RW et démontage des clés USB."""

import json
import os
import subprocess
from typing import Callable, Dict, List, Optional, Tuple

from config import USB_MOUNT_BASE
from log_handler import log_error, log_info, log_warning

ProgressCB = Optional[Callable[[str], None]]


def _run(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
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
class UsbPartition:
    """Représente une partition USB ou un disque amovible."""

    def __init__(self, device: str, parent: str, label: str,
                 size: str, fstype: str, mountpoint: Optional[str],
                 managed: bool, uuid: str = "") -> None:
        self.device     = device
        self.parent     = parent
        self.label      = label
        self.size       = size
        self.fstype     = fstype
        self.mountpoint = mountpoint
        self.managed    = managed
        self.uuid       = uuid          # UUID blkid (ex. "1A2B-3C4D" ou UUID ext4)

    @property
    def display_name(self) -> str:
        label = f" [{self.label}]" if self.label else ""
        return f"{self.device}{label}  {self.size}  {self.fstype}"

    @property
    def short_uuid(self) -> str:
        """UUID tronqué pour affichage compact (max 13 chars)."""
        if not self.uuid:
            return "—"
        return self.uuid if len(self.uuid) <= 13 else self.uuid[:13] + "…"


# ══════════════════════════════════════════════════════════════════════════════
class UsbManager:
    """Détecte, monte (RO/RW) et démonte les périphériques USB."""

    def __init__(self) -> None:
        # {device: mount_point} – montages RO gérés par nous
        self._managed: Dict[str, str] = {}
        # {device: mount_point} – montages RW temporaires (export)
        self._managed_rw: Dict[str, str] = {}

    # ── Énumération ───────────────────────────────────────────────────────────

    def list_partitions(self) -> List[UsbPartition]:
        parts: List[UsbPartition] = []
        try:
            rc, out, err = _run(
                ["lsblk", "-J", "-o",
                 "NAME,SIZE,TRAN,FSTYPE,MOUNTPOINT,LABEL,TYPE,HOTPLUG"],
                timeout=10
            )
            if rc != 0:
                log_error(f"lsblk : {err}")
                return []

            for disk in json.loads(out).get("blockdevices", []):
                tran    = disk.get("tran") or ""
                hotplug = str(disk.get("hotplug", "0"))
                if tran != "usb" and hotplug != "1":
                    continue
                parent = f"/dev/{disk['name']}"
                children = disk.get("children", [])
                if children:
                    for child in children:
                        if child.get("type") in ("part", "lvm"):
                            parts.append(self._build(child, parent))
                else:
                    if disk.get("fstype"):
                        parts.append(self._build(disk, parent))

        except json.JSONDecodeError as e:
            log_error(f"Parsing lsblk : {e}")
        except Exception as e:
            log_error(f"list_partitions : {e}")
        return parts

    def _build(self, node: Dict, parent: str) -> UsbPartition:
        dev = f"/dev/{node['name']}"
        mp  = node.get("mountpoint") or self._managed.get(dev)
        return UsbPartition(
            device=dev, parent=parent,
            label=node.get("label") or "",
            size=node.get("size") or "?",
            fstype=node.get("fstype") or "inconnu",
            mountpoint=mp,
            managed=dev in self._managed,
            uuid=self.get_uuid(dev),
        )

    # ── UUID ──────────────────────────────────────────────────────────────────

    def get_uuid(self, device: str) -> str:
        """
        Retourne l'UUID du périphérique via blkid.
        Retourne une chaîne vide si introuvable.
        """
        rc, out, _ = _run(
            ["blkid", "-s", "UUID", "-o", "value", device],
            timeout=10
        )
        return out.strip() if rc == 0 else ""

    # ── Montage (lecture seule) ───────────────────────────────────────────────

    def mount(self, device: str,
              progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        """
        Monte le périphérique en lecture seule.
        Si déjà monté en RW par le système, le remonte en RO.
        Logue l'UUID du périphérique lors du montage.
        """
        current_mp = self._current_mountpoint(device)

        if current_mp:
            if self._is_ro(device, current_mp):
                self._managed[device] = current_mp
                uuid = self.get_uuid(device)
                log_info(f"USB déjà monté RO : {device}  UUID={uuid or '?'}  → {current_mp}")
                return True, f"Déjà monté en lecture seule sur {current_mp}"
            # Remontage en lecture seule
            if progress_cb:
                progress_cb(f"Remontage de {device} en lecture seule…")
            rc, _, err = _run(["mount", "-o", "remount,ro", current_mp], timeout=20)
            if rc == 0:
                self._managed[device] = current_mp
                uuid = self.get_uuid(device)
                log_info(f"USB remonté RO : {device}  UUID={uuid or '?'}  → {current_mp}")
                return True, f"{device} remonté en lecture seule sur {current_mp}"
            log_error(f"Remontage RO échoué pour {device} : {err.strip()}")
            return False, f"Impossible de remonter en lecture seule : {err.strip()}"

        # Nouveau montage
        dev_name = device.replace("/dev/", "").replace("/", "_")
        mp = os.path.join(USB_MOUNT_BASE, dev_name)
        try:
            os.makedirs(mp, exist_ok=True)
        except OSError as e:
            return False, f"Impossible de créer le point de montage : {e}"

        if progress_cb:
            progress_cb(f"Montage de {device} → {mp} (lecture seule)…")

        fstype = self._detect_fstype(device)
        extra  = ["-t", fstype] if fstype in ("vfat", "exfat", "ntfs", "ntfs3") else []

        rc, out, err = _run(["mount", "-o", "ro"] + extra + [device, mp], timeout=30)
        if rc == 0:
            self._managed[device] = mp
            uuid = self.get_uuid(device)
            log_info(f"USB monté RO : {device}  UUID={uuid or '?'}  → {mp}")
            return True, f"{device} monté en lecture seule sur {mp}"

        try:
            os.rmdir(mp)
        except OSError:
            pass
        err_clean = err.strip() or out.strip()
        log_error(f"Montage échoué {device} : {err_clean}")
        return False, f"Échec du montage : {err_clean}"

    # ── Montage RW temporaire (export de logs) ────────────────────────────────

    def mount_for_export(self, device: str,
                         progress_cb: ProgressCB = None) -> Tuple[bool, str, Optional[str], str]:
        """
        Monte le périphérique en lecture/écriture pour permettre l'export de logs.

        Cas possibles :
          • Non monté            → nouveau montage RW à /mnt/avscan_export_<dev>
          • Déjà monté RW        → utilise le point de montage existant (pas de démontage)
          • Déjà monté RO par nous → remonte en RW temporairement

        Retourne (ok, message, mountpoint, action)
        où action ∈ {"mounted_rw", "remounted_rw", "existing_rw", "error"}
        """
        current_mp = self._current_mountpoint(device)

        # ── Cas 1 : déjà monté RW ─────────────────────────────────────────────
        if current_mp and not self._is_ro(device, current_mp):
            uuid = self.get_uuid(device)
            log_info(f"USB utilisé pour export (déjà RW) : {device}  UUID={uuid or '?'}  → {current_mp}")
            return True, f"Utilisation du montage existant : {current_mp}", current_mp, "existing_rw"

        # ── Cas 2 : déjà monté RO → remontage RW ─────────────────────────────
        if current_mp and self._is_ro(device, current_mp):
            if progress_cb:
                progress_cb(f"Remontage RW temporaire de {device}…")
            rc, _, err = _run(["mount", "-o", "remount,rw", current_mp], timeout=20)
            if rc == 0:
                uuid = self.get_uuid(device)
                log_info(f"USB remonté RW (export) : {device}  UUID={uuid or '?'}  → {current_mp}")
                return True, f"{device} remonté RW pour export.", current_mp, "remounted_rw"
            log_error(f"Remontage RW échoué pour {device} : {err.strip()}")
            return False, f"Impossible de remonter en RW : {err.strip()}", None, "error"

        # ── Cas 3 : non monté → montage RW ───────────────────────────────────
        dev_name = device.replace("/dev/", "").replace("/", "_")
        mp = os.path.join(USB_MOUNT_BASE, f"export_{dev_name}")
        try:
            os.makedirs(mp, exist_ok=True)
        except OSError as e:
            return False, f"Impossible de créer le point de montage : {e}", None, "error"

        if progress_cb:
            progress_cb(f"Montage RW de {device} → {mp}…")

        fstype = self._detect_fstype(device)
        extra  = ["-t", fstype] if fstype in ("vfat", "exfat", "ntfs", "ntfs3") else []

        rc, out, err = _run(["mount", "-o", "rw"] + extra + [device, mp], timeout=30)
        if rc == 0:
            self._managed_rw[device] = mp
            uuid = self.get_uuid(device)
            log_info(f"USB monté RW (export) : {device}  UUID={uuid or '?'}  → {mp}")
            return True, f"{device} monté RW pour export.", mp, "mounted_rw"

        try:
            os.rmdir(mp)
        except OSError:
            pass
        err_clean = err.strip() or out.strip()
        log_error(f"Montage RW échoué {device} : {err_clean}")
        return False, f"Échec du montage RW : {err_clean}", None, "error"

    def restore_after_export(self, device: str, action: str) -> None:
        """
        Restaure l'état du montage après un export de logs.
        - "mounted_rw"   → démonte le point de montage temporaire
        - "remounted_rw" → remet en lecture seule
        - "existing_rw"  → ne fait rien
        """
        if action == "mounted_rw":
            mp = self._managed_rw.pop(device, None)
            if mp:
                _run(["umount", mp], timeout=20)
                try:
                    os.rmdir(mp)
                except OSError:
                    pass
                log_info(f"Démontage export RW : {device}")
        elif action == "remounted_rw":
            mp = self._managed.get(device) or self._current_mountpoint(device)
            if mp:
                _run(["mount", "-o", "remount,ro", mp], timeout=20)
                log_info(f"Remontage RO après export : {device} → {mp}")
        # "existing_rw" ou "error" : rien à faire

    # ── Démontage ─────────────────────────────────────────────────────────────

    def umount(self, device: str,
               progress_cb: ProgressCB = None) -> Tuple[bool, str]:
        mp = self._managed.get(device) or self._current_mountpoint(device)
        if not mp:
            return False, f"{device} n'est pas monté."

        if progress_cb:
            progress_cb(f"Démontage de {device}…")

        rc, _, err = _run(["umount", mp], timeout=20)
        if rc != 0:
            rc, _, err = _run(["umount", "-f", mp], timeout=20)

        if rc == 0:
            self._managed.pop(device, None)
            if mp.startswith(USB_MOUNT_BASE):
                try:
                    os.rmdir(mp)
                except OSError:
                    pass
            log_info(f"USB démonté : {device}")
            return True, f"{device} démonté avec succès."

        log_error(f"Démontage échoué {device} : {err.strip()}")
        return False, f"Impossible de démonter {device} : {err.strip()}"

    def umount_all(self) -> None:
        for dev in list(self._managed):
            self.umount(dev)
        for dev in list(self._managed_rw):
            self.restore_after_export(dev, "mounted_rw")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def get_mountpoint(self, device: str) -> Optional[str]:
        return self._managed.get(device) or self._current_mountpoint(device)

    def get_all_usb_mountpoints(self) -> List[str]:
        """Retourne tous les points de montage USB actifs (pour recherche de fichiers)."""
        mps: List[str] = []
        for p in self.list_partitions():
            mp = self.get_mountpoint(p.device)
            if mp and mp not in mps:
                mps.append(mp)
        return mps

    def _current_mountpoint(self, device: str) -> Optional[str]:
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == device:
                        return parts[1]
        except Exception:
            pass
        return None

    def _is_ro(self, device: str, mountpoint: str) -> bool:
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == device and parts[1] == mountpoint:
                        return "ro" in parts[3].split(",")
        except Exception:
            pass
        return False

    def _detect_fstype(self, device: str) -> str:
        rc, out, _ = _run(["blkid", "-o", "value", "-s", "TYPE", device], timeout=10)
        return out.strip() if rc == 0 else ""