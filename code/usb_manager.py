#!/usr/bin/env python3
"""usb_manager.py – Détection, montage RO/RW et démontage des clés USB."""

import json
import os
import tempfile
import subprocess
from typing import Callable, Dict, List, Optional, Tuple

from config import USB_ALLOWED_FSTYPES, USB_MOUNT_BASE, USB_MOUNT_HARDEN_OPTS
from log_handler import log_error, log_info, log_warning

ProgressCB = Optional[Callable[[str], None]]

# Options appliquées à CHAQUE montage et remontage d'un support non fiable :
# aucun exécutable setuid, aucun fichier périphérique, aucune exécution depuis
# la clé. Elles se cumulent avec ro/rw.
_HARDEN_LIST = [o for o in USB_MOUNT_HARDEN_OPTS.split(",") if o]


_NOSYMFOLLOW: Optional[bool] = None


def _nosymfollow_supported() -> bool:
    """
    `nosymfollow` (noyau ≥ 5.10) : le noyau refuse de suivre tout lien symbolique
    du support. Sans lui, un lien absolu posé sur la clé (`lien -> /etc/shadow`)
    est suivi par tout code qui tourne en root HORS sandbox. Détecté une fois.
    """
    global _NOSYMFOLLOW
    if _NOSYMFOLLOW is None:
        d = tempfile.mkdtemp(prefix="bastion_probe_mnt_")
        try:
            rc, _, _ = _run(["mount", "-t", "tmpfs", "-o", "nosymfollow", "tmpfs", d],
                            timeout=10)
            _NOSYMFOLLOW = (rc == 0)
            if rc == 0:
                _run(["umount", d], timeout=10)
        finally:
            try:
                os.rmdir(d)
            except OSError:
                pass
        if not _NOSYMFOLLOW:
            log_warning("Option de montage nosymfollow non prise en charge : "
                        "les liens symboliques de la clé restent suivis hors sandbox.")
    return _NOSYMFOLLOW


def _harden_list() -> List[str]:
    return _HARDEN_LIST + (["nosymfollow"] if _nosymfollow_supported() else [])


def _mount_opts(mode: str, fstype: str = "") -> str:
    """Options de montage durcies. 'noload' : pas de rejeu du journal ext3/4 en RO
    (le rejeu écrirait sur un support potentiellement piégé et dont on veut
    préserver l'état pour l'analyse)."""
    opts = [mode] + _harden_list()
    if mode == "ro" and fstype in ("ext3", "ext4"):
        opts.append("noload")
    return ",".join(opts)


def _remount_opts(mode: str) -> str:
    return ",".join(["remount", mode] + _harden_list())


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
                 managed: bool, uuid: str = "", serial: str = "",
                 vendor: str = "", model: str = "", size_bytes: int = 0) -> None:
        self.device     = device
        self.parent     = parent
        self.label      = label
        self.size       = size
        self.fstype     = fstype
        self.mountpoint = mountpoint
        self.managed    = managed
        self.uuid       = uuid          # UUID blkid (ex. "1A2B-3C4D" ou UUID ext4)
        # Identité matérielle (voir validated_supports.py)
        self.serial     = serial
        self.vendor     = vendor
        self.model      = model
        self.size_bytes = size_bytes

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
    """Détecte, monte (TOUJOURS en lecture seule) et démonte les périphériques USB.

    Seule exception : mount_validated_rw(), pour l'export depuis l'administration
    vers un support déjà validé."""

    def __init__(self) -> None:
        # {device: mount_point} – montages RO gérés par nous
        self._managed: Dict[str, str] = {}
        # {device: mount_point} – montages RW d'export (supports validés)
        self._managed_rw: Dict[str, str] = {}

    # ── Énumération ───────────────────────────────────────────────────────────

    def list_partitions(self) -> List[UsbPartition]:
        parts: List[UsbPartition] = []
        try:
            rc, out, err = _run(
                ["lsblk", "-J", "-o",
                 "NAME,SIZE,TRAN,FSTYPE,MOUNTPOINT,LABEL,TYPE,HOTPLUG,SERIAL,VENDOR,MODEL"],
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
                            parts.append(self._build(child, parent, disk))
                else:
                    if disk.get("fstype"):
                        parts.append(self._build(disk, parent, disk))

        except json.JSONDecodeError as e:
            log_error(f"Parsing lsblk : {e}")
        except Exception as e:
            log_error(f"list_partitions : {e}")
        return parts

    @staticmethod
    def _size_bytes(name: str) -> int:
        try:
            with open(f"/sys/class/block/{name}/size") as f:
                return int(f.read().strip()) * 512
        except Exception:
            return 0

    def _build(self, node: Dict, parent: str, disk: Optional[Dict] = None) -> UsbPartition:
        disk = disk or node
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
            serial=(disk.get("serial") or "").strip(),
            vendor=(disk.get("vendor") or "").strip(),
            model=(disk.get("model") or "").strip(),
            size_bytes=self._size_bytes(node["name"]),
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

        allowed, fstype, why = self._fs_policy(device)
        if not allowed:
            log_error(why)
            if current_mp:                     # déjà monté par le système : retirer
                _run(["umount", current_mp], timeout=20)
            return False, why

        if current_mp:
            if self._is_ro(device, current_mp):
                if not self._is_hardened(device, current_mp):
                    rc, _, err = _run(["mount", "-o", _remount_opts("ro"), current_mp],
                                      timeout=20)
                    if rc != 0:
                        log_error(f"Durcissement impossible {device} : {err.strip()}")
                        return False, f"Impossible de durcir le montage : {err.strip()}"
                self._managed[device] = current_mp
                uuid = self.get_uuid(device)
                log_info(f"USB déjà monté RO : {device}  UUID={uuid or '?'}  → {current_mp}")
                return True, f"Déjà monté en lecture seule sur {current_mp}"
            # Remontage en lecture seule
            if progress_cb:
                progress_cb(f"Remontage de {device} en lecture seule…")
            rc, _, err = _run(["mount", "-o", _remount_opts("ro"), current_mp],
                              timeout=20)
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

        extra = self._type_args(fstype)

        rc, out, err = _run(["mount", "-o", _mount_opts("ro", fstype)] + extra
                            + [device, mp], timeout=30)
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

    # ── Montage en écriture : UNIQUEMENT un support validé (export admin) ─────
    #
    # Aucun support analysé n'est jamais monté en écriture. La seule exception
    # est l'export de rapports/journaux depuis le panneau d'administration, vers
    # un support dont une analyse antérieure a conclu qu'il était sain
    # (validated_supports.py). L'identité est relue ICI, sur le périphérique
    # réel, et non reprise d'un objet fourni par l'appelant.

    def partition_for(self, device: str) -> Optional[UsbPartition]:
        return next((p for p in self.list_partitions() if p.device == device), None)

    def mount_validated_rw(self, device: str) -> Tuple[bool, str, Optional[str]]:
        return self.mount_validated(device, rw=True)

    def mount_validated(self, device: str, rw: bool = True
                        ) -> Tuple[bool, str, Optional[str]]:
        """
        Monte `device` s'il est VALIDÉ : en lecture seule (vérification du secret
        d'appairage) ou en lecture/écriture (+ sync) pour l'export. Toujours avec
        nosuid,nodev,noexec,nosymfollow. Retourne (ok, message, point_de_montage).
        """
        from validated_supports import identity_of, lookup

        part = self.partition_for(device)
        if part is None:
            return False, f"{device} : support introuvable (retiré ?).", None
        record, why = lookup(identity_of(part))
        if record is None:
            log_warning(f"Montage RW refusé pour {device} : {why}")
            return False, f"Montage en écriture refusé : {why}.", None

        allowed, fstype, why = self._fs_policy(device)
        if not allowed:
            log_error(why)
            return False, why, None

        # Repartir d'un état propre : un montage existant (RO par nous, ou
        # automatique) est retiré avant de remonter avec NOS options.
        cur = self._current_mountpoint(device)
        if cur:
            rc, _, err = _run(["umount", cur], timeout=20)
            if rc != 0:
                return False, f"Impossible de démonter {cur} : {err.strip()}", None
            self._managed.pop(device, None)

        dev_name = device.replace("/dev/", "").replace("/", "_")
        mp = os.path.join(USB_MOUNT_BASE, f"export_{dev_name}")
        os.makedirs(mp, exist_ok=True)

        opts = (_mount_opts("rw", fstype) + ",sync") if rw else _mount_opts("ro", fstype)
        rc, out, err = _run(["mount", "-o", opts] + self._type_args(fstype)
                            + [device, mp], timeout=30)
        if rc == 0:
            self._managed_rw[device] = mp
            log_info(f"Support validé monté {'RW' if rw else 'RO'} : {device} → {mp} "
                     f"(validé le {record.get('validated_at', '?')})")
            return (True, f"{device} monté "
                          f"{'en écriture' if rw else 'en lecture seule'} (support validé).",
                    mp)
        try:
            os.rmdir(mp)
        except OSError:
            pass
        err_clean = err.strip() or out.strip()
        log_error(f"Montage RW échoué {device} : {err_clean}")
        return False, f"Échec du montage RW : {err_clean}", None

    def umount_validated(self, device: str) -> Tuple[bool, str]:
        """Synchronise puis démonte un support monté par mount_validated_rw."""
        mp = self._managed_rw.get(device)
        if not mp:
            return False, f"{device} n'est pas monté en écriture par l'application."
        _run(["sync"], timeout=60)
        rc, _, err = _run(["umount", mp], timeout=30)
        if rc != 0:
            return False, f"Impossible de démonter {device} : {err.strip()}"
        self._managed_rw.pop(device, None)
        try:
            os.rmdir(mp)
        except OSError:
            pass
        log_info(f"Support d'export démonté : {device}")
        return True, f"{device} démonté : vous pouvez le retirer."

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
            self.umount_validated(dev)

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

    def _fs_policy(self, device: str) -> Tuple[bool, str, str]:
        """
        Liste blanche des systèmes de fichiers. Le noyau hôte analyse lui-même
        la structure du support au montage ; chaque pilote supplémentaire est
        une surface d'attaque, et le sandbox ne la couvre pas.
        Retourne (autorisé, type, message).
        """
        fstype = self._detect_fstype(device)
        if not fstype:
            return False, "", (f"{device} : système de fichiers non reconnu — "
                               "montage refusé.")
        if fstype not in USB_ALLOWED_FSTYPES:
            return False, fstype, (
                f"{device} : système de fichiers « {fstype} » non pris en charge "
                f"(autorisés : {', '.join(USB_ALLOWED_FSTYPES)}) — montage refusé.")
        return True, fstype, ""

    @staticmethod
    def _type_args(fstype: str) -> List[str]:
        """Type explicite : empêche le noyau d'essayer d'autres pilotes."""
        return ["-t", fstype] if fstype in USB_ALLOWED_FSTYPES else []

    def _is_hardened(self, device: str, mountpoint: str) -> bool:
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == device and parts[1] == mountpoint:
                        have = set(parts[3].split(","))
                        return set(_harden_list()) <= have
        except Exception:
            pass
        return False

    def _detect_fstype(self, device: str) -> str:
        rc, out, _ = _run(["blkid", "-o", "value", "-s", "TYPE", device], timeout=10)
        return out.strip() if rc == 0 else ""