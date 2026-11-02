#!/usr/bin/env python3
"""
export_manager.py – Export de fichiers vers un support externe VALIDÉ.

Appelé uniquement depuis le panneau d'administration (rapports, journaux).
Séquence : vérification de la validation → montage RW durci
(usb_manager.mount_validated_rw) → copie sûre → sync → démontage.
Aucune nouvelle analyse n'est lancée : la validation provient d'une analyse
antérieure (validated_supports.py).

La copie s'exécute en root sur un système de fichiers que l'on ne contrôle pas.
Il pourrait contenir, par exemple, `Rapports_Bastion -> /etc/cron.d`. Chaque étape
utilise donc des descripteurs de répertoire et O_NOFOLLOW : un lien symbolique
sur le support ne peut jamais rediriger une écriture vers le système de la borne.
"""

import hashlib
import os
import re
import secrets
import shutil
import stat
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

from log_handler import log_error, log_info, log_warning
from usb_manager import UsbManager
from validated_supports import identity_of, lookup, set_pair_hash

PAIR_FILE = ".bastion_pair"
_PAIR_RE  = re.compile(r"[0-9a-f]{64}")

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_SAFE_RE   = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class ExportResult:
    ok:      bool
    message: str
    copied:  List[str] = field(default_factory=list)
    failed:  List[str] = field(default_factory=list)


def _clean_name(name: str) -> str:
    name = _SAFE_RE.sub("_", os.path.basename(str(name)))[:100].lstrip(".")
    return name or "fichier"


def _open_subdir(parent_fd: int, name: str) -> int:
    """Ouvre (en le créant au besoin) un sous-répertoire SANS suivre de lien."""
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        os.mkdir(name, 0o755, dir_fd=parent_fd)
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)


def safe_copy_into(mountpoint: str, subdir: str,
                   files: Iterable[Tuple[str, str]]) -> Tuple[List[str], List[str]]:
    """
    Copie [(source, nom_destination)] dans <mountpoint>/<subdir>/.
    Retourne (copiés, échecs). Ne suit aucun lien symbolique du support, n'écrase
    jamais un fichier existant (suffixe _1, _2…).
    """
    copied: List[str] = []
    failed: List[str] = []
    root_fd = os.open(mountpoint, _DIR_FLAGS & ~os.O_NOFOLLOW)   # notre point de montage
    sub_fd: Optional[int] = None
    try:
        try:
            sub_fd = _open_subdir(root_fd, _clean_name(subdir))
        except OSError as e:
            return [], [f"{subdir} : dossier de destination refusé ({e.strerror}) — "
                        "lien symbolique ou fichier de même nom sur le support ?"]

        for src, wanted in files:
            base = _clean_name(wanted)
            stem, dot, ext = base.rpartition(".")
            if not dot:
                stem, ext = base, ""
            out_fd = None
            for i in range(0, 100):
                name = base if i == 0 else f"{stem}_{i}{dot}{ext}"
                try:
                    out_fd = os.open(
                        name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o644, dir_fd=sub_fd)
                    break
                except FileExistsError:
                    continue
                except OSError as e:
                    failed.append(f"{base} : {e.strerror}")
                    break
            if out_fd is None:
                if not any(f.startswith(base) for f in failed):
                    failed.append(f"{base} : trop d'homonymes")
                continue
            try:
                with open(src, "rb") as fin, os.fdopen(out_fd, "wb") as fout:
                    shutil.copyfileobj(fin, fout, 1 << 20)
                    fout.flush()
                    os.fsync(fout.fileno())
                copied.append(name)
            except OSError as e:
                failed.append(f"{base} : {e.strerror or e}")
        os.fsync(sub_fd)
    finally:
        if sub_fd is not None:
            os.close(sub_fd)
        os.close(root_fd)
    return copied, failed


def read_pair_token(mountpoint: str) -> Optional[str]:
    """
    Lit le secret d'appairage d'un support. Le contenu est NON FIABLE : pas de lien
    suivi (O_NOFOLLOW), pas de blocage sur un FIFO (O_NONBLOCK), fichier régulier de
    256 octets au plus, 64 caractères hexadécimaux exactement.
    """
    root_fd = os.open(mountpoint, _DIR_FLAGS & ~os.O_NOFOLLOW)
    try:
        fd = os.open(PAIR_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | os.O_CLOEXEC, dir_fd=root_fd)
    except OSError:
        return None
    finally:
        os.close(root_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 256:
            return None
        data = os.read(fd, 257)
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        token = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    return token if _PAIR_RE.fullmatch(token) else None


def write_pair_token(mountpoint: str) -> Optional[str]:
    """
    Dépose un NOUVEAU secret d'appairage ; retourne le secret, ou None si échec.
    Écrit sous un nom temporaire puis renomme par-dessus : un ancien fichier (cas
    d'un support « oublié » puis ré-analysé), même s'il s'agit d'un lien symbolique
    ou d'un FIFO, est remplacé sans jamais être suivi ni ouvert.
    """
    token = secrets.token_hex(32)
    tmp_name = PAIR_FILE + ".tmp"
    root_fd = os.open(mountpoint, _DIR_FLAGS & ~os.O_NOFOLLOW)
    try:
        try:
            os.unlink(tmp_name, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=root_fd)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(token + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, PAIR_FILE, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
        return token
    except OSError as e:
        log_warning(f"Dépôt du secret d'appairage impossible : {e}")
        return None
    finally:
        os.close(root_fd)


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def export_to_validated_support(usb: UsbManager, device: str,
                                files: List[Tuple[str, str]],
                                subdir: str,
                                allowed_roots: Iterable[str]) -> ExportResult:
    """
    Exporte `files` [(source, nom)] vers `device`, s'il est validé.
    `allowed_roots` : répertoires hors desquels aucune source n'est acceptée.
    """
    roots = [os.path.realpath(r) for r in allowed_roots]
    checked: List[Tuple[str, str]] = []
    for src, name in files:
        real = os.path.realpath(src)
        if not any(real == r or real.startswith(r.rstrip(os.sep) + os.sep) for r in roots):
            log_warning(f"Export : source hors zone autorisée ignorée : {src}")
            continue
        if os.path.isfile(real):
            checked.append((real, name))
    if not checked:
        return ExportResult(False, "Aucun fichier à exporter.")

    # ── Identité + appairage : AVANT tout montage en écriture ────────────────
    part = usb.partition_for(device)
    if part is None:
        return ExportResult(False, f"{device} : support introuvable (retiré ?).")
    identity = identity_of(part)
    record, why = lookup(identity)
    if record is None:
        return ExportResult(False, f"Support non validé : {why}.")
    pair_hash = record.get("pair_hash")
    if pair_hash:
        ok, msg, mp = usb.mount_validated(device, rw=False)
        if not ok or not mp:
            return ExportResult(False, msg)
        try:
            token = read_pair_token(mp)
        finally:
            usb.umount_validated(device)
        if token is None or _sha(token) != pair_hash:
            log_warning(f"Appairage refusé pour {device} : secret absent ou différent.")
            return ExportResult(False, (
                "Support refusé : le secret d'appairage déposé lors du premier export "
                "est absent ou différent (support cloné, remplacé, ou fichier "
                f"« {PAIR_FILE} » supprimé). Utilisez « Oublier le support » puis "
                "analysez-le à nouveau."))

    ok, msg, mp = usb.mount_validated(device, rw=True)
    if not ok or not mp:
        return ExportResult(False, msg)

    copied: List[str] = []
    failed: List[str] = []
    try:
        copied, failed = safe_copy_into(mp, subdir, checked)
        if copied and not pair_hash:                      # premier export : appairer
            token = write_pair_token(mp)
            if token:
                set_pair_hash(identity, _sha(token))
                log_info(f"Support {device} appairé (secret déposé).")
    except Exception as e:                                # noqa: BLE001
        log_error(f"Export vers {device} : {e}")
        failed.append(str(e))
    finally:
        ok_u, msg_u = usb.umount_validated(device)

    if not ok_u:
        failed.append(msg_u)
    log_info(f"EXPORT vers support validé {device} : {len(copied)} copié(s), "
             f"{len(failed)} échec(s) | {copied}")

    if copied and not failed:
        return ExportResult(True, f"{len(copied)} fichier(s) exporté(s) dans "
                                  f"« {subdir} ». {msg_u}", copied, failed)
    if copied:
        return ExportResult(False, f"Export partiel : {len(copied)} copié(s), "
                                   f"{len(failed)} échec(s) : " + " ; ".join(failed[:3]),
                            copied, failed)
    return ExportResult(False, "Export impossible : " + " ; ".join(failed[:3]),
                        copied, failed)