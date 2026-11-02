#!/usr/bin/env python3
"""
reports.py – Rapports d'analyse des supports COMPROMIS, conservés sur la borne.

Règles :
  • un rapport n'est produit que si au moins une menace a été détectée ;
    un support sain ne laisse aucun rapport ;
  • il est écrit dans REPORTS_DIR (répertoire local, droits 700, fichiers 600),
    jamais sur le support analysé qui reste monté en lecture seule ;
  • il n'est consultable, exportable et purgeable que depuis le panneau
    d'administration ;
  • REPORTS_DIR est un répertoire PERMANENT : il survit au redémarrage sur un
    système installé sur disque. En mode live (« nopersistent ») le système de
    fichiers est en RAM et rien ne peut être permanent : storage_status() le
    détecte et l'interface l'affiche.

Le PDF est visualisé avec Evince, lancé SANS les droits root (voir open_in_viewer).
"""

import json
import os
import pwd
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List, Optional, Tuple

from config import (
    REPORTS_DIR,
    REPORTS_MAX_COUNT,
    REPORTS_MAX_TOTAL_MB,
    REPORT_MAX_THREATS_LISTED,
    STATE_DIR,
    VIEWER_BIN,
    VIEWER_USER,
)
from log_handler import (
    log_error, log_info, log_warning, safe_name_part,
    write_device_scan_report_pdf,
)

_NAME_RE = re.compile(
    r"^scan_AV_(\d{8})_(\d{6})_(\d+)menaces_([A-Za-z0-9._-]{1,40})(?:_(\d+))?\.pdf$")


@dataclass
class ReportInfo:
    path:    str
    name:    str
    when:    str      # "AAAA-MM-JJ HH:MM:SS"
    threats: int
    label:   str
    size:    int
    mtime_ns: int = 0
    exported: bool = False     # déjà copié vers un support validé


def _ensure_dir() -> None:
    for d in (STATE_DIR, REPORTS_DIR):
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)


# ══════════════════════════════════════════════════════════════════════════════
def save_compromise_report(device: str, identity: dict, result,
                           clamav_info: dict, yara_info: dict,
                           avast_info: dict, engines_used: dict,
                           sandbox_info: str = "") -> Optional[str]:
    """
    Écrit le rapport d'un support compromis. Retourne son chemin, ou None si le
    support est sain (aucun rapport n'est alors conservé).
    """
    if result is None or result.infected <= 0:
        return None

    _ensure_dir()
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    label = safe_name_part(identity.get("label") or device.replace("/dev/", ""), 40)
    base  = f"scan_AV_{ts}_{result.infected}menaces_{label}"
    fname, n = f"{base}.pdf", 1
    while os.path.exists(os.path.join(REPORTS_DIR, fname)):   # même seconde
        n += 1
        fname = f"{base}_{n}.pdf"

    path = write_device_scan_report_pdf(
        mountpoint=REPORTS_DIR, device=device,
        label=identity.get("label", ""), uuid=identity.get("uuid", ""),
        result=result, clamav_info=clamav_info, yara_info=yara_info,
        avast_info=avast_info, engines_used=engines_used,
        identity=identity, sandbox_info=sandbox_info,
        filename=fname, max_threats=REPORT_MAX_THREATS_LISTED,
    )
    log_info(f"RAPPORT SUPPORT COMPROMIS | chemin={path} | device={device} "
             f"| menaces={result.infected}")
    _rotate(keep=path)
    return path


def _rotate(keep: str = "") -> None:
    """
    Borne le répertoire (nombre ET taille cumulée). On supprime d'abord les
    rapports déjà EXPORTÉS, du plus ancien au plus récent, puis seulement si
    nécessaire les plus anciens non exportés (avec un avertissement). Le rapport
    qu'on vient d'écrire (`keep`) n'est jamais supprimé.
    """
    reps = list_reports()                                 # du plus récent au plus ancien
    count = len(reps)
    total = sum(r.size for r in reps)
    max_bytes = REPORTS_MAX_TOTAL_MB * 1024 * 1024
    oldest_first = list(reversed(reps))
    order = ([r for r in oldest_first if r.exported]
             + [r for r in oldest_first if not r.exported])
    for r in order:
        if count <= REPORTS_MAX_COUNT and total <= max_bytes:
            break
        if keep and os.path.realpath(r.path) == os.path.realpath(keep):
            continue
        try:
            os.remove(r.path)
        except OSError:
            continue
        count -= 1
        total -= r.size
        (log_info if r.exported else log_warning)(
            f"Rapport supprimé par rotation ({'déjà exporté' if r.exported else 'NON exporté'}"
            f", limites {REPORTS_MAX_COUNT} rapports / {REPORTS_MAX_TOTAL_MB} Mo) : {r.name}")


def list_reports() -> List[ReportInfo]:
    """Rapports présents, du plus récent au plus ancien."""
    out: List[ReportInfo] = []
    exported = _load_exported()
    try:
        names = os.listdir(REPORTS_DIR)
    except FileNotFoundError:
        return out
    for name in names:
        m = _NAME_RE.match(name)
        if not m:
            continue
        path = os.path.join(REPORTS_DIR, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not os.path.isfile(path) or os.path.islink(path):
            continue
        d, t = m.group(1), m.group(2)
        out.append(ReportInfo(
            path=path, name=name,
            when=f"{d[:4]}-{d[4:6]}-{d[6:]} {t[:2]}:{t[2:4]}:{t[4:]}",
            threats=int(m.group(3)), label=m.group(4), size=st.st_size,
            mtime_ns=st.st_mtime_ns, exported=name in exported))
    # Chronologique (le nom seul est ambigu au sein d'une même seconde)
    out.sort(key=lambda r: (r.when, r.mtime_ns, r.name), reverse=True)
    return out


# ── Suivi des exports : en mode live les rapports sont en RAM ────────────────

def _exported_path() -> str:
    return os.path.join(STATE_DIR, "exported_reports.json")


def _load_exported() -> set:
    try:
        with open(_exported_path(), encoding="utf-8") as f:
            data = json.load(f)
        return {str(x) for x in data} if isinstance(data, list) else set()
    except Exception:                                     # noqa: BLE001
        return set()


def mark_exported(paths: List[str]) -> None:
    """Note que ces rapports ont été copiés vers un support validé."""
    names = _load_exported() | {os.path.basename(p) for p in paths}
    _ensure_dir()
    tmp = _exported_path() + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(sorted(names), f)
    os.replace(tmp, _exported_path())


def unexported_reports() -> List[ReportInfo]:
    """Rapports pas encore exportés vers un support externe."""
    return [r for r in list_reports() if not r.exported]


def purge_reports() -> Tuple[int, List[str]]:
    """
    Vide le répertoire des rapports (action de l'administrateur). Retourne
    (nombre de fichiers supprimés, erreurs). Aucun lien symbolique n'est suivi :
    seul le lien lui-même est supprimé. Remet aussi à zéro le suivi des exports.
    """
    _ensure_dir()
    removed, errors = 0, []
    fd = os.open(REPORTS_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in os.listdir(fd):
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    errors.append(f"{name} : dossier non supprimé")
                    continue
                os.unlink(name, dir_fd=fd)
                removed += 1
            except OSError as e:
                errors.append(f"{name} : {e.strerror}")
    finally:
        os.close(fd)
    try:
        os.unlink(_exported_path())
    except FileNotFoundError:
        pass
    except OSError as e:
        errors.append(f"suivi des exports : {e.strerror}")
    log_warning(f"PURGE du répertoire des rapports par l'administrateur : "
                f"{removed} fichier(s) supprimé(s), {len(errors)} erreur(s).")
    return removed, errors


# ── Le stockage est-il PERMANENT ? ────────────────────────────────────────────
# Sur un système installé sur disque, oui. En mode live (« nopersistent »), le
# système de fichiers est en RAM (overlay/tmpfs) : les rapports disparaissent à
# l'extinction. On le détecte au lieu de le supposer.

_PERSISTENT_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs"}


def _unescape_mountinfo(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def classify_storage(target: str, mountinfo_text: str) -> Tuple[bool, str]:
    """
    (permanent ?, description) pour `target`, d'après le contenu de
    /proc/self/mountinfo : permanent seulement si le système de fichiers qui le
    contient est un système de fichiers de disque, monté depuis un périphérique bloc.
    """
    best = None
    for line in mountinfo_text.splitlines():
        left, sep, right = line.partition(" - ")
        lf, rf = left.split(), right.split()
        if not sep or len(lf) < 5 or len(rf) < 2:
            continue
        mp = _unescape_mountinfo(lf[4])
        inside = (mp == "/" or target == mp
                  or target.startswith(mp.rstrip("/") + "/"))
        if inside and (best is None or len(mp) >= len(best[0])):
            best = (mp, rf[0], _unescape_mountinfo(rf[1]))
    if best is None:
        return False, "système de fichiers inconnu"
    _mp, fstype, source = best
    persistent = fstype in _PERSISTENT_FS and source.startswith("/dev/")
    return persistent, f"{fstype} sur {source}"


def storage_status() -> Tuple[bool, str]:
    """(permanent ?, description) pour REPORTS_DIR."""
    target = os.path.realpath(REPORTS_DIR)
    while not os.path.exists(target) and target != "/":
        target = os.path.dirname(target)
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as f:
            return classify_storage(target, f.read())
    except OSError:
        return False, "état du stockage illisible"


def resolve_report(path: str) -> Optional[str]:
    """Chemin réel d'un rapport SI c'est bien un de nos rapports (anti-traversée)."""
    try:
        real = os.path.realpath(path)
        root = os.path.realpath(REPORTS_DIR)
    except OSError:
        return None
    if os.path.dirname(real) != root or not _NAME_RE.match(os.path.basename(real)):
        return None
    return real if os.path.isfile(real) else None


def delete_report(path: str) -> Tuple[bool, str]:
    real = resolve_report(path)
    if not real:
        return False, "Rapport introuvable ou chemin non autorisé."
    try:
        os.remove(real)
        log_info(f"Rapport supprimé par l'administrateur : {os.path.basename(real)}")
        return True, "Rapport supprimé."
    except OSError as e:
        return False, f"Suppression impossible : {e}"


# ══════════════════════════════════════════════════════════════════════════════
# Visualisation avec Evince — sans droits root
# ══════════════════════════════════════════════════════════════════════════════

_VIEWERS: List[subprocess.Popen] = []
_viewers_lock = threading.Lock()


def viewer_running() -> bool:
    with _viewers_lock:
        return any(p.poll() is None for p in _VIEWERS)


def purge_stale_viewer_copies() -> int:
    """
    Supprime les copies temporaires de rapports laissées par une visionneuse
    interrompue (plantage, arrêt brutal) : elles sont lisibles par le compte
    de la visionneuse et ne doivent pas survivre. Sans effet tant qu'une
    visionneuse est ouverte.
    """
    if viewer_running():
        return 0
    n = 0
    tmp = tempfile.gettempdir()
    try:
        names = os.listdir(tmp)
    except OSError:
        return 0
    for name in names:
        path = os.path.join(tmp, name)
        if name.startswith("bastion_report_view_") and os.path.isdir(path) \
                and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
            n += 1
    if n:
        log_warning(f"{n} copie(s) temporaire(s) de rapport orpheline(s) supprimée(s).")
    return n


def close_viewers() -> int:
    """Ferme les visionneuses ouvertes (SIGTERM puis SIGKILL). Retourne leur nombre."""
    with _viewers_lock:
        procs = [p for p in _VIEWERS if p.poll() is None]
    for p in procs:
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    deadline = time.time() + 2.0
    for p in procs:
        while p.poll() is None and time.time() < deadline:
            time.sleep(0.05)
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    return len(procs)


def _viewer_account() -> Optional[pwd.struct_passwd]:
    for name in (VIEWER_USER, os.environ.get("SUDO_USER", "")):
        if name and name != "root":
            try:
                return pwd.getpwnam(name)
            except KeyError:
                continue
    return None


def open_in_viewer(path: str,
                   on_exit: Optional[Callable[[], None]] = None) -> Tuple[bool, str]:
    """
    Ouvre un rapport avec Evince.

    L'application tourne en root : Evince est lancé sous le compte non privilégié
    VIEWER_USER, sur une COPIE temporaire du rapport (le répertoire des rapports
    reste inaccessible à ce compte). La copie est supprimée à la fermeture.
    `on_exit` est appelé (thread secondaire) quand Evince se ferme.
    """
    real = resolve_report(path)
    if not real:
        return False, "Rapport introuvable ou chemin non autorisé."
    viewer = shutil.which(VIEWER_BIN)
    if not viewer:
        return False, (f"« {VIEWER_BIN} » n'est pas installé "
                       f"(apt install {VIEWER_BIN}).")

    kw: dict = {}
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin",
           "LANG": os.environ.get("LANG", "C.UTF-8")}
    for k in ("DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        if k in os.environ:
            env[k] = os.environ[k]

    acct = None
    if os.geteuid() == 0:
        acct = _viewer_account()
        if acct is None:
            return False, (f"Compte « {VIEWER_USER} » introuvable : par sécurité, "
                           "Evince n'est pas lancé en root.")
        env.update(HOME=acct.pw_dir, USER=acct.pw_name, LOGNAME=acct.pw_name)
        env.setdefault("XAUTHORITY", os.path.join(acct.pw_dir, ".Xauthority"))
        kw = dict(user=acct.pw_uid, group=acct.pw_gid, extra_groups=[])

    purge_stale_viewer_copies()
    tmpdir = tempfile.mkdtemp(prefix="bastion_report_view_")
    try:
        os.chmod(tmpdir, 0o755)
        copy = os.path.join(tmpdir, os.path.basename(real))
        shutil.copyfile(real, copy)
        os.chmod(copy, 0o644)
        proc = subprocess.Popen(
            [viewer, copy], env=env, cwd=acct.pw_dir if acct else "/",
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True, **kw)
    except Exception as e:                                # noqa: BLE001
        shutil.rmtree(tmpdir, ignore_errors=True)
        log_error(f"Lancement de {VIEWER_BIN} impossible : {e}")
        return False, f"Impossible de lancer {VIEWER_BIN} : {e}"

    with _viewers_lock:
        _VIEWERS.append(proc)

    def _wait() -> None:
        proc.wait()
        with _viewers_lock:
            if proc in _VIEWERS:
                _VIEWERS.remove(proc)
        shutil.rmtree(tmpdir, ignore_errors=True)
        if on_exit:
            try:
                on_exit()
            except Exception:                             # noqa: BLE001
                pass

    threading.Thread(target=_wait, daemon=True).start()
    log_info(f"Rapport ouvert avec {VIEWER_BIN} "
             f"(utilisateur {acct.pw_name if acct else 'courant'}) : "
             f"{os.path.basename(real)}")
    return True, f"{os.path.basename(real)} ouvert dans {VIEWER_BIN}."