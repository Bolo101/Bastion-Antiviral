#!/usr/bin/env python3
"""
bastion_update.py – Mise à jour HORS-LIGNE des bases depuis <clé USB>/bastion.

Parcourt TOUT le dossier « bastion » et n'installe, base par base, que ce qui
est plus récent que sur la borne. Une base en erreur (ex. Avast sans licence)
est sautée : le traitement continue avec les suivantes.

Arborescence attendue (produite par make_bastion.sh) :

    bastion/
      MANIFEST.tsv            dates (epoch UTC) + sha256 de chaque fichier
      clamav/                 main.cvd  daily.cvd|daily.cld  bytecode.cvd
      clamav-thirdparty/      *.ndb *.hdb *.ldb *.ign2 …   (signatures tierces)
      avast/                  fichier VPS (*.vps, *.vpz, vps*.zip, avast_vps*)
      yara/signature-base/    *.yar *.yara                 (jeu complet)
      yara/custom/            *.yar *.yara                 (règles manuelles)

Critère « plus récent » :
  ClamAV officiel     numéro de version lu dans l'en-tête du .cvd/.cld
  Tierces / custom    contenu différent ET date du manifeste > date du fichier
  Avast VPS, YARA     date du manifeste > date de la base installée sur la borne
(les dates du manifeste sont des epoch UTC : pas de décalage de fuseau FAT).

Procédures d'installation = celles de db_manager.py (mêmes répertoires, droits,
propriétaire clamav:clamav, `avast vpsupdate`, rechargement de clamd).

Usage :
  bastion_update.py --bastion /chemin/bastion            installe
  bastion_update.py --bastion /chemin/bastion --check    compare seulement
                    [--json] [--only clamav,thirdparty,avast,yara]

Codes retour : 0 = terminé sans échec · 2 = bastion introuvable ·
               3 = terminé avec au moins un échec · 1 = erreur d'usage/système
"""

import argparse
import fcntl
import fnmatch
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (                                              # noqa: E402
    AVAST_BIN_PATHS, AVAST_LICENSE_PATH, AVAST_VPS_DIR, CLAMAV_DB_DIR,
    STATE_DIR, YARA_CUSTOM_SUBDIR, YARA_RULES_DIR, YARA_SIGBASE_SUBDIR,
)

try:
    from log_handler import log_error, log_info, log_warning      # noqa: E402
except Exception:                                                 # noqa: BLE001
    def log_info(*_a, **_k): pass                                 # type: ignore
    def log_warning(*_a, **_k): pass                              # type: ignore
    def log_error(*_a, **_k): pass                                # type: ignore

# ── Constantes (alignées sur db_manager.py) ───────────────────────────────────
THIRD_PARTY_EXTS = frozenset([
    ".ndb", ".ndu", ".hdb", ".hdu", ".hsb", ".hsu", ".mdb", ".mdu", ".msb",
    ".msu", ".ldb", ".ldu", ".cdb", ".db", ".ftm", ".fp", ".sfp", ".ign",
    ".ign2", ".pdb", ".wdb", ".gdb", ".crb",
])
AVAST_VPS_PATTERNS = ("*.vps", "vps*.zip", "avast_vps*", "*.vpz")
YARA_EXTS = (".yar", ".yara")
YARA_EXTERNALS = {"filename": "", "filepath": "", "extension": "",
                  "filetype": "", "owner": ""}
CLAM_ERR_WORDS = ("Error loading", "Can't load", "Invalid", "Corrupt",
                  "corrupt", "Can't open", "Malformed", "malformed")
OFFICIAL_ORDER = ("main", "daily", "bytecode")
MAX_FILE_BYTES = 2 * 1024 ** 3
MANIFEST_NAME = "MANIFEST.tsv"
KNOWN_TOP = {"clamav", "clamav-thirdparty", "avast", "yara", MANIFEST_NAME}

# Statuts d'une ligne du comparatif
TODO, OK, UPTODATE, SKIP, FAILED, PARTIAL = (
    "TODO", "OK", "UPTODATE", "SKIP", "FAILED", "PARTIAL")


# ══════════════════════════════════════════════════════════════════════════════
# Structures et utilitaires
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Row:
    group: str
    name: str
    borne: str = "—"
    cle: str = "—"
    status: str = UPTODATE
    detail: str = ""


@dataclass
class MEntry:
    epoch: int
    sha: str
    extra: str


@dataclass
class Change:
    dst: str
    backup: Optional[str]
    row: Row


def run(cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "délai dépassé"
    except FileNotFoundError:
        return -2, "", f"commande introuvable : {cmd[0]}"
    except Exception as exc:                                      # noqa: BLE001
        return -3, "", str(exc)


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fmt_time(epoch: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(epoch))


def list_regular(dirpath: str, exts: Tuple[str, ...] = (),
                 patterns: Tuple[str, ...] = ()) -> List[str]:
    """Fichiers ordinaires du répertoire (sans lien symbolique, ni caché, ni
    énorme). Les « ._x » de macOS et autres fichiers cachés sont ignorés."""
    out: List[str] = []
    try:
        names = sorted(os.listdir(dirpath))
    except OSError:
        return out
    for name in names:
        if name.startswith("."):
            continue
        full = os.path.join(dirpath, name)
        try:
            st = os.lstat(full)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
            continue
        low = name.lower()
        if exts and not low.endswith(tuple(exts)):
            continue
        if patterns and not any(fnmatch.fnmatch(low, p) for p in patterns):
            continue
        out.append(name)
    return out


def cvd_header(path: str) -> Optional[Dict]:
    """En-tête ClamAV-VDB:date:version:sigs:flevel:md5:dsig:builder:stime."""
    try:
        with open(path, "rb") as f:
            head = f.read(512)
        parts = head.split(b":")
        if parts[0] != b"ClamAV-VDB" or len(parts) < 4:
            return None
        return {"version": int(parts[2]), "sigs": int(parts[3])}
    except (OSError, ValueError):
        return None


def installed_clam_version(name: str) -> Optional[int]:
    best: Optional[int] = None
    for ext in (".cvd", ".cld"):
        hdr = cvd_header(os.path.join(CLAMAV_DB_DIR, name + ext))
        if hdr and (best is None or hdr["version"] > best):
            best = hdr["version"]
    return best


def find_avast_bin() -> Optional[str]:
    found = shutil.which("avast")
    if found:
        return found
    for p in AVAST_BIN_PATHS:
        if os.path.exists(p):
            return p
    return None


def avast_state() -> Tuple[bool, bool]:
    """(installé, licencié) — via ScanEngine comme le reste de l'application,
    avec repli sur de simples tests de fichiers."""
    installed = licensed = None
    try:
        from scanner import ScanEngine                            # noqa: WPS433
        eng = ScanEngine()
        installed = bool(eng.is_avast_installed())
        licensed = bool(eng.is_avast_licensed())
    except Exception:                                             # noqa: BLE001
        pass
    if installed is None:
        installed = find_avast_bin() is not None
    if licensed is None:
        licensed = os.path.exists(AVAST_LICENSE_PATH)
    return installed, licensed


def clam_loads_ok(db_path: str) -> Tuple[bool, str]:
    """clamscan charge-t-il cette base (fichier ou répertoire) sans erreur ?"""
    if not shutil.which("clamscan"):
        return True, "clamscan absent : chargement non vérifié"
    fd, probe = tempfile.mkstemp(prefix="bastion_probe_")
    os.close(fd)
    try:
        rc, out, err = run(["clamscan", "--no-summary",
                            f"--database={db_path}", probe], timeout=900)
    finally:
        try:
            os.unlink(probe)
        except OSError:
            pass
    combined = out + err
    if rc == 2 and ("error" in combined.lower()
                    or any(w in combined for w in CLAM_ERR_WORDS)):
        lines = [l.strip() for l in combined.splitlines() if l.strip()]
        bad = [l for l in lines if "rror" in l or "Can't" in l] or lines
        return False, (bad[-1] if bad else "erreur de chargement")[:160]
    return True, ""


def sigtool_verify(path: str) -> Tuple[bool, str]:
    st = shutil.which("sigtool")
    if not st:
        return True, "sigtool absent : signature non vérifiée"
    rc, out, err = run([st, "--info", path], timeout=600)
    if rc == 0 and "Verification OK" in out + err:
        return True, ""
    return False, "signature numérique invalide ou fichier corrompu"


def looks_valid_content(path: str) -> bool:
    """Rejette vide / page HTML / HTTP / JSON (même test que db_manager)."""
    try:
        with open(path, "rb") as f:
            head = f.read(64)
        if not head:
            return False
        h = head[:16]
        return not (h.startswith(b"<") or h.startswith(b"HTTP/")
                    or h.startswith(b'{"'))
    except OSError:
        return False


def yara_checker():
    """Fonction de validation de syntaxe si le module python yara existe."""
    try:
        import yara                                               # noqa: WPS433
    except Exception:                                             # noqa: BLE001
        return None

    def _check(path: str) -> Tuple[bool, str]:
        try:
            yara.compile(filepath=path, externals=YARA_EXTERNALS)
            return True, ""
        except Exception as exc:                                  # noqa: BLE001
            return False, str(exc).splitlines()[0][:140]
    return _check


# ══════════════════════════════════════════════════════════════════════════════
class Updater:
    def __init__(self, bastion: str, check: bool, as_json: bool,
                 only: Optional[set]) -> None:
        self.bastion = bastion
        self.check = check
        self.json = as_json
        self.only = only
        self.rows: List[Row] = []
        self.manifest: Dict[str, MEntry] = {}
        self.meta: Dict[str, str] = {}
        self.stage: Optional[str] = None
        self.clam_changes: List[Change] = []
        self.warnings = 0

    # ── sortie ────────────────────────────────────────────────────────────────
    def say(self, msg: str = "") -> None:
        if not self.json:
            print(msg, flush=True)

    def warn(self, msg: str) -> None:
        self.warnings += 1
        log_warning(f"bastion: {msg}")
        self.say(f"[ATTENTION] {msg}")

    def wanted(self, key: str) -> bool:
        return self.only is None or key in self.only

    def add(self, row: Row) -> Row:
        self.rows.append(row)
        return row

    def join(self, *p: str) -> str:
        return os.path.join(self.bastion, *p)

    # ── manifeste ─────────────────────────────────────────────────────────────
    def load_manifest(self) -> None:
        path = self.join(MANIFEST_NAME)
        if not os.path.isfile(path):
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if line.startswith("#"):
                        for tok in line.lstrip("# ").split():
                            if "=" in tok:
                                k, v = tok.split("=", 1)
                                self.meta[k] = v
                        continue
                    cols = line.split("\t")
                    if len(cols) >= 4 and cols[2].isdigit():
                        self.manifest[cols[1]] = MEntry(
                            int(cols[2]), cols[3],
                            cols[4] if len(cols) > 4 else "")
        except OSError as exc:
            self.warn(f"manifeste illisible ({exc}) : dates lues sur les fichiers")

    def epoch(self, rel: str, path: str) -> int:
        e = self.manifest.get(rel)
        if e:
            return e.epoch
        try:
            return int(os.path.getmtime(path))
        except OSError:
            return 0

    # ── zone de travail ───────────────────────────────────────────────────────
    def stage_copy(self, src: str, rel: str) -> str:
        """Copie la source en local (même nom, donc même extension), contrôle
        l'espace disque et l'empreinte du manifeste. Lève ValueError si KO."""
        assert self.stage
        size = os.path.getsize(src)
        free = shutil.disk_usage(self.stage).free
        if free < size * 2 + (16 << 20):
            raise ValueError("espace disque insuffisant")
        dst = os.path.join(self.stage, os.path.basename(src))
        shutil.copyfile(src, dst)
        e = self.manifest.get(rel)
        if e and e.sha and sha256_of(dst) != e.sha:
            os.unlink(dst)
            raise ValueError("empreinte sha256 différente du manifeste (fichier corrompu)")
        return dst

    def install_tracked(self, staged: str, dst: str, row: Row,
                        owner: Optional[str], track: bool) -> None:
        """Installation atomique, avec sauvegarde si track=True (retour arrière)."""
        backup = None
        if track and os.path.exists(dst):
            assert self.stage
            backup = os.path.join(self.stage, "backup_" + str(len(self.clam_changes))
                                  + "_" + os.path.basename(dst))
            shutil.copyfile(dst, backup)
        d = os.path.dirname(dst)
        os.makedirs(d, exist_ok=True)
        tmp = os.path.join(d, "." + os.path.basename(dst) + ".bastion-tmp")
        try:
            shutil.copyfile(staged, tmp)
            os.chmod(tmp, 0o644)
            if owner:
                try:
                    shutil.chown(tmp, user=owner, group=owner)
                except (LookupError, OSError):
                    self.warn(f"chown {owner} impossible sur {os.path.basename(dst)}")
            os.replace(tmp, dst)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        if track:
            self.clam_changes.append(Change(dst, backup, row))

    def rollback_clam(self, why: str) -> None:
        for ch in reversed(self.clam_changes):
            try:
                if ch.backup and os.path.exists(ch.backup):
                    shutil.copyfile(ch.backup, ch.dst)
                elif os.path.exists(ch.dst):
                    os.unlink(ch.dst)
            except OSError as exc:
                self.warn(f"retour arrière impossible pour {os.path.basename(ch.dst)} : {exc}")
            ch.row.status = FAILED
            ch.row.detail = f"retour arrière : {why}"
        self.clam_changes = []

    # ══════════════════════════════════════════════════════════════════════════
    # ClamAV officiel
    # ══════════════════════════════════════════════════════════════════════════
    def do_clamav(self) -> None:
        d = self.join("clamav")
        self.say("── ClamAV (bases officielles) ──")
        if not os.path.isdir(d):
            self.say("[IGNORÉ] dossier clamav/ absent du bastion")
            return
        best: Dict[str, Tuple[int, str]] = {}
        for fn in list_regular(d, exts=(".cvd", ".cld")):
            hdr = cvd_header(os.path.join(d, fn))
            name = fn.rsplit(".", 1)[0]
            if not hdr:
                r = self.add(Row("clamav", fn, status=FAILED,
                                 detail="en-tête ClamAV invalide"))
                self.say(f"[ERREUR] {fn} : en-tête ClamAV invalide — ignoré")
                continue
            if name not in best or hdr["version"] > best[name][0]:
                best[name] = (hdr["version"], fn)
        if not best and not any(r.group == "clamav" for r in self.rows):
            self.say("[IGNORÉ] aucun .cvd/.cld dans clamav/")
        order = [n for n in OFFICIAL_ORDER if n in best] + \
                sorted(n for n in best if n not in OFFICIAL_ORDER)
        for name in order:
            ver, fn = best[name]
            cur = installed_clam_version(name)
            row = self.add(Row("clamav", f"{name}", borne="absente" if cur is None
                               else f"v{cur}", cle=f"v{ver}"))
            if cur is not None and ver <= cur:
                row.status = UPTODATE
                row.detail = "borne plus récente" if ver < cur else ""
                self.say(f"[À JOUR] {name} : v{cur} sur la borne"
                         + (f" (clé v{ver}, plus ancienne)" if ver < cur else ""))
                continue
            row.status = TODO
            if self.check:
                self.say(f"[À INSTALLER] {name} : {row.borne} → v{ver}")
                continue
            self.install_clam_official(name, fn, ver, row)

    def install_clam_official(self, name: str, fn: str, ver: int, row: Row) -> None:
        rel = f"clamav/{fn}"
        n_changes = len(self.clam_changes)
        try:
            staged = self.stage_copy(self.join("clamav", fn), rel)
            if fn.lower().endswith(".cvd"):
                ok, msg = sigtool_verify(staged)
                if not ok:
                    raise ValueError(msg)
                if msg:
                    self.warn(f"{name} : {msg}")
            ok, msg = clam_loads_ok(staged)
            if not ok:
                raise ValueError(f"ClamAV refuse cette base : {msg}")
            if msg:
                self.warn(f"{name} : {msg}")
            dst = os.path.join(CLAMAV_DB_DIR, fn)
            self.install_tracked(staged, dst, row, "clamav", True)
            # Un .cld plus ancien du même nom ne doit pas masquer le .cvd
            if fn.lower().endswith(".cvd"):
                old_cld = os.path.join(CLAMAV_DB_DIR, name + ".cld")
                hdr = cvd_header(old_cld)
                if hdr and hdr["version"] < ver:
                    backup = os.path.join(self.stage, f"backup_cld_{name}.cld")  # type: ignore[arg-type]
                    shutil.copyfile(old_cld, backup)
                    os.unlink(old_cld)
                    self.clam_changes.append(Change(old_cld, backup, row))
            row.status = OK
            row.detail = f"installée (v{ver})"
            log_info(f"bastion: ClamAV {fn} installé (v{ver})")
            self.say(f"[OK] {name} : {row.borne} → v{ver}")
        except Exception as exc:                                  # noqa: BLE001
            # annule uniquement ce fichier
            for ch in reversed(self.clam_changes[n_changes:]):
                try:
                    if ch.backup:
                        shutil.copyfile(ch.backup, ch.dst)
                    elif os.path.exists(ch.dst):
                        os.unlink(ch.dst)
                except OSError:
                    pass
            del self.clam_changes[n_changes:]
            row.status = FAILED
            row.detail = str(exc)
            log_error(f"bastion: ClamAV {fn} : {exc}")
            self.say(f"[ERREUR] {name} : {exc} — base ignorée")

    # ══════════════════════════════════════════════════════════════════════════
    # Fichiers « un par un » (signatures tierces ClamAV, règles YARA custom)
    # ══════════════════════════════════════════════════════════════════════════
    def file_state(self, rel: str, src: str, dst: str) -> Tuple[str, str]:
        if not os.path.exists(dst):
            return TODO, "nouveau"
        try:
            if sha256_of(src) == sha256_of(dst):
                return UPTODATE, "identique"
            if self.epoch(rel, src) > int(os.path.getmtime(dst)):
                return TODO, "plus récent sur la clé"
        except OSError as exc:
            return TODO, f"comparaison impossible ({exc})"
        return UPTODATE, "borne plus récente"

    def do_fileset(self, group: str, title: str, subdir: str, dst_dir: str,
                   exts: Tuple[str, ...], owner: Optional[str], track: bool,
                   validate) -> None:
        d = self.join(*subdir.split("/"))
        self.say(f"── {title} ──")
        if not os.path.isdir(d):
            self.say(f"[IGNORÉ] dossier {subdir}/ absent du bastion")
            return
        files = list_regular(d, exts=exts)
        if group == "thirdparty":
            files = [f for f in files if os.path.splitext(f)[1].lower()
                     in THIRD_PARTY_EXTS]
        if not files:
            self.say(f"[IGNORÉ] aucun fichier reconnu dans {subdir}/")
            return
        todo: List[Tuple[str, str]] = []
        n_same = 0
        for fn in files:
            state, why = self.file_state(f"{subdir}/{fn}", os.path.join(d, fn),
                                         os.path.join(dst_dir, fn))
            if state == TODO:
                todo.append((fn, why))
            else:
                n_same += 1
        row = self.add(Row(group, title, borne=f"{n_same} à jour",
                           cle=f"{len(files)} fichier(s)"))
        if not todo:
            row.status = UPTODATE
            self.say(f"[À JOUR] {len(files)} fichier(s), aucun changement")
            return
        row.status = TODO
        row.detail = f"{len(todo)} à installer"
        if self.check:
            for fn, why in todo[:12]:
                self.say(f"[À INSTALLER] {fn} ({why})")
            if len(todo) > 12:
                self.say(f"[À INSTALLER] … et {len(todo) - 12} autre(s)")
            self.say(f"[À JOUR] {n_same} fichier(s) déjà à jour")
            return
        done, failed = [], []
        verbose = len(todo) <= 15
        for fn, why in todo:
            rel = f"{subdir}/{fn}"
            n_changes = len(self.clam_changes)
            try:
                staged = self.stage_copy(os.path.join(d, fn), rel)
                ok, msg = validate(staged, rel)
                if not ok:
                    raise ValueError(msg)
                self.install_tracked(staged, os.path.join(dst_dir, fn), row,
                                     owner, track)
                done.append(fn)
                if verbose:
                    self.say(f"[OK] {fn} ({why})")
                elif len(done) % 10 == 0:
                    self.say(f"… {len(done)}/{len(todo)} fichiers installés")
            except Exception as exc:                              # noqa: BLE001
                del self.clam_changes[n_changes:]
                failed.append(fn)
                log_warning(f"bastion: {group} {fn} : {exc}")
                self.say(f"[ERREUR] {fn} : {exc} — ignoré")
        if not verbose and done:
            self.say(f"[OK] {len(done)} fichier(s) installé(s)")
        self.say(f"[À JOUR] {n_same} fichier(s) déjà à jour")
        if failed and not done:
            row.status, row.detail = FAILED, f"{len(failed)} fichier(s) en échec"
        elif failed:
            row.status = PARTIAL
            row.detail = f"{len(done)} installé(s), {len(failed)} en échec"
        else:
            row.status, row.detail = OK, f"{len(done)} installé(s)"

    def validate_thirdparty(self, staged: str, rel: str) -> Tuple[bool, str]:
        e = self.manifest.get(rel)
        try:
            min_bytes = int(e.extra) if e and e.extra.isdigit() else 64
        except ValueError:
            min_bytes = 64
        size = os.path.getsize(staged)
        if size < min_bytes or not looks_valid_content(staged):
            return False, f"contenu invalide ({size} o)"
        ok, msg = clam_loads_ok(staged)
        if not ok:
            return False, f"ClamAV refuse ce fichier : {msg}"
        return True, ""

    def do_thirdparty(self) -> None:
        self.do_fileset("thirdparty", "Signatures tierces ClamAV",
                        "clamav-thirdparty", CLAMAV_DB_DIR,
                        tuple(sorted(THIRD_PARTY_EXTS)), "clamav", True,
                        self.validate_thirdparty)

    def do_yara_custom(self) -> None:
        checker = None if self.check else yara_checker()

        def _validate(staged: str, rel: str) -> Tuple[bool, str]:
            if not looks_valid_content(staged):
                return False, "contenu invalide"
            if checker:
                ok, msg = checker(staged)
                if not ok:
                    return False, f"règle YARA invalide : {msg}"
            return True, ""

        self.do_fileset("yara-custom", "Règles YARA personnalisées",
                        "yara/custom",
                        os.path.join(YARA_RULES_DIR, YARA_CUSTOM_SUBDIR),
                        YARA_EXTS, None, False, _validate)

    # ── finalisation ClamAV : test global, rechargement du démon ─────────────
    def finalize_clamav(self) -> None:
        if not self.clam_changes:
            return
        ok, msg = clam_loads_ok(CLAMAV_DB_DIR)
        if not ok:
            self.say(f"[ERREUR] le jeu complet de bases ne se charge plus ({msg})")
            self.rollback_clam("conflit de chargement ClamAV")
            return
        if msg:
            self.warn(msg)
        rc, out, _ = run(["systemctl", "is-active", "clamav-daemon"], timeout=10)
        if rc == 0 and out.strip() == "active":
            self.say("Rechargement du démon ClamAV…")
            rc2, _, err2 = run(["systemctl", "reload", "clamav-daemon"], timeout=60)
            if rc2 != 0:
                self.warn(f"rechargement clamd impossible : {err2.strip()[:100]}")

    # ══════════════════════════════════════════════════════════════════════════
    # Avast VPS
    # ══════════════════════════════════════════════════════════════════════════
    def do_avast(self) -> None:
        d = self.join("avast")
        self.say("── Avast (base VPS) ──")
        if not os.path.isdir(d):
            self.say("[IGNORÉ] dossier avast/ absent du bastion")
            return
        cands = list_regular(d, patterns=AVAST_VPS_PATTERNS)
        if not cands:
            self.add(Row("avast", "VPS", status=SKIP, detail="aucun fichier VPS dans le bastion"))
            self.say("[IGNORÉ] aucun fichier VPS dans avast/")
            return
        fn = max(cands, key=lambda f: self.epoch(f"avast/{f}", os.path.join(d, f)))
        src = os.path.join(d, fn)
        cle_epoch = self.epoch(f"avast/{fn}", src)
        row = self.add(Row("avast", "VPS", cle=fmt_time(cle_epoch)))
        installed, licensed = avast_state()
        if not installed:
            row.status, row.detail = SKIP, "Avast non installé — base ignorée"
            self.say("[IGNORÉ] Avast non installé — base Avast ignorée")
            return
        if not licensed:
            row.status, row.detail = SKIP, "licence Avast absente — base ignorée"
            self.say("[IGNORÉ] licence Avast absente — base Avast ignorée")
            return
        newest = 0
        try:
            for f in os.listdir(AVAST_VPS_DIR):
                try:
                    newest = max(newest, int(os.path.getmtime(os.path.join(AVAST_VPS_DIR, f))))
                except OSError:
                    pass
        except OSError:
            pass
        row.borne = fmt_time(newest) if newest else "absente"
        if newest and cle_epoch <= newest:
            row.status = UPTODATE
            self.say(f"[À JOUR] VPS : borne {row.borne}, clé {row.cle}")
            return
        row.status = TODO
        if self.check:
            self.say(f"[À INSTALLER] VPS {fn} : {row.borne} → {row.cle}")
            return
        dst = os.path.join(AVAST_VPS_DIR, fn)
        try:
            staged = self.stage_copy(src, f"avast/{fn}")
            self.install_tracked(staged, dst, row, None, False)
            avast = find_avast_bin()
            rc = -2
            if avast:
                rc, _, err = run([avast, "vpsupdate", dst], timeout=300)
            if rc == 0:
                row.status, row.detail = OK, "installée (avast vpsupdate)"
                self.say(f"[OK] VPS {fn} installé (avast vpsupdate)")
            else:
                self.warn(f"avast vpsupdate indisponible ou échoué (code {rc}) : "
                          "redémarrage du service Avast")
                rc2, _, err2 = run(["systemctl", "restart", "avast"], timeout=120)
                if rc2 != 0:
                    raise ValueError(f"vpsupdate et redémarrage Avast en échec "
                                     f"({err2.strip()[:100]})")
                row.status = OK
                row.detail = "copiée, service redémarré (à vérifier)"
                self.say(f"[OK] VPS {fn} copié, service Avast redémarré")
            log_info(f"bastion: VPS Avast {fn} installé")
        except Exception as exc:                                  # noqa: BLE001
            if os.path.exists(dst):
                try:
                    os.unlink(dst)       # sinon sa date ferait croire à « à jour »
                except OSError:
                    pass
            row.status, row.detail = FAILED, str(exc)
            log_error(f"bastion: VPS Avast : {exc}")
            self.say(f"[ERREUR] Avast VPS : {exc} — base ignorée")

    # ══════════════════════════════════════════════════════════════════════════
    # YARA signature-base (jeu complet, remplacé d'un bloc)
    # ══════════════════════════════════════════════════════════════════════════
    def do_yara(self) -> None:
        sig = self.join("yara", "signature-base")
        self.say("── YARA (signature-base) ──")
        if not os.path.isdir(sig):
            self.say("[IGNORÉ] dossier yara/signature-base/ absent du bastion")
            return
        files = list_regular(sig, exts=YARA_EXTS)
        if not files:
            self.add(Row("yara", "signature-base", status=SKIP,
                         detail="aucune règle dans le bastion"))
            self.say("[IGNORÉ] aucune règle .yar/.yara dans yara/signature-base/")
            return
        expected = sorted(os.path.basename(r) for r in self.manifest
                          if r.startswith("yara/signature-base/"))
        cle_epoch = max(self.epoch(f"yara/signature-base/{f}", os.path.join(sig, f))
                        for f in files)
        row = self.add(Row("yara", "signature-base", cle=f"{len(files)} règles, "
                           + fmt_time(cle_epoch)))
        missing = [f for f in expected if f not in files]
        if missing:
            row.status = FAILED
            row.detail = f"jeu incomplet ({len(missing)} fichier(s) manquant(s))"
            self.say(f"[ERREUR] jeu YARA incomplet : {len(missing)} fichier(s) "
                     "listé(s) au manifeste mais absent(s) — base ignorée")
            return
        dst_dir = os.path.join(YARA_RULES_DIR, YARA_SIGBASE_SUBDIR)
        cur = [f for f in (os.listdir(dst_dir) if os.path.isdir(dst_dir) else [])
               if f.lower().endswith(YARA_EXTS) and not f.startswith(".")]
        borne_epoch = 0
        for f in cur:
            try:
                borne_epoch = max(borne_epoch, int(os.path.getmtime(os.path.join(dst_dir, f))))
            except OSError:
                pass
        row.borne = f"{len(cur)} règles, {fmt_time(borne_epoch)}" if cur else "absentes"
        if cur and cle_epoch <= borne_epoch:
            row.status = UPTODATE
            self.say(f"[À JOUR] {len(cur)} règles sur la borne ({fmt_time(borne_epoch)})")
            return
        row.status = TODO
        if self.check:
            self.say(f"[À INSTALLER] signature-base : {row.borne} → {row.cle}")
            return
        self.install_yara_set(sig, files, dst_dir, row)

    def install_yara_set(self, sig: str, files: List[str], dst_dir: str,
                         row: Row) -> None:
        assert self.stage
        new_dir = dst_dir + ".bastion-new"
        old_dir = dst_dir + ".bastion-old"
        try:
            for p in (new_dir, old_dir):
                if os.path.isdir(p):
                    shutil.rmtree(p)
            os.makedirs(new_dir)
            checker = yara_checker()
            n, bad = 0, []
            for fn in files:
                try:
                    staged = self.stage_copy(os.path.join(sig, fn),
                                             f"yara/signature-base/{fn}")
                except ValueError as exc:
                    raise ValueError(f"{fn} : {exc}")
                if not looks_valid_content(staged):
                    bad.append(fn)
                    continue
                if checker:
                    ok, msg = checker(staged)
                    if not ok:
                        bad.append(fn)
                        self.warn(f"règle ignorée {fn} : {msg}")
                        os.unlink(staged)
                        continue
                shutil.copyfile(staged, os.path.join(new_dir, fn))
                os.chmod(os.path.join(new_dir, fn), 0o644)
                os.unlink(staged)
                n += 1
            if n == 0:
                raise ValueError("aucune règle valide")
            os.chmod(new_dir, 0o755)
            if os.path.isdir(dst_dir):
                os.rename(dst_dir, old_dir)
            try:
                os.rename(new_dir, dst_dir)
            except OSError:
                if os.path.isdir(old_dir):
                    os.rename(old_dir, dst_dir)
                raise
            if os.path.isdir(old_dir):
                shutil.rmtree(old_dir, ignore_errors=True)
            row.status = PARTIAL if bad else OK
            row.detail = (f"{n} règles installées, {len(bad)} ignorée(s)"
                          if bad else f"{n} règles installées")
            log_info(f"bastion: YARA signature-base : {n} règles")
            self.say(f"[OK] signature-base : {n} règles installées dans {dst_dir}")
        except Exception as exc:                                  # noqa: BLE001
            shutil.rmtree(new_dir, ignore_errors=True)
            row.status, row.detail = FAILED, str(exc)
            log_error(f"bastion: YARA signature-base : {exc}")
            self.say(f"[ERREUR] YARA signature-base : {exc} — base ignorée")

    # ══════════════════════════════════════════════════════════════════════════
    def run(self) -> int:
        if not os.path.isdir(self.bastion):
            self.say(f"[ERREUR] dossier introuvable : {self.bastion}")
            if self.json:
                print(json.dumps({"error": f"dossier introuvable : {self.bastion}"},
                                 ensure_ascii=False))
            return 2
        self.load_manifest()
        gen = self.meta.get("generated_epoch")
        self.say(f"Bastion : {self.bastion}")
        self.say("Manifeste : " + (
            f"généré le {fmt_time(int(gen))}" if gen and gen.isdigit()
            else "absent — dates lues sur les fichiers"))
        extra = sorted(n for n in os.listdir(self.bastion)
                       if n not in KNOWN_TOP and not n.startswith("."))
        if extra:
            self.say("Éléments non reconnus (ignorés) : " + ", ".join(extra))
        self.say("Mode : " + ("comparaison seule (aucune modification)"
                              if self.check else "installation"))
        self.say()

        if not self.check:
            os.makedirs(STATE_DIR, exist_ok=True)
            self.stage = tempfile.mkdtemp(prefix="bastion_", dir=STATE_DIR)
        try:
            steps = [("clamav", self.do_clamav), ("thirdparty", self.do_thirdparty),
                     ("avast", self.do_avast), ("yara", self.do_yara),
                     ("yara", self.do_yara_custom)]
            for key, fn in steps:
                if self.wanted(key):
                    try:
                        fn()
                    except Exception as exc:                      # noqa: BLE001
                        # Garde-fou : une base ne doit jamais arrêter les autres
                        self.add(Row(key, key, status=FAILED, detail=str(exc)))
                        log_error(f"bastion: {key} : {exc}")
                        self.say(f"[ERREUR] {key} : {exc} — base ignorée")
                # Après les bases ClamAV (officielles + tierces) : test global
                # du jeu complet, retour arrière si besoin, rechargement de clamd
                if key == "thirdparty" and not self.check:
                    try:
                        self.finalize_clamav()
                    except Exception as exc:                      # noqa: BLE001
                        self.warn(f"finalisation ClamAV : {exc}")
                if self.wanted(key):
                    self.say()
        finally:
            if self.stage:
                shutil.rmtree(self.stage, ignore_errors=True)
        return self.report()

    def report(self) -> int:
        c = {s: sum(1 for r in self.rows if r.status == s)
             for s in (TODO, OK, UPTODATE, SKIP, FAILED, PARTIAL)}
        failed = c[FAILED] + c[PARTIAL]
        if self.json:
            print(json.dumps({
                "bastion": self.bastion, "check": self.check,
                "generated_epoch": self.meta.get("generated_epoch"),
                "summary": c,
                "rows": [r.__dict__ for r in self.rows],
            }, ensure_ascii=False))
            return 3 if (failed and not self.check) else 0
        self.say("══ Récapitulatif ══")
        for r in self.rows:
            tag = {TODO: "À INSTALLER", OK: "OK", UPTODATE: "À JOUR",
                   SKIP: "IGNORÉ", FAILED: "ERREUR", PARTIAL: "ATTENTION"}[r.status]
            self.say(f"[{tag}] {r.group}/{r.name} : {r.detail or r.cle}")
        if self.check:
            self.say(f"{c[TODO]} base(s) à installer · {c[UPTODATE]} à jour · "
                     f"{c[SKIP]} ignorée(s) · {failed} en échec")
        else:
            self.say(f"{c[OK]} installée(s) · {c[UPTODATE]} à jour · "
                     f"{c[SKIP]} ignorée(s) · {failed} en échec")
            log_info(f"bastion: {c}")
        return 3 if (failed and not self.check) else 0


# ══════════════════════════════════════════════════════════════════════════════
def main() -> int:
    ap = argparse.ArgumentParser(description="Mise à jour hors-ligne depuis bastion/")
    ap.add_argument("--bastion", required=True, help="chemin du dossier bastion")
    ap.add_argument("--check", action="store_true",
                    help="compare seulement, sans rien installer")
    ap.add_argument("--json", action="store_true",
                    help="sortie JSON (utile avec --check)")
    ap.add_argument("--only", default="",
                    help="liste séparée par des virgules : clamav,thirdparty,avast,yara")
    args = ap.parse_args()

    only = {s.strip() for s in args.only.split(",") if s.strip()} or None
    if not args.check and os.geteuid() != 0:
        print("[ERREUR] droits root requis pour installer les bases", flush=True)
        return 1

    lock_fh = None
    if not args.check:
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            lock_fh = open(os.path.join(STATE_DIR, "bastion_update.lock"), "w")
            fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("[ERREUR] une mise à jour offline est déjà en cours", flush=True)
            return 1
        except OSError:
            lock_fh = None

    return Updater(os.path.realpath(args.bastion), args.check, args.json, only).run()


if __name__ == "__main__":
    sys.exit(main())