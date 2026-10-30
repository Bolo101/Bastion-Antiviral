#!/usr/bin/env python3
"""
sandbox.py – Isolation de chaque analyse dans un conteneur éphémère (bubblewrap).

Chaque moteur (ClamAV, Avast, YARA) lancé par scanner.py est exécuté dans son
propre sandbox, créé pour l'analyse puis détruit à la fin :

  • namespaces : mount, pid, ipc, uts, cgroup, NET (aucun accès réseau)
  • racine      : tmpfs vide, puis en LECTURE SEULE ; seuls /usr, les
                  bibliothèques, les bases de signatures et les règles sont montés
  • cible       : le support analysé est monté en LECTURE SEULE, au même chemin
                  que sur l'hôte (aucune traduction de chemin dans l'UI)
  • /tmp, /dev  : tmpfs / dev minimal, éphémères
  • privilèges  : toutes les capabilities supprimées SAUF CAP_DAC_READ_SEARCH
                  (lecture de tous les fichiers de la clé, quel que soit leur
                  propriétaire — sinon un fichier 600 d'un autre UID échapperait
                  à l'analyse), no_new_privs, nouvelle session, env vidé
  • seccomp     : filtre généré (python3-seccomp) qui interdit notamment
                  open_by_handle_at (évasion classique liée à CAP_DAC_READ_SEARCH),
                  ptrace, mount, bpf, io_uring, keyctl, kexec, userns imbriqués…
  • cycle de vie: --die-with-parent → le sandbox meurt avec son parent

Deux modes (SANDBOX_MODE = "auto" choisit le premier qui passe l'auto-test) :
  • "idmap" : user namespace « identité » (userns_exec.py) : les capabilities
              n'existent que DANS ce namespace → confinement maximal.
  • "root"  : sans user namespace, pour les noyaux qui les interdisent ;
              root réel mais réduit à CAP_DAC_READ_SEARCH + seccomp.

Limite (voir README) : le montage du système de fichiers de la clé est fait par
le noyau hôte (usb_manager.py : liste blanche de FS, nosuid/nodev/noexec) et
n'est pas couvert par ce module.
"""

import errno
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import threading
from typing import Dict, Iterable, List, Optional, Sequence

from config import (
    SANDBOX_ENABLED,
    SANDBOX_REQUIRED,
    SANDBOX_BWRAP_BIN,
    SANDBOX_TMPFS_SIZE_MB,
    SANDBOX_MODE,
    SANDBOX_USE_SECCOMP,
)
from log_handler import log_error, log_info, log_warning


class SandboxUnavailable(RuntimeError):
    """Le sandbox est requis mais ne peut pas être créé sur ce système."""


_HERE = os.path.dirname(os.path.abspath(__file__))
_USERNS_HELPER = os.path.join(_HERE, "userns_exec.py")

# Chemins qu'une cible d'analyse n'a jamais le droit de désigner
_FORBIDDEN_TARGETS = {
    "/", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/sys",
    "/dev", "/run", "/var", "/root", "/home", "/boot", "/opt", "/tmp",
}

_SYSTEM_DIRS = ("bin", "sbin", "lib", "lib32", "lib64", "libx32")
_ETC_FILES = (
    "ld.so.cache", "ld.so.conf", "ld.so.conf.d", "passwd", "group",
    "nsswitch.conf", "localtime",
)

CLONE_NEWUSER = 0x10000000

# Appels système refusés (EPERM). Ceux inconnus de l'architecture sont ignorés.
_DENY_SYSCALLS = (
    # contournement des namespaces / lecture hors du montage (CAP_DAC_READ_SEARCH)
    "open_by_handle_at", "name_to_handle_at",
    # manipulation des montages / racine
    "mount", "umount", "umount2", "pivot_root", "chroot", "move_mount",
    "open_tree", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
    # namespaces
    "unshare", "setns",
    # inspection / injection dans d'autres processus
    "ptrace", "process_vm_readv", "process_vm_writev", "kcmp",
    # noyau
    "kexec_load", "kexec_file_load", "init_module", "finit_module",
    "delete_module", "bpf", "perf_event_open", "userfaultfd", "lookup_dcookie",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    # trousseau de clés, horloge, système
    "keyctl", "add_key", "request_key", "reboot", "swapon", "swapoff",
    "settimeofday", "clock_settime", "clock_adjtime", "adjtimex", "acct",
    "quotactl", "syslog", "sethostname", "setdomainname", "iopl", "ioperm",
)


def _build_seccomp_bpf() -> Optional[bytes]:
    """Génère le filtre seccomp (BPF) via libseccomp. None si indisponible."""
    if not SANDBOX_USE_SECCOMP:
        return None
    try:
        import seccomp                                    # type: ignore
    except ImportError:
        return None
    try:
        f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
        for name in _DENY_SYSCALLS:
            try:
                f.add_rule(seccomp.ERRNO(errno.EPERM), name)
            except (RuntimeError, OSError, ValueError):
                pass                                      # syscall inconnu ici
        # clone3 ne permet pas d'inspecter ses flags : ENOSYS → glibc retombe sur clone
        try:
            f.add_rule(seccomp.ERRNO(errno.ENOSYS), "clone3")
        except (RuntimeError, OSError, ValueError):
            pass
        # clone(CLONE_NEWUSER) interdit
        f.add_rule(seccomp.ERRNO(errno.EPERM), "clone",
                   seccomp.Arg(0, seccomp.MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
        with tempfile.TemporaryFile() as tmp:
            f.export_bpf(tmp)
            tmp.seek(0)
            return tmp.read()
    except Exception as e:                                # noqa: BLE001
        log_warning(f"Génération du filtre seccomp impossible : {e}")
        return None


class Sandbox:
    """Fabrique de commandes sandboxées. Une instance = une analyse."""

    _lock         = threading.Lock()
    _probe_done   = False
    _probe_ok     = False
    _probe_reason = ""
    _help_text    = ""
    _mode         = ""          # "idmap" | "root" (une fois l'auto-test passé)
    _bpf: Optional[bytes] = None
    _read_all     = False       # fichiers d'un autre UID (droits 600) lisibles ?
    _nested_blocked = False     # userns imbriqués bloqués dans le sandbox ?

    def __init__(self, label: str = "scan") -> None:
        self.label = label

    # ── bwrap ─────────────────────────────────────────────────────────────────

    @classmethod
    def _bwrap_path(cls) -> Optional[str]:
        return shutil.which(SANDBOX_BWRAP_BIN)

    @classmethod
    def _supports(cls, option: str) -> bool:
        """Vrai si la version de bwrap installée gère l'option (aide chargée à la demande)."""
        if not cls._help_text:
            bwrap = cls._bwrap_path()
            if bwrap:
                try:
                    cls._help_text = subprocess.run(
                        [bwrap, "--help"], capture_output=True, text=True,
                        timeout=10).stdout
                except Exception:
                    cls._help_text = ""
        return option in cls._help_text

    @classmethod
    def _base_args(cls) -> List[str]:
        """Arguments communs à tous les sandboxes (sans bind de données)."""
        args = [
            "--unshare-ipc", "--unshare-pid", "--unshare-net",
            "--unshare-uts", "--unshare-cgroup-try",
            "--die-with-parent", "--new-session",
            "--cap-drop", "ALL",
        ]
        if cls._bpf is not None:
            # Lecture de tous les fichiers de la clé ; sûr uniquement parce que
            # seccomp interdit open_by_handle_at (voir _DENY_SYSCALLS).
            args += ["--cap-add", "CAP_DAC_READ_SEARCH"]
        args += [
            "--clearenv",
            "--setenv", "PATH",   "/usr/local/bin:/usr/bin:/bin",
            "--setenv", "HOME",   "/tmp",
            "--setenv", "TMPDIR", "/tmp",
            "--setenv", "LANG",   "C.UTF-8",
            "--hostname", "bastion-sandbox",
            "--proc", "/proc",
            "--dev",  "/dev",
        ]
        return args

    @classmethod
    def _system_binds(cls) -> List[str]:
        """Racine minimale : /usr + liens/répertoires de bibliothèques + /etc réduit."""
        args: List[str] = ["--ro-bind", "/usr", "/usr"]
        for d in _SYSTEM_DIRS:
            p = "/" + d
            if os.path.islink(p):
                args += ["--symlink", os.readlink(p), p]
            elif os.path.isdir(p):
                args += ["--ro-bind", p, p]
        for f in _ETC_FILES:
            p = "/etc/" + f
            if os.path.exists(p):
                args += ["--ro-bind", p, p]
        return args

    @staticmethod
    def validate_target(path: str) -> str:
        """
        Contrôle une cible d'analyse (répertoire ou fichier) et retourne son
        chemin canonique. Refuse la racine, les répertoires système et tout
        ce qui n'existe pas.
        """
        real = os.path.realpath(path)
        if not os.path.exists(real):
            raise SandboxUnavailable(f"Cible inexistante : {path}")
        if real in _FORBIDDEN_TARGETS:
            raise SandboxUnavailable(f"Cible interdite pour l'analyse : {real}")
        return real

    # ── Construction de la ligne de commande ──────────────────────────────────

    @classmethod
    def _wrap_mode(cls, argv: List[str]) -> List[str]:
        """Préfixe le helper de user namespace identité si le mode l'exige."""
        if cls._mode == "idmap":
            return [sys.executable or "/usr/bin/python3", "-I", "-B",
                    _USERNS_HELPER, "--"] + argv
        return argv

    def build_command(self,
                      cmd:        Sequence[str],
                      ro_binds:   Iterable[str] = (),
                      targets:    Iterable[str] = (),
                      extra_ro:   Optional[Dict[str, str]] = None,
                      seccomp_fd: Optional[int] = None) -> List[str]:
        """
        Retourne la ligne de commande complète (helper éventuel + bwrap … -- cmd).

        ro_binds : chemins hôte montés en lecture seule au même chemin
        targets  : supports à analyser — lecture seule, même chemin que l'hôte
        extra_ro : {chemin_hôte: chemin_sandbox} pour les montages ailleurs
        """
        bwrap = self._bwrap_path()
        if not bwrap:
            raise SandboxUnavailable(self.unavailable_reason() or "bwrap absent")

        args = [bwrap] + self._base_args()

        if seccomp_fd is not None:
            args += ["--seccomp", str(seccomp_fd)]

        if SANDBOX_TMPFS_SIZE_MB > 0 and self._supports("--size"):
            args += ["--size", str(SANDBOX_TMPFS_SIZE_MB * 1024 * 1024)]
        args += ["--tmpfs", "/tmp"]

        args += self._system_binds()

        for p in ro_binds:
            if p and os.path.exists(p):
                args += ["--ro-bind", p, p]

        for host, inside in (extra_ro or {}).items():
            args += ["--ro-bind", host, inside]

        for t in targets:
            real = self.validate_target(t)
            args += ["--ro-bind", real, real]
            if os.path.abspath(t) != real:
                args += ["--symlink", real, os.path.abspath(t)]

        # Racine en lecture seule (/tmp reste un tmpfs distinct, donc inscriptible)
        args += ["--remount-ro", "/"]

        return self._wrap_mode(args + ["--"] + list(cmd))

    # ── Auto-test ─────────────────────────────────────────────────────────────

    @classmethod
    def _probe_mode(cls, mode: str) -> bool:
        """
        Essaie un mode et vérifie, dans le sandbox : pas de /etc/shadow ni /home,
        une seule interface réseau (lo), racine en lecture seule, lecture d'un
        fichier 600 d'un autre UID, et userns imbriqués refusés.
        """
        cls._mode = mode
        cls._read_all = cls._nested_blocked = False

        probe_dir = tempfile.mkdtemp(prefix="bastion_probe_")
        try:
            secret = os.path.join(probe_dir, "secret")
            with open(secret, "w") as f:
                f.write("x")
            os.chown(secret, 1234, 1234)
            os.chmod(secret, 0o600)
            os.chmod(probe_dir, 0o755)

            script = (
                "test ! -e /etc/shadow || exit 11; test ! -e /home || exit 12; "
                "[ \"$(tail -n +3 /proc/net/dev | wc -l)\" -le 1 ] || exit 13; "
                "touch /usr/.w 2>/dev/null && exit 14; "
                f"cat {secret} >/dev/null 2>&1 && echo READALL; "
                "unshare -U true 2>/dev/null && echo NESTED; exit 0"
            )
            sb = cls("selftest")
            fd = cls._open_seccomp_fd()
            try:
                full = sb.build_command(["/bin/sh", "-c", script],
                                        targets=[probe_dir], seccomp_fd=fd)
                r = subprocess.run(full, capture_output=True, text=True,
                                   timeout=30,
                                   pass_fds=(fd,) if fd is not None else ())
            finally:
                if fd is not None:
                    os.close(fd)
        except SandboxUnavailable as e:
            cls._probe_reason = str(e)
            return False
        except Exception as e:                            # noqa: BLE001
            cls._probe_reason = f"mode {mode} : échec du lancement : {e}"
            return False
        finally:
            shutil.rmtree(probe_dir, ignore_errors=True)

        if r.returncode != 0:
            cls._probe_reason = (
                f"mode {mode} refusé (code {r.returncode}) : "
                f"{(r.stderr or '').strip()[:200]}")
            return False

        cls._read_all = "READALL" in r.stdout
        cls._nested_blocked = "NESTED" not in r.stdout
        return True

    @classmethod
    def _open_seccomp_fd(cls) -> Optional[int]:
        if cls._bpf is None:
            return None
        fd = os.memfd_create("bastion-seccomp")
        os.write(fd, cls._bpf)
        os.lseek(fd, 0, os.SEEK_SET)
        os.set_inheritable(fd, True)
        return fd

    @classmethod
    def self_test(cls) -> bool:
        """Choisit et valide un mode de sandbox (une fois ; résultat mis en cache)."""
        with cls._lock:
            if cls._probe_done:
                return cls._probe_ok
            cls._probe_done = True

            if not cls._bwrap_path():
                cls._probe_reason = (
                    f"'{SANDBOX_BWRAP_BIN}' introuvable (apt install bubblewrap)")
                return False
            if os.geteuid() != 0:
                cls._probe_reason = "l'application doit s'exécuter en root"
                return False

            cls._bpf = _build_seccomp_bpf()
            modes = ["idmap", "root"] if SANDBOX_MODE == "auto" else [SANDBOX_MODE]
            reasons: List[str] = []
            for mode in modes:
                if mode == "idmap" and not os.path.isfile(_USERNS_HELPER):
                    reasons.append("userns_exec.py manquant")
                    continue
                if cls._probe_mode(mode):
                    cls._probe_ok = True
                    cls._probe_reason = ""
                    log_info(f"Sandbox opérationnel : {cls.describe()}")
                    if not cls._read_all:
                        log_warning(
                            "Sandbox : fichiers d'un autre UID (droits 600) "
                            "illisibles — python3-seccomp requis pour les lire.")
                    if not cls._nested_blocked:
                        log_warning("Sandbox : user namespaces imbriqués NON bloqués.")
                    return True
                reasons.append(cls._probe_reason)
            cls._mode = ""
            cls._probe_reason = " | ".join(r for r in reasons if r)
            return False

    # ── Informations ──────────────────────────────────────────────────────────

    @classmethod
    def unavailable_reason(cls) -> str:
        return cls._probe_reason

    @classmethod
    def describe(cls) -> str:
        parts = [f"mode {cls._mode}",
                 "seccomp" if cls._bpf is not None else "SANS seccomp",
                 "lecture complète" if cls._read_all else "lecture limitée",
                 "userns imbriqués bloqués" if cls._nested_blocked
                 else "userns imbriqués NON bloqués"]
        return ", ".join(parts) + ", sans réseau, cible en lecture seule"

    @classmethod
    def short_status(cls) -> str:
        """Libellé court pour le bandeau de l'interface."""
        if not SANDBOX_ENABLED:
            return "⚠ Sandbox · désactivé"
        if not cls.self_test():
            return "❌ Sandbox"
        full = cls._bpf is not None and cls._read_all and cls._nested_blocked
        return f"{'🔒' if full else '⚠'} Sandbox · {cls._mode}{'' if full else ' (limité)'}"

    @classmethod
    def status_summary(cls) -> str:
        if not SANDBOX_ENABLED:
            return "⚠   Sandbox : désactivé (configuration)"
        if cls.self_test():
            hardened = cls._bpf is not None and cls._read_all and cls._nested_blocked
            return (f"{'✅' if hardened else '⚠ '}  Sandbox : actif ({cls.describe()})")
        return f"❌  Sandbox : indisponible — {cls._probe_reason}"

    # ── Lancement ─────────────────────────────────────────────────────────────

    @staticmethod
    def _limits() -> None:
        """Exécuté dans le fils, avant exec : pas de core dump."""
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, OSError):
            pass

    def popen(self, cmd: Sequence[str], *, ro_binds: Iterable[str] = (),
              targets: Iterable[str] = (),
              extra_ro: Optional[Dict[str, str]] = None,
              **popen_kw) -> subprocess.Popen:
        """Popen sandboxé. Lève SandboxUnavailable si le sandbox est requis et absent."""
        if not self.self_test():
            raise SandboxUnavailable(self.unavailable_reason())
        fd = self._open_seccomp_fd()
        try:
            full = self.build_command(cmd, ro_binds, targets, extra_ro, fd)
            log_info(f"[sandbox:{self.label}] lancement de {os.path.basename(cmd[0])}")
            return subprocess.Popen(full, preexec_fn=self._limits,
                                    pass_fds=(fd,) if fd is not None else (),
                                    **popen_kw)
        finally:
            if fd is not None:
                os.close(fd)

    def run(self, cmd: Sequence[str], *, ro_binds: Iterable[str] = (),
            targets: Iterable[str] = (),
            extra_ro: Optional[Dict[str, str]] = None,
            timeout: Optional[float] = None) -> subprocess.CompletedProcess:
        """subprocess.run sandboxé (sortie capturée en texte)."""
        proc = self.popen(cmd, ro_binds=ro_binds, targets=targets,
                          extra_ro=extra_ro, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise
        return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


# ══════════════════════════════════════════════════════════════════════════════
def sandbox_policy_ok() -> bool:
    """
    True si les analyses peuvent démarrer selon la politique configurée.
      • sandbox actif                     → True
      • sandbox absent + SANDBOX_REQUIRED → False  (échec fermé : on ne scanne pas)
      • sandbox absent + non requis       → True   (dégradé, avertissement)
    """
    if not SANDBOX_ENABLED:
        log_warning("Sandbox désactivé par configuration : analyses SANS isolation.")
        return not SANDBOX_REQUIRED
    if Sandbox.self_test():
        return True
    msg = f"Sandbox indisponible : {Sandbox.unavailable_reason()}"
    if SANDBOX_REQUIRED:
        log_error(msg + " — analyse refusée (SANDBOX_REQUIRED=True).")
        return False
    log_warning(msg + " — analyse SANS isolation (SANDBOX_REQUIRED=False).")
    return True


def sandbox_active() -> bool:
    """True si les moteurs doivent réellement être lancés dans un sandbox."""
    return SANDBOX_ENABLED and Sandbox.self_test()