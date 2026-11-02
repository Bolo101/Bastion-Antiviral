#!/usr/bin/env python3
"""
landlock_exec.py – Interdit l'exécution de fichiers hors des répertoires système,
puis lance la commande (exécuté À L'INTÉRIEUR du sandbox, voir sandbox.py).

Pourquoi : bubblewrap monte la clé analysée avec nosuid,nodev mais ne reporte pas
noexec. Landlock (LSM du noyau, sans capability ni root) comble ce manque :
après cet appel, plus aucun execve() n'est possible hors de la liste blanche —
ni depuis la clé analysée, ni depuis /tmp. Les restrictions Landlock sont
irrévocables et héritées par tous les processus fils.

Seul le droit « exécuter » est géré : lecture et écriture ne sont pas touchées
(les moteurs doivent lire les fichiers de la clé).

Limite inhérente : cela interdit d'EXÉCUTER un fichier, pas de le LIRE. Un
interpréteur déjà autorisé (`python3 /cle/x.py`, `sh /cle/x.sh`) peut toujours
lire et interpréter un script de la clé.

Usage : landlock_exec.py [--allow-exec CHEMIN]... -- commande [args…]
"""

import ctypes
import errno
import os
import sys

_SYS_CREATE_RULESET = 444
_SYS_ADD_RULE       = 445
_SYS_RESTRICT_SELF  = 446
_VERSION_FLAG       = 1 << 0
_RULE_PATH_BENEATH  = 1
_ACCESS_FS_EXECUTE  = 1 << 0
_PR_SET_NO_NEW_PRIVS = 38


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def abi_version() -> int:
    """Version de l'ABI Landlock du noyau, ou -1 si indisponible."""
    libc = ctypes.CDLL(None, use_errno=True)
    return int(libc.syscall(_SYS_CREATE_RULESET, None, 0, _VERSION_FLAG))


def restrict_exec(allowed_paths) -> None:
    """Applique la restriction : execve() uniquement sous `allowed_paths`."""
    libc = ctypes.CDLL(None, use_errno=True)

    attr = _RulesetAttr(handled_access_fs=_ACCESS_FS_EXECUTE)
    fd = libc.syscall(_SYS_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset")

    for p in allowed_paths:
        try:
            pfd = os.open(p, os.O_PATH | os.O_CLOEXEC)
        except OSError:
            continue                              # chemin absent de ce sandbox
        try:
            rule = _PathBeneath(allowed_access=_ACCESS_FS_EXECUTE, parent_fd=pfd)
            if libc.syscall(_SYS_ADD_RULE, fd, _RULE_PATH_BENEATH,
                            ctypes.byref(rule), 0) != 0:
                raise OSError(ctypes.get_errno(), f"landlock_add_rule({p})")
        finally:
            os.close(pfd)

    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(NO_NEW_PRIVS)")
    if libc.syscall(_SYS_RESTRICT_SELF, fd, 0) != 0:
        raise OSError(ctypes.get_errno(), "landlock_restrict_self")
    os.close(fd)


def main() -> int:
    argv = sys.argv[1:]
    allowed = []
    while argv and argv[0] == "--allow-exec":
        allowed.append(argv[1])
        argv = argv[2:]
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        sys.stderr.write("landlock_exec: aucune commande\n")
        return 2
    try:
        restrict_exec(allowed)
    except OSError as e:
        # Échec fermé : l'appelant a vérifié que Landlock fonctionne ; si ce n'est
        # plus le cas, ne PAS lancer le moteur sans la restriction demandée.
        sys.stderr.write(f"landlock_exec: restriction impossible : {e}\n")
        return 126
    try:
        os.execvp(argv[0], argv)
    except OSError as e:
        sys.stderr.write(f"landlock_exec: {argv[0]} : {e.strerror}\n")
        return 126 if e.errno == errno.EACCES else 127


if __name__ == "__main__":
    sys.exit(main())