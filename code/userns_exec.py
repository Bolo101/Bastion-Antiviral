#!/usr/bin/env python3
"""
userns_exec.py – Exécute une commande dans un user namespace « identité ».

Pourquoi : dans un user namespace ordinaire (bwrap --unshare-user) un seul UID
est mappé. Les fichiers appartenant à un autre propriétaire (clé ext4, droits
600) y sont illisibles, même pour « root » : un fichier piégé y échapperait à
l'analyse. Ici, tous les UID/GID (0 … 2^32-2) sont mappés sur eux-mêmes ; les
capabilities obtenues dans ce namespace (CAP_DAC_READ_SEARCH, voir sandbox.py)
valent donc pour tous les fichiers de la clé, mais UNIQUEMENT dans ce
namespace : aucune capability n'existe sur le reste du système.

Mécanisme : le processus parent (root réel) écrit lui-même uid_map/gid_map du
fils, sans newuidmap ni /etc/subuid. Les user namespaces imbriqués sont
interdits (user.max_user_namespaces = 0 dans le nouveau namespace).

Usage : userns_exec.py -- <commande> [args…]     (doit être root)
"""

import ctypes
import os
import signal
import sys

CLONE_NEWUSER    = 0x10000000
PR_SET_PDEATHSIG = 1
FULL_MAP         = "0 0 4294967295\n"      # id interne == id externe, 0 … 2^32-2


def _die(msg: str, code: int) -> int:
    sys.stderr.write(f"userns_exec: {msg}\n")
    return code


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        return _die("aucune commande", 2)
    if os.geteuid() != 0:
        return _die("doit être exécuté en root", 3)

    libc = ctypes.CDLL(None, use_errno=True)
    ready_r, ready_w = os.pipe()
    go_r, go_w = os.pipe()

    pid = os.fork()
    if pid == 0:                                   # ── fils ──
        try:
            os.close(ready_r)
            os.close(go_w)
            # Meurt avec le parent (le wrapper), même sur SIGKILL
            libc.prctl(PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0)
            if libc.unshare(CLONE_NEWUSER) != 0:
                raise OSError(ctypes.get_errno(), "unshare(CLONE_NEWUSER)")
            os.write(ready_w, b"1")
            os.close(ready_w)
            if os.read(go_r, 1) != b"1":
                os._exit(125)
            os.close(go_r)
            try:                                   # pas de userns imbriqués
                with open("/proc/sys/user/max_user_namespaces", "w") as f:
                    f.write("0")
            except OSError:
                pass                               # seccomp prend le relais
            os.execvp(argv[0], argv)
        except BaseException as e:                 # noqa: BLE001
            sys.stderr.write(f"userns_exec: {e}\n")
            os._exit(126)

    # ── parent ──
    os.close(ready_w)
    os.close(go_r)

    def _forward(sig, _frame):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass

    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, _forward)

    if os.read(ready_r, 1) != b"1":
        os.waitpid(pid, 0)
        return _die("création du user namespace refusée", 125)

    try:
        with open(f"/proc/{pid}/uid_map", "w") as f:
            f.write(FULL_MAP)
        with open(f"/proc/{pid}/gid_map", "w") as f:
            f.write(FULL_MAP)
    except OSError as e:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        return _die(f"écriture uid_map/gid_map impossible : {e}", 125)

    os.write(go_w, b"1")
    os.close(go_w)

    while True:
        try:
            _, status = os.waitpid(pid, 0)
            break
        except InterruptedError:
            continue
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    return 128 + os.WTERMSIG(status)


if __name__ == "__main__":
    sys.exit(main())