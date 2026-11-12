#!/usr/bin/env python3
"""
validated_supports.py – Registre des supports « validés ».

Un support est validé quand une analyse COMPLÈTE a conclu qu'il est sain :
aucune menace, aucune erreur, analyse non interrompue, exécutée dans le sandbox
avec au moins un moteur antivirus (ClamAV ou Avast). Seuls ces supports peuvent
ensuite être montés EN ÉCRITURE, uniquement depuis le panneau d'administration,
pour y exporter des rapports (voir usb_manager.mount_validated_rw).

Un support qui revient compromis est immédiatement retiré du registre.

Identité : UUID du système de fichiers + n° de série USB + fabricant/modèle +
taille. TOUS ces champs doivent correspondre. Ils sont fournis par le support
lui-même : un périphérique malveillant qui connaîtrait l'identité d'un support
validé pourrait la reproduire. Cette empreinte écarte les erreurs et les clés
quelconques, pas un attaquant ciblé disposant d'un périphérique programmable ;
c'est pourquoi chaque entrée affiche sa date de validation à l'administrateur.

Appairage : au premier export, l'application dépose sur le support un secret
aléatoire (.bastion_pair) dont seule l'empreinte est gardée ici. Les exports
suivants exigent ce secret (lu en lecture seule AVANT tout montage en écriture) :
un périphérique qui n'a copié que les identifiants visibles est refusé.

Fichier : droits 600 dans un répertoire 700 ; écriture atomique.
"""

import json
import os
import tempfile
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from config import STATE_DIR, VALIDATED_SUPPORTS_PATH
from log_handler import log_info, log_warning

_lock = threading.Lock()
_MAX_ENTRIES = 1000
_FIELDS = ("uuid", "serial", "vendor", "model", "size_bytes")


def identity_of(part) -> Dict[str, str]:
    """Empreinte d'un support (UsbPartition ou objet équivalent)."""
    def clean(v) -> str:
        return " ".join(str(v or "").split())[:128]
    return {
        "uuid":       clean(getattr(part, "uuid", "")),
        "serial":     clean(getattr(part, "serial", "")),
        "vendor":     clean(getattr(part, "vendor", "")),
        "model":      clean(getattr(part, "model", "")),
        "size_bytes": clean(getattr(part, "size_bytes", 0) or 0),
        "fstype":     clean(getattr(part, "fstype", "")),
        "label":      clean(getattr(part, "label", "")),
    }


def is_identifiable(identity: Dict[str, str]) -> bool:
    """Sans UUID de système de fichiers, aucune identité stable : jamais validé."""
    return bool(identity.get("uuid"))


def _same(a: Dict[str, str], b: Dict[str, str]) -> bool:
    return all(a.get(f, "").casefold() == b.get(f, "").casefold() for f in _FIELDS)


def _load() -> Dict:
    try:
        with open(VALIDATED_SUPPORTS_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("supports"), list):
            return data
    except FileNotFoundError:
        pass
    except Exception as e:                                # noqa: BLE001
        log_warning(f"Registre des supports validés illisible : {e}")
    return {"version": 1, "supports": []}


def _save(data: Dict) -> None:
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)                 # indépendant de l'umask
    fd, tmp = tempfile.mkstemp(dir=STATE_DIR, prefix=".validated_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, VALIDATED_SUPPORTS_PATH)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ══════════════════════════════════════════════════════════════════════════════

def mark_validated(identity: Dict[str, str], engines: List[str],
                   scanned: int) -> bool:
    """Enregistre (ou renouvelle) la validation. False si le support n'a pas d'UUID."""
    if not is_identifiable(identity):
        log_warning("Support sain mais sans UUID : non enregistré comme validé.")
        return False
    with _lock:
        data = _load()
        # Un nouveau scan sain NE réinitialise PAS l'appairage : sinon un faux support
        # n'aurait qu'à passer une analyse pour s'en débarrasser.
        previous = next((r for r in data["supports"]
                         if _same(r.get("identity", {}), identity)), None)
        data["supports"] = [r for r in data["supports"]
                            if not _same(r.get("identity", {}), identity)]
        entry = {
            "identity":     identity,
            "validated_at": datetime.now().isoformat(timespec="seconds"),
            "engines":      engines,
            "scanned":      scanned,
        }
        if previous and previous.get("pair_hash"):
            entry["pair_hash"] = previous["pair_hash"]
        data["supports"].append(entry)
        data["supports"] = data["supports"][-_MAX_ENTRIES:]
        _save(data)
    log_info(f"Support validé : uuid={identity.get('uuid')} "
             f"serial={identity.get('serial') or '-'} moteurs={engines}")
    return True


def set_pair_hash(identity: Dict[str, str], pair_hash: str) -> bool:
    """Enregistre l'empreinte SHA-256 du secret d'appairage déposé sur le support."""
    with _lock:
        data = _load()
        for r in data["supports"]:
            if _same(r.get("identity", {}), identity):
                r["pair_hash"] = pair_hash
                _save(data)
                return True
    return False


def revoke(identity: Dict[str, str]) -> int:
    """
    Retire TOUTES les entrées ayant cet UUID (même avec un autre n° de série :
    un support compromis ne doit laisser aucune validation derrière lui).
    Retourne le nombre d'entrées retirées.
    """
    uuid = identity.get("uuid", "")
    if not uuid:
        return 0
    with _lock:
        data = _load()
        keep = [r for r in data["supports"]
                if r.get("identity", {}).get("uuid", "").casefold() != uuid.casefold()]
        removed = len(data["supports"]) - len(keep)
        if removed:
            data["supports"] = keep
            _save(data)
    if removed:
        log_warning(f"Validation retirée (support compromis) : uuid={uuid}")
    return removed


def lookup(identity: Dict[str, str]) -> Tuple[Optional[Dict], str]:
    """(entrée, "") si le support est validé ; (None, raison) sinon."""
    if not is_identifiable(identity):
        return None, "support sans UUID : identité impossible à vérifier"
    with _lock:
        data = _load()
    same_uuid = [r for r in data["supports"]
                 if r.get("identity", {}).get("uuid", "").casefold()
                 == identity["uuid"].casefold()]
    for r in same_uuid:
        if _same(r.get("identity", {}), identity):
            return r, ""
    if same_uuid:
        log_warning("UUID connu mais empreinte matérielle DIFFÉRENTE "
                    f"(uuid={identity['uuid']}) : clone possible, export refusé.")
        return None, ("UUID déjà validé mais matériel différent (numéro de série, "
                      "modèle ou taille) : support refusé")
    return None, "support jamais validé : analysez-le d'abord (il doit être sain)"


def list_records() -> List[Dict]:
    with _lock:
        return list(_load()["supports"])


def forget(identity: Dict[str, str]) -> bool:
    """Retrait manuel par l'administrateur."""
    return revoke(identity) > 0