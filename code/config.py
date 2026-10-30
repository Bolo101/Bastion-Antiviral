#!/usr/bin/env python3
"""config.py – Constantes partagées."""

# ── ClamAV ─────────────────────────────────────────────────────────────────────
CLAMAV_DB_DIR = "/var/lib/clamav"

# ── YARA ───────────────────────────────────────────────────────────────────────
YARA_RULES_DIR = "/var/lib/yara-rules"

# Sous-répertoires des règles YARA
YARA_SIGBASE_SUBDIR = "signature-base"  # règles téléchargées depuis GitHub
YARA_CUSTOM_SUBDIR = "custom"  # règles importées manuellement

# URL de téléchargement des règles Florian Roth
SIGBASE_ZIP_URL = (
    "https://github.com/Neo23x0/signature-base"
    "/archive/refs/heads/master.zip"
)
SIGBASE_YARA_PREFIX = "signature-base-master/yara/"  # chemin dans le zip

# ── Avast ──────────────────────────────────────────────────────────────────────
AVAST_LICENSE_DIR = "/etc/avast"
AVAST_LICENSE_PATH = "/etc/avast/license.avastlic"
AVAST_VPS_DIR = "/var/lib/avast/Setup"

# Chemins possibles du binaire avast selon la distribution et la version
AVAST_BIN_PATHS = [
    "/usr/bin/avast",
    "/opt/avast/bin/avast",
    "/usr/local/bin/avast",
]

# Chemins possibles du binaire scan (CLI de scan Avast for Linux)
AVAST_SCAN_BIN_PATHS = [
    "/usr/bin/scan",
    "/opt/avast/bin/scan",
    "/usr/local/bin/scan",
]

# Binaire avastlic (outil de licence)
AVAST_LIC_BIN_PATHS = [
    "/usr/bin/avastlic",
    "/opt/avast/bin/avastlic",
    "/usr/local/bin/avastlic",
]

# ── Système ────────────────────────────────────────────────────────────────────
USB_MOUNT_BASE = "/mnt/avscan_usb"
LOG_FILE = "/var/log/virusscanner.log"
ADMIN_CFG_DIR = "/etc/virusscanner"
ADMIN_CFG_PATH = "/etc/virusscanner/admin.conf"
ADMIN_CRED_PATH = "/etc/virusscanner/admin.cred"

DEFAULT_CODE = "0000"
MIN_CODE_LENGTH = 4

# ── Sandbox d'analyse (voir sandbox.py) ────────────────────────────────────────
SANDBOX_ENABLED = True          # Lancer chaque moteur dans un sandbox éphémère
SANDBOX_REQUIRED = True         # Échec fermé : pas de sandbox → pas d'analyse
SANDBOX_BWRAP_BIN = "bwrap"     # Binaire bubblewrap
SANDBOX_TMPFS_SIZE_MB = 512     # Taille du /tmp éphémère du sandbox (0 = illimité)
SANDBOX_MODE = "auto"           # "auto" | "idmap" | "root"  (voir sandbox.py)
SANDBOX_USE_SECCOMP = True      # Filtre seccomp généré (python3-seccomp)

# Avast : "strict"  = le scan tourne entièrement dans le sandbox (si Avast ne
#                     fonctionne pas ainsi, l'erreur est affichée)
#         "daemon"  = autorise l'accès au démon Avast ; l'analyse est alors
#                     faite PAR LE DÉMON, hors sandbox (à n'utiliser qu'en
#                     connaissance de cause)
AVAST_SANDBOX_MODE = "strict"
AVAST_DAEMON_SOCKET_DIRS = ["/var/run/avast", "/run/avast"]

# ── Montage des supports USB (voir usb_manager.py) ─────────────────────────────
# Seuls ces systèmes de fichiers sont montés : chaque pilote noyau supplémentaire
# est une surface d'attaque (le noyau analyse le contenu du support à l'hôte).
USB_ALLOWED_FSTYPES = ("vfat", "exfat", "ntfs", "ntfs3", "ext2", "ext3", "ext4",
                       "iso9660", "udf")
USB_MOUNT_HARDEN_OPTS = "nosuid,nodev,noexec"