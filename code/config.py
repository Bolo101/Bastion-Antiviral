#!/usr/bin/env python3
"""config.py – Constantes partagées."""

# ── ClamAV ─────────────────────────────────────────────────────────────────────
CLAMAV_DB_DIR  = "/var/lib/clamav"

# ── YARA ───────────────────────────────────────────────────────────────────────
YARA_RULES_DIR = "/var/lib/yara-rules"

# Sous-répertoires des règles YARA
YARA_SIGBASE_SUBDIR = "signature-base"   # règles téléchargées depuis GitHub
YARA_CUSTOM_SUBDIR  = "custom"           # règles importées manuellement

# URL de téléchargement des règles Florian Roth
SIGBASE_ZIP_URL = (
    "https://github.com/Neo23x0/signature-base"
    "/archive/refs/heads/master.zip"
)
SIGBASE_YARA_PREFIX = "signature-base-master/yara/"  # chemin dans le zip

# ── Avast ──────────────────────────────────────────────────────────────────────
AVAST_LICENSE_DIR  = "/etc/avast"
AVAST_LICENSE_PATH = "/etc/avast/license.avastlic"
AVAST_VPS_DIR      = "/var/lib/avast/Setup"

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
LOG_FILE       = "/var/log/virusscanner.log"
ADMIN_CFG_DIR  = "/etc/virusscanner"
ADMIN_CFG_PATH = "/etc/virusscanner/admin.conf"