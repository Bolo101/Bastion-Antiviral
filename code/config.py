#!/usr/bin/env python3
"""config.py – Constantes partagées."""

CLAMAV_DB_DIR  = "/var/lib/clamav"
YARA_RULES_DIR = "/var/lib/yara-rules"
USB_MOUNT_BASE = "/mnt/avscan_usb"
LOG_FILE       = "/var/log/virusscanner.log"
ADMIN_CFG_DIR  = "/etc/virusscanner"
ADMIN_CFG_PATH = "/etc/virusscanner/admin.conf"

# Sous-répertoires des règles YARA
YARA_SIGBASE_SUBDIR = "signature-base"   # règles téléchargées depuis GitHub
YARA_CUSTOM_SUBDIR  = "custom"           # règles importées manuellement

# URL de téléchargement des règles Florian Roth
SIGBASE_ZIP_URL = (
    "https://github.com/Neo23x0/signature-base"
    "/archive/refs/heads/master.zip"
)
SIGBASE_YARA_PREFIX = "signature-base-master/yara/"  # chemin dans le zip