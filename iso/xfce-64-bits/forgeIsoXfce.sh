#!/bin/bash
# =============================================================================
# forgeIsoXfce.sh  –  Génère une ISO live Debian Bookworm / XFCE
#                     avec le scanner antiviral USB (ClamAV + YARA)
#
# Pré-requis sur la machine de build :
#   sudo apt install live-build wget curl python3 unzip
#
# Structure attendue du projet :
#   ../code/        → les 8 fichiers Python du scanner
#   ../database/    → (optionnel) fichiers .cvd/.yar pré-téléchargés
#
# Exécution :
#   chmod +x forgeIsoXfce.sh && sudo ./forgeIsoXfce.sh
# =============================================================================

set -euo pipefail

# ── Variables ─────────────────────────────────────────────────────────────────
ISO_NAME="$(pwd)/usb-antivirus-scanner-v1.0.iso"
WORK_DIR="$(pwd)/debian-live-build"
CODE_DIR="$(pwd)/../../code"
DATABASE_DIR="$(pwd)/../database"
SIGBASE_URL="https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"

# ── Couleurs ──────────────────────────────────────────────────────────────────
GREEN="\e[32m"; YELLOW="\e[33m"; RED="\e[31m"; RESET="\e[0m"
ok()   { echo -e "${GREEN}✅  $*${RESET}"; }
warn() { echo -e "${YELLOW}⚠   $*${RESET}"; }
err()  { echo -e "${RED}❌  $*${RESET}"; exit 1; }
step() { echo -e "\n${YELLOW}▶▶  $*${RESET}"; }

# ── Vérification des pré-requis ───────────────────────────────────────────────
step "Vérification des pré-requis..."
for cmd in lb wget curl python3 unzip; do
    command -v "$cmd" &>/dev/null \
        || err "Commande manquante : $cmd  →  apt install live-build wget curl python3 unzip"
done
[[ -d "$CODE_DIR" ]] || err "Répertoire code introuvable : $CODE_DIR"
for f in config.py log_handler.py admin_auth.py usb_manager.py \
          db_manager.py scanner.py gui.py main.py; do
    [[ -f "$CODE_DIR/$f" ]] || err "Fichier manquant dans $CODE_DIR : $f"
done
ok "Pré-requis OK"

# ── Installation des outils de build ─────────────────────────────────────────
step "Installation des dépendances de build..."
apt-get update -qq
apt-get install -y live-build xorriso syslinux wget curl python3 unzip
ok "Outils de build installés"

# ── Préparation du répertoire de travail ──────────────────────────────────────
step "Préparation du répertoire de travail..."
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"
lb clean 2>/dev/null || true

# ── Configuration live-build ──────────────────────────────────────────────────
step "Configuration de live-build (Debian Bookworm / XFCE / AZERTY)..."
lb config \
    --distribution bookworm \
    --architectures amd64 \
    --linux-packages linux-image \
    --debian-installer none \
    --bootappend-live "boot=live components quiet splash \
hostname=antivirus-usb username=scanner \
locales=fr_FR.UTF-8 keyboard-layouts=fr" \
    --apt-options "--yes --no-install-recommends"
ok "live-build configuré"

# ── Dépôts Debian ─────────────────────────────────────────────────────────────
mkdir -p config/archives
cat > config/archives/debian.list.chroot << 'EOF'
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
EOF

# ── Liste des paquets ─────────────────────────────────────────────────────────
step "Définition des paquets..."
mkdir -p config/package-lists

cat > config/package-lists/custom.list.chroot << 'EOF'
# Système de base
coreutils
sudo
live-boot
live-config
live-tools
console-setup
keyboard-configuration
locales
# Desktop XFCE minimal
xorg
xfce4
xfce4-terminal
lightdm
lightdm-gtk-greeter
# Réseau
network-manager
network-manager-gnome
wget
curl
ca-certificates
# Python + GUI
python3
python3-tk
python3-pip
# YARA
yara
python3-yara
# ClamAV
clamav
clamav-daemon
clamav-freshclam
# Avast for Linux – installé depuis le dépôt officiel repo.avcdn.net
# (le hook 0250 configure le dépôt et installe le paquet)
# avast  ← ajouté dynamiquement par le hook 0250
# Outils disque/USB
parted
ntfs-3g
dosfstools
exfatprogs
util-linux
usbutils
# Firmware
firmware-linux-free
firmware-linux-nonfree
# Divers
unzip
squashfs-tools
EOF
ok "Liste de paquets définie"

# =============================================================================
# Hooks chroot
# =============================================================================
mkdir -p config/hooks/normal

# ── Hook 1 : téléchargement base ClamAV ──────────────────────────────────────
step "Création du hook ClamAV..."
cat > config/hooks/normal/0100-clamav-db.hook.chroot << 'HOOK'
#!/bin/bash
set -euo pipefail
echo ">>> [Hook ClamAV] Mise à jour de la base virale via freshclam..."

DB_DIR="/var/lib/clamav"
LOG="/var/log/clamav-build.log"
mkdir -p "$DB_DIR"
chown clamav:clamav "$DB_DIR" 2>/dev/null || true

# Arrêt des services pour libérer le verrou PID
systemctl stop clamav-freshclam 2>/dev/null || true
systemctl stop clamav-daemon    2>/dev/null || true
systemctl disable clamav-freshclam 2>/dev/null || true

# Vérifie si les bases sont déjà présentes et récentes (copiées depuis la machine de build)
EXISTING=$(find "$DB_DIR" -name "*.cvd" -o -name "*.cld" 2>/dev/null | wc -l)
if [[ "$EXISTING" -ge 2 ]]; then
    # Vérifie que les fichiers ne sont pas vides
    VALID=0
    for f in "$DB_DIR"/main.cvd "$DB_DIR"/daily.cvd "$DB_DIR"/main.cld "$DB_DIR"/daily.cld; do
        if [[ -f "$f" ]] && [[ $(stat -c%s "$f" 2>/dev/null || echo 0) -gt 1048576 ]]; then
            VALID=$((VALID + 1))
        fi
    done
    if [[ "$VALID" -ge 2 ]]; then
        echo ">>> [Hook ClamAV] $EXISTING fichier(s) de base déjà présents et valides." | tee -a "$LOG"
        echo "    Tentative de mise à jour incrémentale via freshclam..." | tee -a "$LOG"
    fi
fi

# Fichier de configuration freshclam temporaire pour ce hook
FRESHCLAM_CONF="$(mktemp /tmp/freshclam-hook.XXXXXX.conf)"
cat > "$FRESHCLAM_CONF" << CONF
DatabaseDirectory $DB_DIR
UpdateLogFile $LOG
LogVerbose yes
LogTime yes
MaxAttempts 3
DatabaseMirror database.clamav.net
DatabaseMirror db.local.clamav.net
ConnectTimeout 30
ReceiveTimeout 60
Bytecode yes
CONF

echo ">>> [Hook ClamAV] Lancement de freshclam..." | tee -a "$LOG"
if freshclam --config-file="$FRESHCLAM_CONF" --stdout 2>&1 | tee -a "$LOG"; then
    COUNT=$(find "$DB_DIR" \( -name "*.cvd" -o -name "*.cld" \) | wc -l)
    echo ">>> [Hook ClamAV] ✅ Base mise à jour ($COUNT fichier(s))." | tee -a "$LOG"
else
    RC=$?
    if [[ $RC -eq 1 ]]; then
        COUNT=$(find "$DB_DIR" \( -name "*.cvd" -o -name "*.cld" \) | wc -l)
        echo ">>> [Hook ClamAV] ✅ Base déjà à jour ($COUNT fichier(s))." | tee -a "$LOG"
    else
        echo ">>> [Hook ClamAV] ⚠ freshclam code $RC — base incluse dans l'image utilisée." | tee -a "$LOG"
    fi
fi

rm -f "$FRESHCLAM_CONF"

# Correction des permissions
chown clamav:clamav "$DB_DIR"/ 2>/dev/null || true
find "$DB_DIR" -name "*.cvd" -o -name "*.cld" 2>/dev/null     | xargs chown clamav:clamav 2>/dev/null || true
find "$DB_DIR" -name "*.cvd" -o -name "*.cld" 2>/dev/null     | xargs chmod 644 2>/dev/null || true

FINAL=$(find "$DB_DIR" -name "*.cvd" -o -name "*.cld" | wc -l)
echo ">>> [Hook ClamAV] Terminé. $FINAL fichier(s) dans $DB_DIR." | tee -a "$LOG"
HOOK
chmod +x config/hooks/normal/0100-clamav-db.hook.chroot
ok "Hook ClamAV créé"

# ── Hook 2 : téléchargement règles YARA ──────────────────────────────────────
step "Création du hook YARA..."
# Le heredoc utilise des variables bash d'ici : SIGBASE_URL est interpolé.
cat > config/hooks/normal/0200-yara-rules.hook.chroot << HOOK
#!/bin/bash
set -euo pipefail
echo ">>> [Hook YARA] Téléchargement de signature-base (Florian Roth)..."

YARA_DIR="/var/lib/yara-rules/signature-base"
TMP_ZIP="/tmp/signature-base.zip"
LOG="/var/log/yara-build.log"
URL="${SIGBASE_URL}"

mkdir -p "\$YARA_DIR"

# Vérifie si les règles sont déjà présentes (copiées depuis la machine de build)
EXISTING=\$(find "\$YARA_DIR" -name "*.yar" 2>/dev/null | wc -l)
if [[ "\$EXISTING" -gt 50 ]]; then
    echo ">>> [Hook YARA] \$EXISTING règles déjà présentes — skip téléchargement." | tee -a "\$LOG"
    exit 0
fi

wget -q --show-progress -O "\$TMP_ZIP" "\$URL" 2>>"\$LOG" || {
    echo "  ⚠ Impossible de télécharger signature-base." | tee -a "\$LOG"
    echo "    Les règles YARA incluses dans l'image seront utilisées." | tee -a "\$LOG"
    exit 0
}

python3 - "\$TMP_ZIP" "\$YARA_DIR" << 'PYEOF'
import sys, zipfile, os

zip_path = sys.argv[1]
out_dir  = sys.argv[2]
PREFIX   = "signature-base-master/yara/"
count    = 0
os.makedirs(out_dir, exist_ok=True)

with zipfile.ZipFile(zip_path) as zf:
    for member in zf.namelist():
        if (member.startswith(PREFIX)
                and member.endswith((".yar", ".yara"))
                and not member.endswith("/")):
            fname  = os.path.basename(member)
            target = os.path.join(out_dir, fname)
            with zf.open(member) as src, open(target, "wb") as dst:
                dst.write(src.read())
            count += 1

print(f"  {count} fichier(s) de règles YARA extraits.")
PYEOF

rm -f "\$TMP_ZIP"
COUNT=\$(find "\$YARA_DIR" -name "*.yar" | wc -l)
echo ">>> [Hook YARA] \$COUNT règle(s) installée(s)." | tee -a "\$LOG"
HOOK
chmod +x config/hooks/normal/0200-yara-rules.hook.chroot
ok "Hook YARA créé"

# ── Hook 2.5 : installation Avast for Linux ───────────────────────────────────
step "Création du hook d'installation Avast..."
cat > config/hooks/normal/0250-avast-install.hook.chroot << 'HOOK'
#!/bin/bash
# ============================================================================
# Hook 0250 : Installation d'Avast Business Antivirus for Linux
#
# Ce hook est exécuté dans le chroot pendant lb build.
# Il configure le dépôt Avast, installe le paquet, désactive le service
# au boot (la licence et le démarrage sont gérés par le panneau Admin).
#
# Aucune licence n'est incluse dans l'image : l'administrateur doit
# l'importer via le panneau Admin (code d'activation ou fichier .avastlic
# sur clé USB).
# ============================================================================
set -euo pipefail
LOG="/var/log/avast-install.log"
echo ">>> [Hook Avast] Début de l'installation..." | tee -a "$LOG"

# ── Détection de la distribution ──────────────────────────────────────────
. /etc/os-release
DIST_ID="${ID}"           # debian | ubuntu
DIST_CODENAME="${VERSION_CODENAME}"  # bookworm | bullseye | jammy …

# Mapping vers les noms de dépôts supportés par Avast
case "${DIST_ID}-${DIST_CODENAME}" in
    debian-bookworm)  AVAST_DIST="debian-bullseye" ;;  # Bookworm: utilise bullseye (compat)
    debian-bullseye)  AVAST_DIST="debian-bullseye" ;;
    debian-buster)    AVAST_DIST="debian-buster"   ;;
    ubuntu-jammy)     AVAST_DIST="ubuntu-jammy"    ;;
    ubuntu-focal)     AVAST_DIST="ubuntu-focal"    ;;
    ubuntu-bionic)    AVAST_DIST="ubuntu-bionic"   ;;
    *)                AVAST_DIST="debian-bullseye"  ;;  # fallback
esac

echo ">>> [Hook Avast] Distribution détectée : ${DIST_ID}-${DIST_CODENAME} → dépôt : ${AVAST_DIST}" | tee -a "$LOG"

# ── Vérification si déjà installé ─────────────────────────────────────────
if command -v avast &>/dev/null; then
    echo ">>> [Hook Avast] Avast déjà installé — skip." | tee -a "$LOG"
    exit 0
fi

# ── Pré-requis ──────────────────────────────────────────────────────────────
apt-get install -y --no-install-recommends     ca-certificates curl gnupg apt-transport-https 2>>"$LOG"     || { echo ">>> [Hook Avast] ⚠ Pré-requis manquants — skip installation." | tee -a "$LOG"; exit 0; }

# ── Clé GPG Avast ──────────────────────────────────────────────────────────
echo ">>> [Hook Avast] Import de la clé GPG Avast..." | tee -a "$LOG"
GPG_KEY_URL="https://repo.avcdn.net/linux-av/doc/avast-gpg-key.asc"
GPG_DEST="/etc/apt/trusted.gpg.d/avast.gpg"

if curl -fsSL --max-time 30 --retry 3         "$GPG_KEY_URL" 2>>"$LOG"         | gpg --dearmor -o "$GPG_DEST" 2>>"$LOG"; then
    chmod 644 "$GPG_DEST"
    echo ">>> [Hook Avast] Clé GPG importée." | tee -a "$LOG"
else
    echo ">>> [Hook Avast] ⚠ Impossible d'importer la clé GPG (réseau ?)." | tee -a "$LOG"
    echo ">>> [Hook Avast] Avast ne sera PAS installé dans cette image." | tee -a "$LOG"
    exit 0   # Non bloquant : l'image fonctionne sans Avast
fi

# ── Dépôt Avast ────────────────────────────────────────────────────────────
echo "deb https://repo.avcdn.net/linux-av/deb ${AVAST_DIST} release"     > /etc/apt/sources.list.d/avast.list
echo ">>> [Hook Avast] Dépôt ajouté : ${AVAST_DIST}" | tee -a "$LOG"

# ── Installation ───────────────────────────────────────────────────────────
echo ">>> [Hook Avast] apt-get update + install avast..." | tee -a "$LOG"
if apt-get update -qq 2>>"$LOG"    && apt-get install -y --no-install-recommends avast 2>>"$LOG"; then
    echo ">>> [Hook Avast] ✅ Avast installé avec succès." | tee -a "$LOG"
else
    echo ">>> [Hook Avast] ⚠ Échec de l'installation (paquet non disponible ?)." | tee -a "$LOG"
    echo ">>> [Hook Avast] L'image sera fonctionnelle sans Avast." | tee -a "$LOG"
    # Nettoyage partiel
    rm -f /etc/apt/sources.list.d/avast.list "$GPG_DEST" 2>/dev/null || true
    exit 0
fi

# ── Désactivation du service (géré par le panneau Admin) ──────────────────
echo ">>> [Hook Avast] Désactivation du service avast au boot..." | tee -a "$LOG"
systemctl disable avast.target 2>>"$LOG" || true
systemctl disable avast        2>>"$LOG" || true

# ── Création du répertoire de licence (vide — l'admin importe la sienne) ──
mkdir -p /etc/avast
chmod 755 /etc/avast
echo ">>> [Hook Avast] Répertoire /etc/avast créé (en attente de licence)." | tee -a "$LOG"

# ── Note d'information pour l'administrateur ──────────────────────────────
cat > /etc/avast/LICENCE_REQUISE.txt << 'INFO'
Avast Business Antivirus for Linux est installé mais PAS activé.

Pour activer Avast, ouvrez le Panneau d'administration et :

  Option A – Code d'activation (requiert Internet) :
    Onglet [🔐 Avast] → entrez votre code d'activation → [Activer]

  Option B – Fichier de licence hors-ligne :
    1. Copiez license.avastlic à la racine d'une clé USB
    2. Onglet [🔐 Avast] → [Importer licence (USB)]

Le fichier license.avastlic peut être téléchargé depuis :
  https://www.avast.com/business/linux
  ou via l'outil avastlic avec votre code d'activation.
INFO
chmod 644 /etc/avast/LICENCE_REQUISE.txt

echo ">>> [Hook Avast] Configuration terminée. Licence requise au premier démarrage." | tee -a "$LOG"
HOOK
chmod +x config/hooks/normal/0250-avast-install.hook.chroot
ok "Hook Avast créé"

# ── Hook 3 : configuration système ────────────────────────────────────────────
step "Création du hook système..."
cat > config/hooks/normal/0300-system-config.hook.chroot << 'HOOK'
#!/bin/bash
set -euo pipefail
echo ">>> [Hook Système] Configuration locale, utilisateurs, services..."

# Locale française
echo "fr_FR.UTF-8 UTF-8" >> /etc/locale.gen
locale-gen fr_FR.UTF-8
update-locale LANG=fr_FR.UTF-8 LC_ALL=fr_FR.UTF-8

# Utilisateur scanner (autologin, sudo sans mot de passe)
if ! id scanner &>/dev/null; then
    useradd -m -s /bin/bash -G sudo,plugdev,cdrom,dialout scanner
    echo "scanner:scanner" | chpasswd
fi
echo "scanner ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/scanner
chmod 0440 /etc/sudoers.d/scanner

# Répertoires de l'application
mkdir -p /opt/usb-antivirus
mkdir -p /mnt/avscan_usb && chmod 777 /mnt/avscan_usb
mkdir -p /etc/virusscanner && chmod 700 /etc/virusscanner
mkdir -p /var/lib/yara-rules/signature-base /var/lib/yara-rules/custom
chmod -R 755 /var/lib/yara-rules

# Wrapper de lancement
cat > /usr/local/bin/usb-antivirus << 'WRAPPER'
#!/bin/bash
exec sudo -E python3 /opt/usb-antivirus/main.py "$@"
WRAPPER
chmod 755 /usr/local/bin/usb-antivirus

# Désactivation des services AV au boot (gérés depuis le panneau Admin)
systemctl disable clamav-freshclam 2>/dev/null || true
systemctl disable clamav-daemon    2>/dev/null || true
# Avast (peut ne pas être installé si le hook 0250 a échoué)
systemctl disable avast.target     2>/dev/null || true
systemctl disable avast            2>/dev/null || true

echo ">>> [Hook Système] OK ✅"
HOOK
chmod +x config/hooks/normal/0300-system-config.hook.chroot
ok "Hook système créé"

# ── Hook 4 : permissions finales ────────────────────────────────────────────
cat > config/hooks/normal/0400-permissions.hook.chroot << 'HOOK'
#!/bin/bash
set -euo pipefail
echo ">>> [Hook Permissions] Finalisation..."

# Application Python
chmod 644 /opt/usb-antivirus/*.py
chmod 755 /opt/usb-antivirus

# ClamAV
mkdir -p /var/lib/clamav /var/log/clamav /var/run/clamav
chown -R clamav:clamav /var/lib/clamav /var/log/clamav /var/run/clamav 2>/dev/null || true
chmod 755 /var/lib/clamav /var/log/clamav /var/run/clamav
find /var/lib/clamav -name "*.cvd" -o -name "*.cld" 2>/dev/null \
    | xargs chmod 644 2>/dev/null || true

# YARA
chmod -R 755 /var/lib/yara-rules

# Avast (si installé)
if [ -d /etc/avast ]; then
    chmod 755 /etc/avast
    # Le fichier de licence sera déposé par l'administrateur
    [ -f /etc/avast/license.avastlic ] && chmod 644 /etc/avast/license.avastlic || true
fi
if [ -d /var/lib/avast ]; then
    chmod -R 755 /var/lib/avast 2>/dev/null || true
fi

# Autostart XFCE : s'assurer que le répertoire appartient à scanner
chown -R scanner:scanner /home/scanner/ 2>/dev/null || true

echo ">>> [Hook Permissions] OK ✅"
HOOK
chmod +x config/hooks/normal/0400-permissions.hook.chroot
ok "Hook permissions créé"

# =============================================================================
# includes.chroot – Fichiers intégrés dans l'image
# =============================================================================
step "Copie des fichiers dans le chroot..."

# ── Application Python ────────────────────────────────────────────────────────
APP_CHROOT="config/includes.chroot/opt/usb-antivirus"
mkdir -p "$APP_CHROOT"
cp -v "$CODE_DIR"/{config.py,log_handler.py,admin_auth.py,\
usb_manager.py,db_manager.py,scanner.py,gui.py,main.py} "$APP_CHROOT/"
ok "Fichiers Python copiés → $APP_CHROOT"

# ── Bases ClamAV : pré-téléchargement sur la machine de build ─────────────────
step "Pré-téléchargement de la base ClamAV (machine de build)..."
CLAMAV_CHROOT="config/includes.chroot/var/lib/clamav"
mkdir -p "$CLAMAV_CHROOT"

# 1. Copie depuis ../database/ si disponible
DB_FOUND=0
if [[ -d "$DATABASE_DIR" ]]; then
    for f in main.cvd main.cld daily.cvd daily.cld bytecode.cvd bytecode.cld; do
        if [[ -f "$DATABASE_DIR/$f" ]]; then
            cp -v "$DATABASE_DIR/$f" "$CLAMAV_CHROOT/"
            DB_FOUND=$((DB_FOUND + 1))
        fi
    done
fi

# 2. Téléchargement via freshclam sur la machine de build, puis copie dans le chroot
#
#    Stratégie : freshclam met à jour son répertoire natif (/var/lib/clamav),
#    qui est toujours fonctionnel (permissions, verrou, config OK).
#    On copie ensuite les fichiers résultants dans le chroot.
#    Cela évite tous les problèmes de freshclam avec un DatabaseDirectory
#    non-standard (droits clamav, verrou PID résiduel, rejet silencieux).

# S'assurer que freshclam est installé
if ! command -v freshclam &>/dev/null; then
    warn "freshclam absent — installation..."
    apt-get install -y clamav-freshclam
fi

CLAMAV_SYSTEM="/var/lib/clamav"
step "Mise à jour de la base ClamAV sur la machine de build (freshclam → $CLAMAV_SYSTEM)..."

# Arrêt du service pour libérer le verrou PID
systemctl stop clamav-freshclam 2>/dev/null || true
sleep 1   # laisse le temps au PID de se libérer

# Lancement de freshclam dans son environnement natif
echo "  Lancement de freshclam..."
freshclam --stdout 2>&1 | tee /tmp/freshclam-build.log || {
    RC=$?
    if [[ $RC -eq 1 ]]; then
        ok "Base ClamAV déjà à jour (code 1)."
    else
        warn "freshclam a quitté avec le code $RC — voir /tmp/freshclam-build.log"
        warn "Continuons : les fichiers déjà présents dans $CLAMAV_SYSTEM seront copiés."
    fi
}

# Copie des bases depuis /var/lib/clamav → chroot
echo "  Copie des bases dans le chroot..."
COPIED=0
# Seuils de validation par fichier :
#   main / daily  → > 1 Mo  (fichiers de plusieurs dizaines/centaines de Mo)
#   bytecode      → > 10 Ko (fichier léger, ~300 Ko — exclu à tort par le seuil 1 Mo)
declare -A MIN_SIZE=(
    ["main.cvd"]=1048576  ["main.cld"]=1048576
    ["daily.cvd"]=1048576 ["daily.cld"]=1048576
    ["bytecode.cvd"]=10240 ["bytecode.cld"]=10240
)
for f in "$CLAMAV_SYSTEM"/main.cvd "$CLAMAV_SYSTEM"/main.cld \
          "$CLAMAV_SYSTEM"/daily.cvd "$CLAMAV_SYSTEM"/daily.cld \
          "$CLAMAV_SYSTEM"/bytecode.cvd "$CLAMAV_SYSTEM"/bytecode.cld; do
    FNAME=$(basename "$f")
    THRESHOLD=${MIN_SIZE[$FNAME]:-10240}
    if [[ -f "$f" ]] && [[ $(stat -c%s "$f" 2>/dev/null || echo 0) -gt $THRESHOLD ]]; then
        cp -v "$f" "$CLAMAV_CHROOT/"
        ok "$FNAME copié ($(du -h "$f" | cut -f1))"
        COPIED=$((COPIED + 1))
    fi
done

if [[ $COPIED -gt 0 ]]; then
    ok "$COPIED fichier(s) de base ClamAV intégrés dans le chroot."
else
    warn "Aucun fichier de base ClamAV trouvé dans $CLAMAV_SYSTEM."
    warn "Le hook chroot (0100-clamav-db) tentera un second téléchargement"
    warn "pendant lb build. Vérifiez la connexion Internet."
fi

# Redémarrage du service
systemctl start clamav-freshclam 2>/dev/null || true

# ── Règles YARA : pré-téléchargement sur la machine de build ──────────────────
step "Pré-téléchargement des règles YARA signature-base (machine de build)..."
YARA_CHROOT="config/includes.chroot/var/lib/yara-rules"
mkdir -p "$YARA_CHROOT/signature-base" "$YARA_CHROOT/custom"

# 1. Copie depuis ../database/yara-rules/ si disponible
if [[ -d "$DATABASE_DIR/yara-rules" ]]; then
    while IFS= read -r -d '' f; do
        cp "$f" "$YARA_CHROOT/custom/"
    done < <(find "$DATABASE_DIR/yara-rules" -name "*.yar" -o -name "*.yara" -print0)
fi

# 2. Téléchargement si règles absentes
EXISTING_RULES=$(find "$YARA_CHROOT/signature-base" -name "*.yar" 2>/dev/null | wc -l)
if [[ "$EXISTING_RULES" -lt 50 ]]; then
    echo "  Téléchargement de signature-base (Florian Roth) depuis GitHub..."
    TMP_ZIP="$(mktemp /tmp/sigbase.XXXXXX.zip)"
    if wget -q --show-progress -O "$TMP_ZIP" "$SIGBASE_URL" 2>&1; then
        python3 - "$TMP_ZIP" "$YARA_CHROOT/signature-base" << 'PYEOF'
import sys, zipfile, os

zip_path = sys.argv[1]
out_dir  = sys.argv[2]
PREFIX   = "signature-base-master/yara/"
count    = 0
os.makedirs(out_dir, exist_ok=True)

with zipfile.ZipFile(zip_path) as zf:
    for member in zf.namelist():
        if (member.startswith(PREFIX)
                and member.endswith((".yar", ".yara"))
                and not member.endswith("/")):
            fname  = os.path.basename(member)
            target = os.path.join(out_dir, fname)
            with zf.open(member) as src, open(target, "wb") as dst:
                dst.write(src.read())
            count += 1

print(f"  {count} fichier(s) de règles YARA extraits.")
PYEOF
        EXISTING_RULES=$(find "$YARA_CHROOT/signature-base" -name "*.yar" | wc -l)
        ok "$EXISTING_RULES règles YARA signature-base téléchargées"
        rm -f "$TMP_ZIP"
    else
        warn "Échec téléchargement YARA — le hook réseau réessaiera pendant la build"
        rm -f "$TMP_ZIP" 2>/dev/null || true
    fi
else
    ok "$EXISTING_RULES règles YARA déjà présentes"
fi

# ── Fichiers de configuration ─────────────────────────────────────────────────
step "Génération des fichiers de configuration..."

# ClamAV
mkdir -p config/includes.chroot/etc/clamav
cat > config/includes.chroot/etc/clamav/clamd.conf << 'EOF'
LogFile /var/log/clamav/clamav.log
LogFileMaxSize 0
LogTime yes
LogSyslog yes
PidFile /var/run/clamav/clamd.pid
LocalSocket /var/run/clamav/clamd.ctl
LocalSocketGroup clamav
LocalSocketMode 666
FixStaleSocket yes
DatabaseDirectory /var/lib/clamav
OfficialDatabaseOnly no
SelfCheck 3600
ScanPE yes
ScanELF yes
ScanOLE2 yes
ScanPDF yes
ScanHTML yes
ScanArchive yes
ScanMail yes
PhishingSignatures yes
PhishingScanURLs yes
AlgorithmicDetection yes
Bytecode yes
BytecodeSecurity TrustSigned
BytecodeTimeout 60000
MaxScanSize 100M
MaxFileSize 25M
MaxRecursion 16
MaxFiles 10000
ExcludePath ^/proc/
ExcludePath ^/sys/
ExcludePath ^/dev/
ExcludePath ^/run/
EOF

cat > config/includes.chroot/etc/clamav/freshclam.conf << 'EOF'
DatabaseDirectory /var/lib/clamav
UpdateLogFile /var/log/clamav/freshclam.log
LogVerbose yes
LogTime yes
MaxAttempts 3
DatabaseOwner clamav
DatabaseMirror database.clamav.net
Bytecode yes
EOF

# Locale et clavier
mkdir -p config/includes.chroot/etc/default
cat > config/includes.chroot/etc/default/locale << 'EOF'
LANG=fr_FR.UTF-8
LC_ALL=fr_FR.UTF-8
EOF

cat > config/includes.chroot/etc/default/keyboard << 'EOF'
XKBMODEL="pc105"
XKBLAYOUT="fr"
XKBVARIANT="azerty"
XKBOPTIONS=""
BACKSPACE="guess"
EOF

# LightDM autologin
mkdir -p config/includes.chroot/etc/lightdm
cat > config/includes.chroot/etc/lightdm/lightdm.conf << 'EOF'
[Seat:*]
autologin-user=scanner
autologin-user-timeout=0
user-session=xfce
EOF

# NetworkManager
mkdir -p config/includes.chroot/etc/NetworkManager
cat > config/includes.chroot/etc/NetworkManager/NetworkManager.conf << 'EOF'
[main]
plugins=ifupdown,keyfile
dns=default
[ifupdown]
managed=false
EOF

# Service systemd d'initialisation ClamAV
mkdir -p config/includes.chroot/etc/systemd/system
cat > config/includes.chroot/etc/systemd/system/clamav-init.service << 'EOF'
[Unit]
Description=Initialisation ClamAV (répertoires et permissions)
After=local-fs.target
Before=clamav-daemon.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "\
    mkdir -p /var/lib/clamav /var/log/clamav /var/run/clamav && \
    chown -R clamav:clamav /var/lib/clamav /var/log/clamav /var/run/clamav && \
    chmod 755 /var/lib/clamav /var/log/clamav /var/run/clamav"

[Install]
WantedBy=multi-user.target
EOF

mkdir -p config/includes.chroot/etc/systemd/system/multi-user.target.wants
ln -sf /etc/systemd/system/clamav-init.service \
    config/includes.chroot/etc/systemd/system/multi-user.target.wants/clamav-init.service

# Autostart XFCE
mkdir -p "config/includes.chroot/home/scanner/.config/autostart"
cat > "config/includes.chroot/home/scanner/.config/autostart/usb-antivirus.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=USB Antivirus Scanner
Exec=/usr/local/bin/usb-antivirus
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true
EOF

# Entrée menu application
mkdir -p config/includes.chroot/usr/share/applications
cat > config/includes.chroot/usr/share/applications/usb-antivirus.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=USB Antivirus Scanner
GenericName=Scanner Antiviral USB
Comment=Analyse les clés USB avec ClamAV et YARA
Exec=/usr/local/bin/usb-antivirus
Icon=security-high
Terminal=false
Categories=Security;Utility;
EOF

# README sur l'USB
cat > config/includes.chroot/README_SCANNER.txt << 'EOF'
=============================================================================
 USB Antivirus Scanner  –  ClamAV + YARA
=============================================================================

DÉMARRAGE
---------
Le scanner démarre automatiquement. Si ce n'est pas le cas :
  usb-antivirus   (dans un terminal)

ADMINISTRATION (bouton ⚙, code par défaut : 0000 – À CHANGER)
---------------------------------------------------------------
• Mise à jour ClamAV (Internet) ou import .cvd depuis clé USB
• Mise à jour YARA (Internet) ou import .yar/.zip depuis clé USB
• Planification cron de la mise à jour
• Changement du code admin
• Quitter

MISE À JOUR HORS-LIGNE
----------------------
ClamAV  → https://database.clamav.net  (main.cvd, daily.cvd, bytecode.cvd)
YARA    → https://github.com/Neo23x0/signature-base/archive/master.zip

Copiez les fichiers à la racine d'une clé USB, puis utilisez
le panneau Admin → onglet ClamAV ou YARA → "Importer depuis clé USB".

JOURNAUX
--------
/var/log/virusscanner.log
/var/log/clamav/clamav.log
=============================================================================
EOF

ok "Tous les fichiers de configuration générés"

# =============================================================================
# Build de l'ISO
# =============================================================================
step "Lancement de la build live-build (20-40 min)..."
lb build 2>&1 | tee /tmp/lb-build.log

# ── Récupération de l'ISO ─────────────────────────────────────────────────────
step "Récupération de l'ISO générée..."
ISO_FOUND=""
for candidate in live-image-amd64.hybrid.iso binary.hybrid.iso; do
    [[ -f "$candidate" ]] && { ISO_FOUND="$candidate"; break; }
done
[[ -n "$ISO_FOUND" ]] || err "ISO introuvable après la build. Consultez /tmp/lb-build.log"
mv "$ISO_FOUND" "$ISO_NAME"
ok "ISO : $ISO_NAME"

# ── Nettoyage ─────────────────────────────────────────────────────────────────
step "Nettoyage..."
lb clean

# =============================================================================
# Résumé
# =============================================================================
ISO_SIZE=$(du -h "$ISO_NAME" | cut -f1)
CV_COUNT=$(find "$CLAMAV_CHROOT" \( -name "*.cvd" -o -name "*.cld" \) 2>/dev/null | wc -l)
TP_COUNT=$(find "$CLAMAV_CHROOT" \( -name "*.ndb" -o -name "*.hdb" -o -name "*.db" -o -name "*.ftm" \) 2>/dev/null | wc -l)
YR_COUNT=$(find "$YARA_CHROOT/signature-base" -name "*.yar" 2>/dev/null | wc -l)

echo ""
echo "═══════════════════════════════════════════════════════════"
echo -e "${GREEN}🎉  BUILD TERMINÉ AVEC SUCCÈS${RESET}"
echo "═══════════════════════════════════════════════════════════"
echo "  ISO         : $ISO_NAME  ($ISO_SIZE)"
echo "  ClamAV      : $CV_COUNT fichier(s) de base officielle(s)"
echo "  Signatures  : $TP_COUNT fichier(s) tiers (Sanesecurity, InterServer, URLhaus)"
echo "  Avast       : installé (licence requise via panneau Admin)"
echo "  YARA        : $YR_COUNT règle(s) signature-base incluses"
echo "  Clavier     : AZERTY (fr)"
echo "  Autologin   : scanner  (sudo sans mot de passe)"
echo "  Code admin  : 0000  (À CHANGER au premier démarrage !)"
echo ""
echo "  Pour flasher sur une clé USB :"
echo "    sudo dd if=$ISO_NAME of=/dev/sdX bs=4M status=progress"
echo "═══════════════════════════════════════════════════════════"