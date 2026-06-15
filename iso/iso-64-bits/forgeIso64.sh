#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  forgeIsoXfce.sh  –  ISO live Debian Trixie  /  OpenBox + LightDM         ║
# ║                       Scanner antiviral USB  (ClamAV + YARA + Avast)        ║
# ║                                                                              ║
# ║  Entrée 1 : Live       → OpenBox kiosque  (usb-antivirus)                   ║
# ║  Entrée 2 : Installer  → rsync sur disque + session installée kiosque       ║
# ║  Entrée 3 : Live Safe  → Live + nomodeset                                   ║
# ║                                                                              ║
# ║  Pré-requis sur la machine de build :                                       ║
# ║    sudo apt install live-build xorriso syslinux wget curl python3 unzip     ║
# ║                                                                              ║
# ║  Structure du projet :                                                       ║
# ║    ../code/      → les 8 fichiers Python du scanner                         ║
# ║    ../database/  → (optionnel) .cvd/.yar pré-téléchargés                   ║
# ║                                                                              ║
# ║  Exécution :                                                                 ║
# ║    chmod +x forgeIsoXfce.sh && sudo ./forgeIsoXfce.sh                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Variables ─────────────────────────────────────────────────────────────────
ISO_NAME="$(pwd)/bastion-antiviral-v1.0.iso"
WORK_DIR="$(pwd)/debian-live-build"
CODE_DIR="$(pwd)/../../code"
SIGBASE_URL="https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"

# Paramètres de boot communs (réutilisés dans syslinux + GRUB)
BOOT_PARAMS="boot=live components quiet splash hostname=antivirus-usb username=scanner locales=fr_FR.UTF-8 keyboard-layouts=fr noeject nopersistent"

# ── Couleurs ──────────────────────────────────────────────────────────────────
GREEN="\e[32m"; YELLOW="\e[33m"; RED="\e[31m"; RESET="\e[0m"
ok()   { echo -e "${GREEN}✅  $*${RESET}"; }
warn() { echo -e "${YELLOW}⚠   $*${RESET}"; }
err()  { echo -e "${RED}❌  $*${RESET}"; exit 1; }
step() { echo -e "\n${YELLOW}▶▶  $*${RESET}"; }

# ── Vérification des pré-requis ───────────────────────────────────────────────
step "Vérification des pré-requis..."
for cmd in lb wget curl python3 unzip rsync xorriso; do
    command -v "$cmd" &>/dev/null \
        || err "Commande manquante : $cmd  →  apt install live-build wget curl python3 unzip"
done
[[ -d "$CODE_DIR" ]] || err "Répertoire code introuvable : $CODE_DIR"
for f in config.py log_handler.py admin_auth.py usb_manager.py \
          db_manager.py scanner.py gui.py main.py pdf_viewer.py; do
    [[ -f "$CODE_DIR/$f" ]] || err "Fichier manquant dans $CODE_DIR : $f"
done
ok "Pré-requis OK"

# ── Installation des outils de build ─────────────────────────────────────────
step "Installation des dépendances de build..."
apt-get update -qq
apt-get install -y live-build xorriso syslinux isolinux syslinux-utils wget curl python3 unzip rsync
ok "Outils de build installés"

# ── Préparation du répertoire de travail ──────────────────────────────────────
step "Préparation du répertoire de travail..."
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"
lb clean 2>/dev/null || true

# ── Configuration live-build ──────────────────────────────────────────────────
step "Configuration de live-build (Debian Trixie / OpenBox / AZERTY)..."
lb config \
    --distribution trixie \
    --architectures amd64 \
    --linux-packages linux-image \
    --debian-installer none \
    --bootappend-live "${BOOT_PARAMS}" \
    --bootloaders "syslinux,grub-efi" \
    --binary-images iso-hybrid \
    --apt-options "--yes --no-install-recommends"
ok "live-build configuré"

# ── Dépôts Debian ─────────────────────────────────────────────────────────────
mkdir -p config/archives
cat > config/archives/debian.list.chroot << 'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
EOF

# ── Dépôt Avast (sources persistantes dans l'image finale) ───────────────────
# Procédure officielle Avast Business for Linux :
#   1. Clé stockée en ASCII armored (.asc) via curl | tee  (PAS gpg --dearmor)
#   2. DIST détecté automatiquement — debian-bookworm supporté nativement
#   3. signed-by pointe sur le fichier .asc
# live-build copie config/archives/*.list.chroot → /etc/apt/sources.list.d/
# Le hook 0250 gère la clé .asc directement (plus fiable que *.key.chroot).
step "Configuration du dépôt Avast (config/archives)..."

AVAST_GPG_URL="https://repo.avcdn.net/linux-av/doc/avast-gpg-key.asc"
AVAST_KEY_DEST="/etc/apt/trusted.gpg.d/avast.asc"   # ASCII armored, pas binaire

# Détection de la distribution (identique à la procédure officielle Avast)
AVAST_DIST=$(. /etc/os-release 2>/dev/null; echo "${ID}-${VERSION_CODENAME}" 2>/dev/null || echo "debian-bookworm")

# Vérifie que le dépôt Avast supporte cette distribution
case "$AVAST_DIST" in
    debian-buster|debian-bullseye|debian-bookworm|    ubuntu-bionic|ubuntu-focal|ubuntu-jammy|ubuntu-noble)
        ok "Distribution Avast supportée : $AVAST_DIST" ;;
    *)
        warn "Distribution '$AVAST_DIST' non reconnue — utilisation de debian-bookworm"
        AVAST_DIST="debian-bookworm" ;;
esac

# Pré-téléchargement de la clé pour s'assurer qu'elle est disponible au build
# Note : la clé est téléchargée en ASCII armored (.asc) — format recommandé par Avast
TMP_ASC="$(mktemp /tmp/avast_key_XXXXXX.asc)"
if curl -fsSL --max-time 30 --retry 2 "$AVAST_GPG_URL" -o "$TMP_ASC" 2>/dev/null    && [[ -s "$TMP_ASC" ]]; then
    # Vérification basique que c'est bien une clé GPG ASCII armored
    if grep -q "BEGIN PGP PUBLIC KEY BLOCK" "$TMP_ASC" 2>/dev/null; then
        ok "Clé GPG Avast vérifiée (ASCII armored)"
        # Le hook 0250 installera cette clé via curl | tee (procédure officielle)
    else
        warn "Fichier téléchargé ne ressemble pas à une clé GPG — le hook tentera quand même"
    fi

    # .list.chroot : sera placé dans /etc/apt/sources.list.d/avast.list dans l'image
    cat > config/archives/avast.list.chroot << AVAST_LIST
# Avast Business Antivirus for Linux
# Dépôt officiel     : https://repo.avcdn.net
# Clé ASCII armored  : $AVAST_KEY_DEST
# Distribution       : $AVAST_DIST
deb [signed-by=$AVAST_KEY_DEST] https://repo.avcdn.net/linux-av/deb $AVAST_DIST release
AVAST_LIST
    ok "Dépôt Avast → config/archives/avast.list.chroot ($AVAST_DIST)"
    rm -f "$TMP_ASC"
else
    warn "Impossible de joindre repo.avcdn.net — dépôt Avast non préconfigurés"
    warn "Le hook 0250 tentera l'installation au moment du build (connexion requise)"
    warn "Installation manuelle post-déploiement :"
    warn "  curl -s https://repo.avcdn.net/linux-av/doc/avast-gpg-key.asc \"
    warn "    | sudo tee /etc/apt/trusted.gpg.d/avast.asc"
    warn "  echo 'deb [signed-by=/etc/apt/trusted.gpg.d/avast.asc]"
    warn "    https://repo.avcdn.net/linux-av/deb \$(. /etc/os-release;"
    warn "    echo \$ID-\$VERSION_CODENAME) release' \"
    warn "    | sudo tee /etc/apt/sources.list.d/avast.list"
    warn "  sudo apt update && sudo apt install avast avast-fss avast-rest avast-license"
    rm -f "$TMP_ASC"
fi

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
# Desktop OpenBox minimal
xorg
xserver-xorg-video-all
xserver-xorg-video-intel
xserver-xorg-video-ati
xserver-xorg-video-nouveau
xserver-xorg-video-vesa
xserver-xorg-video-fbdev
xserver-xorg-input-all
openbox
lightdm
xfwm4
xfce4-session
xfdesktop4
xfce4-panel
xfce4-terminal
thunar
xfce4-appfinder
xfce4-power-manager
# Réseau
network-manager
wget
curl
ca-certificates
# Python + GUI
python3
python3-tk
python3-pip
python3-pil
python3-pil.imagetk
python3-fitz
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
# GRUB + boot (pour install-to-disk)
grub-common
grub-pc-bin
grub-efi-amd64-bin
grub-pc
os-prober
# Firmware
firmware-linux-free
firmware-linux-nonfree
# Kiosk – verrouillage de session
xdotool
xbindkeys
unclutter
xterm
whiptail
# Divers
unzip
rsync
squashfs-tools
pciutils
acpi
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

# ── Hook 1.5 : signatures tierces ClamAV ─────────────────────────────────────
step "Création du hook signatures tierces ClamAV (validation par fichier)..."
cat > config/hooks/normal/0150-clamav-thirdparty.hook.chroot << 'HOOK'
#!/bin/bash
# =============================================================================
# Hook 0150 – Téléchargement des signatures tierces ClamAV
#
# Stratégie de validation : chaque fichier est validé immédiatement après
# son installation dans DB_DIR en testant le RÉPERTOIRE COMPLET avec clamscan.
# Si l'ajout du fichier casse le chargement, il est supprimé avant de passer
# au suivant. Cela élimine les conflits dès leur apparition sans algorithme
# d'isolation post-hoc.
#
# Sources :
#   Sanesecurity  – phishing, malwares, spam (màj horaire)
#   InterServer   – signatures généralistes
#   URLhaus       – URLs malveillantes actives (abuse.ch)
# =============================================================================
set -uo pipefail   # pas de -e : on ne bloque pas le build sur un wget raté

DB_DIR="/var/lib/clamav"
LOG="/var/log/clamav-thirdparty.log"
mkdir -p "$DB_DIR"

TP_OK=0
TP_SKIP=0

echo ">>> [Hook TP] Début des signatures tierces ClamAV…" | tee "$LOG"

# ── Détection clamscan ────────────────────────────────────────────────────────
if ! command -v clamscan &>/dev/null; then
    echo ">>> [Hook TP] clamscan introuvable — validation impossible, skip." | tee -a "$LOG"
    exit 0
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

# Vérifie qu'un fichier est une signature ClamAV valide et non une page HTML.
# Tous les formats tiers (.ndb .hdb .hsb .ldb .cdb .db .ftm .fp .ign2) sont du
# texte brut : leur première ligne ne commence jamais par '<' ou 'HTTP'.
_is_valid_content() {
    local FILE="$1"
    local HEADER
    HEADER=$(head -c 64 "$FILE" 2>/dev/null)
    case "$HEADER" in
        '<'*|'HTTP/'*|'{"'*|'<!DOCTYPE'*|'<!doctype'*) return 1 ;;
    esac
    [[ -n "$HEADER" ]] || return 1
    return 0
}

# _db_ok : teste que le RÉPERTOIRE COMPLET se charge sans erreur (timeout 60s).
# Utilise /dev/null comme cible de scan fictive — code 0 ou 1 = base OK.
_db_ok() {
    local OUT
    OUT=$(timeout 60 clamscan --no-summary --database="$DB_DIR" /dev/null 2>&1)
    local RC=$?
    # rc=0 propre, rc=1 détection (normal sur /dev/null parfois), rc=2 erreur base
    if [[ $RC -eq 2 ]]; then
        # Cherche des erreurs réelles de chargement de base dans la sortie
        if echo "$OUT" | grep -qiE "error loading|can't load|invalid|corrupt|can't open"; then
            return 1
        fi
    fi
    return 0
}

# install_and_validate <url> <fname> <min_bytes>
# Télécharge, vérifie le contenu, installe dans DB_DIR, valide la base complète.
# Supprime le fichier si la validation échoue. Retourne 0 si installé, 1 sinon.
install_and_validate() {
    local URL="$1" FNAME="$2" MIN_SIZE="${3:-64}"
    local DEST="$DB_DIR/$FNAME"
    local TMP
    TMP="$(mktemp /tmp/clamtp_XXXXXX)"

    echo "  ⬇  $FNAME …" | tee -a "$LOG"

    if ! wget -q --timeout=30 --tries=3 -O "$TMP" "$URL" 2>>"$LOG"; then
        echo "  ⚠ $FNAME : échec réseau — ignoré" | tee -a "$LOG"
        rm -f "$TMP"; return 1
    fi

    local SIZE
    SIZE=$(stat -c%s "$TMP" 2>/dev/null || echo 0)

    if [[ "$SIZE" -lt "$MIN_SIZE" ]]; then
        echo "  ⚠ $FNAME : fichier trop petit (${SIZE} < ${MIN_SIZE} o) — ignoré" | tee -a "$LOG"
        rm -f "$TMP"; return 1
    fi

    if ! _is_valid_content "$TMP"; then
        echo "  ⚠ $FNAME : contenu invalide (HTML/erreur serveur) — ignoré" | tee -a "$LOG"
        rm -f "$TMP"; return 1
    fi

    # Installer dans DB_DIR
    mv "$TMP" "$DEST"
    chmod 644 "$DEST"
    chown clamav:clamav "$DEST" 2>/dev/null || true

    # Valider la base COMPLÈTE avec ce fichier en place
    if _db_ok; then
        echo "  ✅ $FNAME installé et validé (${SIZE} o)" | tee -a "$LOG"
        TP_OK=$((TP_OK + 1))
        return 0
    else
        echo "  ⚠ $FNAME incompatible avec la base (conflit de format) — supprimé" | tee -a "$LOG"
        rm -f "$DEST"
        TP_SKIP=$((TP_SKIP + 1))
        return 1
    fi
}

# ── Sanesecurity ──────────────────────────────────────────────────────────────
# Liste des signatures validées depuis https://sanesecurity.com/usage/signatures/
# Chaque fichier est téléchargé et validé individuellement — les conflits sont
# éliminés au fur et à mesure sans purge globale.
echo ">>> [Hook TP] Sanesecurity…" | tee -a "$LOG"

SANE_FILES=(
    sanesecurity.ftm  sigwhitelist.ign2
    junk.ndb    jurlbl.ndb   jurlbla.ndb  lott.ndb
    phish.ndb   rogue.hdb    scam.ndb     blurl.ndb
    spamimg.hdb spamattach.hdb spam.ldb   shelter.ldb
    spear.ndb   spearl.ndb   badmacro.ndb
    malwarehash.hsb   hackingteam.hsb
    foxhole_generic.cdb  foxhole_filename.cdb  foxhole_js.cdb
    foxhole_js.ndb       foxhole_all.cdb        foxhole_all.ndb
    foxhole_mail.cdb     foxhole_links.ldb
    MiscreantPunch099-Low.ldb  MiscreantPunch099-INFO-Low.ldb
    porcupine.ndb  phishtank.ndb  porcupine.hsb
    bofhland_cracked_URL.ndb   bofhland_malware_URL.ndb
    bofhland_phishing_URL.ndb  bofhland_malware_attach.hdb
    winnow_malware.hdb           winnow_malware_links.ndb
    winnow_spam_complete.ndb     winnow_phish_complete_url.ndb
    winnow.complex.patterns.ldb  winnow_extended_malware.hdb
    winnow_extended_malware_links.ndb  winnow.attachments.hdb
    doppelstern.ndb   doppelstern.hdb   doppelstern-phishtank.ndb
    crdfam.clamav.hdb scamnailer.ndb
    malware.expert.ndb  malware.expert.hdb  malware.expert.ldb
    malware.expert.fp
)

SANE_BASE_URL=""

# Méthode 1 : rsync (méthode officielle Sanesecurity — copie d'abord dans un dossier temp,
# puis validation individuelle de chaque fichier avant installation définitive)
if command -v rsync &>/dev/null; then
    echo "  rsync://rsync.sanesecurity.net/sanesecurity …" | tee -a "$LOG"
    RSYNC_TMP="$(mktemp -d /tmp/sanesec_rsync_XXXXXX)"
    if rsync --timeout=30 --contimeout=15 --no-recursive -q \
        rsync://rsync.sanesecurity.net/sanesecurity/ "$RSYNC_TMP/" 2>>"$LOG" \
       && [[ $(ls "$RSYNC_TMP" 2>/dev/null | wc -l) -gt 0 ]]; then
        echo "  rsync OK — validation individuelle de chaque fichier…" | tee -a "$LOG"
        for fname in "${SANE_FILES[@]}"; do
            if [[ -f "$RSYNC_TMP/$fname" ]]; then
                SZ=$(stat -c%s "$RSYNC_TMP/$fname" 2>/dev/null || echo 0)
                if [[ "$SZ" -ge 64 ]] && _is_valid_content "$RSYNC_TMP/$fname"; then
                    DEST="$DB_DIR/$fname"
                    cp "$RSYNC_TMP/$fname" "$DEST"
                    chmod 644 "$DEST"; chown clamav:clamav "$DEST" 2>/dev/null || true
                    if _db_ok; then
                        echo "  ✅ $fname (rsync, ${SZ}o)" | tee -a "$LOG"
                        TP_OK=$((TP_OK + 1))
                    else
                        echo "  ⚠ $fname incompatible — supprimé" | tee -a "$LOG"
                        rm -f "$DEST"
                        TP_SKIP=$((TP_SKIP + 1))
                    fi
                fi
            fi
        done
        SANE_BASE_URL="rsync"
    else
        echo "  ⚠ rsync Sanesecurity inaccessible — fallback HTTP" | tee -a "$LOG"
    fi
    rm -rf "$RSYNC_TMP"
fi

# Méthode 2 : HTTP fallback
if [[ -z "$SANE_BASE_URL" ]]; then
    echo "  Fallback HTTP Sanesecurity…" | tee -a "$LOG"
    for SANE_HTTP in \
        "https://mirror.ihost.md/clamav/sanesecurity" \
        "https://ftp.swin.edu.au/sanesecurity"; do
        if wget --timeout=15 --tries=1 -q --spider "$SANE_HTTP/sanesecurity.ftm" 2>/dev/null; then
            SANE_BASE_URL="$SANE_HTTP"
            echo "  Miroir joignable : $SANE_HTTP" | tee -a "$LOG"
            for fname in "${SANE_FILES[@]}"; do
                install_and_validate "$SANE_HTTP/$fname" "$fname" 64 || true
            done
            break
        fi
    done
fi

[[ -n "$SANE_BASE_URL" ]] || echo "  ⚠ Sanesecurity inaccessible — ignoré." | tee -a "$LOG"

# ── InterServer ───────────────────────────────────────────────────────────────
echo ">>> [Hook TP] InterServer…" | tee -a "$LOG"
install_and_validate "http://sigs.interserver.net/interserver256.hdb" "interserver256.hdb" 500 || true
install_and_validate "http://sigs.interserver.net/topline.db"          "topline.db"          500 || true

# ── URLhaus (abuse.ch) ────────────────────────────────────────────────────────
echo ">>> [Hook TP] URLhaus…" | tee -a "$LOG"
URLHAUS_OK=false
for _url in \
    "https://urlhaus.abuse.ch/downloads/urlhaus.ndb" \
    "https://curbengh.github.io/malware-filter/urlhaus-filter-clam.ndb"; do
    if install_and_validate "$_url" "urlhaus-filter.ndb" 1000; then
        URLHAUS_OK=true; break
    fi
done
$URLHAUS_OK || echo "  ⚠ URLhaus inaccessible — ignoré." | tee -a "$LOG"

# ── Bilan final ───────────────────────────────────────────────────────────────
TP_FINAL=$(find "$DB_DIR" \( \
    -name "*.ndb" -o -name "*.hdb" -o -name "*.hsb" \
    -o -name "*.db"  -o -name "*.ftm" -o -name "*.ldb" \
    -o -name "*.cdb" -o -name "*.fp"  -o -name "*.ign2" \
    \) 2>/dev/null | wc -l)

echo ">>> [Hook TP] ✅ Terminé : $TP_OK installés, $TP_SKIP rejetés, $TP_FINAL fichier(s) tiers actifs." | tee -a "$LOG"

# Vérification finale de cohérence
if ! _db_ok; then
    echo ">>> [Hook TP] ❌ La base ne se charge toujours pas — purge totale des fichiers tiers." | tee -a "$LOG"
    find "$DB_DIR" \( -name "*.ndb" -o -name "*.hdb" -o -name "*.hsb" \
        -o -name "*.db" -o -name "*.ftm" -o -name "*.ldb" \
        -o -name "*.cdb" -o -name "*.fp" -o -name "*.ign2" \) \
        -delete 2>/dev/null || true
    echo ">>> [Hook TP] Purge effectuée. ClamAV fonctionnera avec les bases officielles seules." | tee -a "$LOG"
fi
HOOK
chmod +x config/hooks/normal/0150-clamav-thirdparty.hook.chroot
ok "Hook signatures tierces ClamAV (validation par fichier) créé"

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

# ── Hook 2.5 : installation Avast Business for Linux ─────────────────────────
# Procédure officielle Avast (https://repo.avcdn.net) :
#   1. DIST détecté via . /etc/os-release → $ID-$VERSION_CODENAME
#      debian-bookworm est désormais supporté nativement (plus besoin du mapping bullseye)
#   2. Clé en ASCII armored (.asc) via curl | tee — pas gpg --dearmor
#   3. sources.list avec signed-by=/etc/apt/trusted.gpg.d/avast.asc
#   4. Paquets : avast (moteur) + avast-fss (file shield) + avast-rest (API REST)
#                + avast-license (outil avastlic pour activation par code)
step "Création du hook d'installation Avast Business (procédure officielle)..."
cat > config/hooks/normal/0250-avast-install.hook.chroot << 'HOOK'
#!/bin/bash
# ============================================================================
# Hook 0250 : Installation d'Avast Business Antivirus for Linux
#
# Procédure officielle Avast (extrait de la documentation) :
#   DIST=$(. /etc/os-release; echo "$ID-$VERSION_CODENAME")
#   echo "deb https://repo.avcdn.net/linux-av/deb $DIST release" \
#     > /etc/apt/sources.list.d/avast.list
#   curl -s https://repo.avcdn.net/linux-av/doc/avast-gpg-key.asc \
#     | tee /etc/apt/trusted.gpg.d/avast.asc
#   apt update && apt install avast avast-fss avast-rest avast-license
#
# Distributions supportées : debian-buster/bullseye/bookworm/trixie,
#   ubuntu-bionic/focal/jammy/noble
#
# Une licence Business est requise. L'administrateur l'active via le
# panneau Admin (code d'activation ou fichier .avastlic USB/parcourir).
# ============================================================================
set -uo pipefail
LOG="/var/log/avast-install.log"
echo ">>> [Hook Avast] Début (procédure officielle)…" | tee "$LOG"

# ── Déjà installé ? ──────────────────────────────────────────────────────────
if command -v avast &>/dev/null || command -v scan &>/dev/null; then
    echo ">>> [Hook Avast] Avast déjà présent — skip." | tee -a "$LOG"
    exit 0
fi

# ── Pré-requis ───────────────────────────────────────────────────────────────
apt-get install -y --no-install-recommends     ca-certificates curl apt-transport-https >>"$LOG" 2>&1     || { echo ">>> [Hook Avast] ⚠ Pré-requis manquants." | tee -a "$LOG"; exit 0; }

# ── Détection de la distribution (procédure officielle Avast) ────────────────
DIST=$(. /etc/os-release; echo "${ID}-${VERSION_CODENAME}")
echo ">>> [Hook Avast] Distribution détectée : $DIST" | tee -a "$LOG"

# Validation contre la liste supportée
case "$DIST" in
    debian-buster|debian-bullseye|debian-bookworm|    ubuntu-bionic|ubuntu-focal|ubuntu-jammy|ubuntu-noble)
        echo ">>> [Hook Avast] Distribution supportée." | tee -a "$LOG" ;;
    *)
        echo ">>> [Hook Avast] ⚠ Distribution '$DIST' non reconnue — essai avec debian-bookworm."             | tee -a "$LOG"
        DIST="debian-bookworm" ;;
esac

# ── Dépôt APT ────────────────────────────────────────────────────────────────
ASC_DEST="/etc/apt/trusted.gpg.d/avast.asc"
LIST="/etc/apt/sources.list.d/avast.list"
GPG_URL="https://repo.avcdn.net/linux-av/doc/avast-gpg-key.asc"

# Étape 1 : clé ASCII armored via curl | tee (procédure officielle — PAS gpg --dearmor)
if [[ ! -s "$ASC_DEST" ]]; then
    echo ">>> [Hook Avast] Installation de la clé → $ASC_DEST" | tee -a "$LOG"
    if curl -fsSL --max-time 30 --retry 3 "$GPG_URL" | tee "$ASC_DEST" >>"$LOG" 2>&1        && grep -q "BEGIN PGP PUBLIC KEY BLOCK" "$ASC_DEST" 2>/dev/null; then
        chmod 644 "$ASC_DEST"
        echo ">>> [Hook Avast] ✅ Clé ASCII armored installée." | tee -a "$LOG"
    else
        echo ">>> [Hook Avast] ⚠ Impossible d'obtenir la clé GPG (réseau ?)." | tee -a "$LOG"
        echo "    Avast ne sera PAS installé dans cette image (non bloquant)." | tee -a "$LOG"
        rm -f "$ASC_DEST"
        exit 0
    fi
else
    echo ">>> [Hook Avast] Clé déjà présente : $ASC_DEST" | tee -a "$LOG"
fi

# Étape 2 : sources.list avec signed-by pointant sur le .asc
if [[ ! -f "$LIST" ]]; then
    echo "deb [signed-by=$ASC_DEST] https://repo.avcdn.net/linux-av/deb $DIST release"         > "$LIST"
    echo ">>> [Hook Avast] Dépôt ajouté : $LIST" | tee -a "$LOG"
    cat "$LIST" | tee -a "$LOG"
else
    echo ">>> [Hook Avast] Dépôt déjà configuré : $LIST" | tee -a "$LOG"
fi

# ── apt-get update ───────────────────────────────────────────────────────────
echo ">>> [Hook Avast] apt-get update…" | tee -a "$LOG"
apt-get update -qq >>"$LOG" 2>&1 || {
    echo ">>> [Hook Avast] ⚠ apt-get update a échoué — vérifiez la connexion." | tee -a "$LOG"
}

# ── Installation des paquets Avast ───────────────────────────────────────────
# avast         : moteur de scan principal
# avast-fss     : file system shield (protection temps réel)
# avast-rest    : API REST pour intégrations
# avast-license : outil avastlic pour activer via code d'activation
echo ">>> [Hook Avast] Installation : avast avast-fss avast-rest avast-license…" | tee -a "$LOG"
AVAST_INSTALLED=false
if apt-get install -y --no-install-recommends         avast avast-fss avast-rest avast-license >>"$LOG" 2>&1; then
    echo ">>> [Hook Avast] ✅ Paquets Avast installés." | tee -a "$LOG"
    AVAST_INSTALLED=true
elif apt-get install -y --no-install-recommends avast avast-license >>"$LOG" 2>&1; then
    # Fallback si avast-fss ou avast-rest non disponibles
    echo ">>> [Hook Avast] ✅ avast + avast-license installés (avast-fss/rest optionnels)."         | tee -a "$LOG"
    AVAST_INSTALLED=true
else
    echo ">>> [Hook Avast] ⚠ Échec d'installation du paquet avast." | tee -a "$LOG"
    tail -20 "$LOG" | grep -v "^>>>" | tee -a /dev/stderr || true
    echo "    L'image sera fonctionnelle sans Avast (ClamAV + YARA opérationnels)."         | tee -a "$LOG"
    exit 0
fi

if $AVAST_INSTALLED; then
    # Lister les binaires installés
    for BIN in avast scan avastlic; do
        PATH_BIN=$(command -v "$BIN" 2>/dev/null || true)
        [[ -n "$PATH_BIN" ]] && echo ">>> [Hook Avast] Binaire : $PATH_BIN" | tee -a "$LOG"
    done

    # Désactivation du service au boot (géré par le panneau Admin)
    systemctl disable avast.target >>"$LOG" 2>&1 || true
    systemctl disable avast        >>"$LOG" 2>&1 || true
    echo ">>> [Hook Avast] Service avast désactivé au boot." | tee -a "$LOG"
fi

# ── Répertoire de licence ─────────────────────────────────────────────────────
mkdir -p /etc/avast
chmod 755 /etc/avast

cat > /etc/avast/README_LICENCE.txt << 'INFO'
Avast Business Antivirus for Linux est installé mais PAS activé.

Une licence Business est requise pour utiliser le moteur de scan.
Sans licence, avast/scan refuse de scanner (code 126).

Comment activer la licence (3 méthodes) :

  Méthode A — Code d'activation (requiert Internet, via le panneau Admin) :
    Onglet [🔐 Avast] → entrez le code d'activation → [🔑 Activer]
    (utilise l'outil avastlic du paquet avast-license)

  Méthode B — Fichier .avastlic depuis une clé USB :
    Copiez license.avastlic à la racine d'une clé USB
    Onglet [🔐 Avast] → [🔌 Importer licence (USB)]

  Méthode C — Fichier .avastlic depuis le système de fichiers :
    Onglet [🔐 Avast] → [📂 Parcourir…] → sélectionnez le fichier

  En ligne de commande :
    sudo cp /chemin/vers/license.avastlic /etc/avast/license.avastlic
    # ou via avastlic :
    avastlic -o ~/license.avastlic -c CODE_ACTIVATION
    sudo cp ~/license.avastlic /etc/avast/license.avastlic

Licence Avast Business Linux : https://www.avast.com/business/linux
INFO
chmod 644 /etc/avast/README_LICENCE.txt

echo ">>> [Hook Avast] ✅ Installation terminée. Licence requise — voir /etc/avast/README_LICENCE.txt"     | tee -a "$LOG"
HOOK
chmod +x config/hooks/normal/0250-avast-install.hook.chroot
ok "Hook Avast Business (procédure officielle) créé"

# ── Hook 3 : configuration système – OpenBox kiosque ─────────────────────────
step "Création du hook système (OpenBox + LightDM)..."
cat > config/hooks/normal/0300-system-config.hook.chroot << 'HOOK'
#!/bin/bash
set -euo pipefail
echo ">>> [Hook Système] Configuration locale, utilisateurs, services (OpenBox kiosque)..."

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

# Répertoires de données applicatifs (../pdf/ et ../img/ relatifs au code)
mkdir -p /opt/pdf && chmod 775 /opt/pdf && chown scanner:scanner /opt/pdf 2>/dev/null || true
mkdir -p /opt/img && chmod 755 /opt/img

# Wrapper de lancement
cat > /usr/local/bin/usb-antivirus << 'WRAPPER'
#!/bin/bash
exec sudo -E python3 /opt/usb-antivirus/main.py "$@"
WRAPPER
chmod 755 /usr/local/bin/usb-antivirus

# ── OPENBOX : configuration globale kiosque ──────────────────────────────────
# Toutes les fenêtres : plein écran, sans décoration, couche supérieure.
# Les raccourcis clavier sont supprimés.
mkdir -p /etc/xdg/openbox
cat > /etc/xdg/openbox/rc.xml << 'XML'
<?xml version="1.0" encoding="UTF-8"?>
<openbox_config xmlns="http://openbox.org/3.4/rc"
                xmlns:xi="http://www.w3.org/2001/XInclude">
  <applications>
    <application class="*">
      <fullscreen>yes</fullscreen>
      <decor>no</decor>
      <maximized>yes</maximized>
      <layer>above</layer>
      <focus>yes</focus>
    </application>
  </applications>
  <!-- Tous les raccourcis clavier désactivés en mode kiosque -->
  <keyboard>
  </keyboard>
  <!-- Pas de menu sur clic droit du bureau -->
  <mouse>
    <context name="Root">
    </context>
  </mouse>
  <desktops>
    <number>1</number>
  </desktops>
</openbox_config>
XML

# Pas d'autostart OpenBox (fond noir, pas de taskbar, pas de tray)
mkdir -p /etc/xdg/openbox
cat > /etc/xdg/openbox/autostart << 'AUTOSTART'
# Aucun programme de bureau — kiosque minimal
AUTOSTART

# ── Désactiver Ctrl+Alt+Backspace (ZAP) et VT switching au niveau Xorg ───────
mkdir -p /etc/X11/xorg.conf.d
cat > /etc/X11/xorg.conf.d/99-kiosk-lock.conf << 'XORGCONF'
Section "ServerFlags"
    Option "DontZap"       "true"
    Option "DontVTSwitch"  "true"
    Option "BlankTime"     "0"
    Option "StandbyTime"   "0"
    Option "SuspendTime"   "0"
    Option "OffTime"       "0"
EndSection
Section "Monitor"
    Identifier "Monitor0"
    Option "DPMS" "false"
EndSection
XORGCONF

# ── Script dispatcher : LightDM appelle ce script pour LIVE et INSTALLATEUR ──
# Lit /proc/cmdline : si "installer=1" → installe sur disque.
#                     sinon           → lance l'application en boucle.
cat > /usr/local/bin/usb-antivirus-session.sh << 'SESSION'
#!/bin/bash
# =============================================================================
# usb-antivirus-session.sh  –  Dispatcher live / installateur
#
# Appelé par LightDM via usb-antivirus-live.desktop.
# Détecte le paramètre "installer=1" dans /proc/cmdline et bascule
# automatiquement vers le mode installateur (xterm + install-to-disk.sh).
# =============================================================================
export DISPLAY=:0
export XDG_RUNTIME_DIR="/run/user/$(id -u)"

# Anti-veille
xset s off -dpms 2>/dev/null || true
xset s noblank   2>/dev/null || true

# Démarrage d'OpenBox en arrière-plan
openbox &
OB_PID=$!
sleep 1

# Fond noir
xsetroot -solid black 2>/dev/null || true

if grep -q "installer=1" /proc/cmdline 2>/dev/null; then
    # ── Mode installateur ────────────────────────────────────────────────────
    xterm -title "USB Antivirus Scanner - Installation" \
          -fa "Monospace" -fs 12 \
          -bg "#0d0d1a" -fg "#e0e0e0" \
          -e "sudo /usr/local/bin/install-to-disk.sh"
else
    # ── Mode live kiosque ────────────────────────────────────────────────────
    # Boucle de relance : redémarre uniquement en cas de crash (exit != 0)
    while true; do
        /usr/local/bin/usb-antivirus
        [[ $? -eq 0 ]] && break   # quitter volontaire → on sort
        sleep 1
    done

    # Quitter volontaire → lancer un vrai bureau XFCE
    kill "$OB_PID" 2>/dev/null || true
    exec xfce4-session
fi

kill "$OB_PID" 2>/dev/null || true
SESSION
chmod 755 /usr/local/bin/usb-antivirus-session.sh

# ── Session pour le système INSTALLÉ (xfwm4 + application installée) ─────────
cat > /usr/local/bin/usb-antivirus-session-installed.sh << 'SESSION'
#!/bin/bash
# =============================================================================
# usb-antivirus-session-installed.sh  –  Session kiosque sur système installé
#
# Utilise xfwm4 comme gestionnaire de fenêtres (plus robuste pour un système
# installé pérenne). L'application redémarre automatiquement.
# =============================================================================
export DISPLAY=:0
export XDG_RUNTIME_DIR="/run/user/$(id -u)"

xset s off -dpms 2>/dev/null || true
xset s noblank   2>/dev/null || true

# Fond noir
xsetroot -solid black 2>/dev/null || true

# Démarrage de xfwm4 (léger, stable, sans décoration)
xfwm4 --compositor=off &
WM_PID=$!
sleep 1

# Boucle de relance : redémarre uniquement en cas de crash (exit != 0)
while true; do
    /usr/local/bin/usb-antivirus
    [[ $? -eq 0 ]] && break   # quitter volontaire → on sort
    sleep 1
done

# Quitter volontaire → lancer un vrai bureau XFCE
kill "$WM_PID" 2>/dev/null || true
exec xfce4-session
SESSION
chmod 755 /usr/local/bin/usb-antivirus-session-installed.sh

# ── Fichiers .desktop pour LightDM (xsessions) ───────────────────────────────
mkdir -p /usr/share/xsessions

cat > /usr/share/xsessions/usb-antivirus-live.desktop << 'XSESSION'
[Desktop Entry]
Name=USB Antivirus Live
Comment=Scanner antiviral USB (mode live OpenBox kiosque)
Exec=/usr/local/bin/usb-antivirus-session.sh
TryExec=/usr/local/bin/usb-antivirus-session.sh
Type=Application
XSESSION

cat > /usr/share/xsessions/usb-antivirus-installed.desktop << 'XSESSION'
[Desktop Entry]
Name=USB Antivirus Installed
Comment=Scanner antiviral USB (système installé, kiosque xfwm4)
Exec=/usr/local/bin/usb-antivirus-session-installed.sh
TryExec=/usr/local/bin/usb-antivirus-session-installed.sh
Type=Application
XSESSION

# ── LightDM autologin – session live ─────────────────────────────────────────
mkdir -p /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/50-autologin.conf << 'LDM'
[Seat:*]
autologin-user=scanner
autologin-session=usb-antivirus-live
autologin-user-timeout=0
allow-guest=false
LDM

mkdir -p /etc/skel
cat > /etc/skel/.dmrc << 'DMRC'
[Desktop]
Session=usb-antivirus-live
DMRC

# ── Script install-to-disk.sh (rsync, UEFI/BIOS, whiptail) ───────────────────
cat > /usr/local/bin/install-to-disk.sh << 'INSTALLER'
#!/bin/bash
set -e

TITLE="USB Antivirus Scanner - Installation"
TARGET_MNT="/mnt/av-target"

part() {
    case "$1" in
        *nvme*|*mmcblk*) echo "${1}p${2}" ;;
        *)               echo "${1}${2}"  ;;
    esac
}

# Détection des disques disponibles (exclure loop et le media live)
LIVE_DEV=$(findmnt -n -o SOURCE / 2>/dev/null | sed 's|/dev/||;s|[0-9]*$||' || true)
DISKS=$(lsblk -d -o NAME,SIZE,MODEL -n | grep -v "^loop" | grep -v "^${LIVE_DEV}" || true)

if [ -z "$DISKS" ]; then
    whiptail --title "$TITLE" --msgbox "Aucun disque cible détecté." 8 55
    exit 1
fi

MENU_ARGS=()
while IFS= read -r line; do
    name=$(echo "$line" | awk '{print $1}')
    rest=$(echo "$line" | awk '{$1=""; print $0}' | xargs)
    MENU_ARGS+=("/dev/$name" "$rest")
done <<< "$DISKS"

TARGET=$(whiptail --title "$TITLE" \
    --menu "Choisir le disque cible\n⚠  TOUTES LES DONNÉES SERONT EFFACÉES" \
    20 72 10 "${MENU_ARGS[@]}" \
    3>&1 1>&2 2>&3) || { echo "Installation annulée."; exit 0; }

whiptail --title "$TITLE" --yesno \
"⚠  AVERTISSEMENT FINAL

Toutes les données sur $TARGET seront définitivement effacées.
Le système sera installé en mode kiosque (démarrage automatique
de l'application antiviral USB).

Confirmer l'installation sur $TARGET ?" \
13 62 || { echo "Installation annulée."; exit 0; }

UEFI=0
[ -d /sys/firmware/efi ] && UEFI=1

# ── Partitionnement ───────────────────────────────────────────────────────────
whiptail --title "$TITLE" --infobox "Partitionnement de $TARGET..." 5 56
wipefs -a "$TARGET"

if [ "$UEFI" -eq 1 ]; then
    parted -s "$TARGET" mklabel gpt
    parted -s "$TARGET" mkpart ESP  fat32 1MiB 513MiB
    parted -s "$TARGET" set 1 esp on
    parted -s "$TARGET" mkpart root ext4 513MiB 100%
    EFI_PART="$(part "$TARGET" 1)"
    ROOT_PART="$(part "$TARGET" 2)"
else
    parted -s "$TARGET" mklabel msdos
    parted -s "$TARGET" mkpart primary ext4 1MiB 100%
    parted -s "$TARGET" set 1 boot on
    ROOT_PART="$(part "$TARGET" 1)"
fi

# ── Formatage ─────────────────────────────────────────────────────────────────
whiptail --title "$TITLE" --infobox "Formatage des partitions..." 5 50
mkfs.ext4 -F "$ROOT_PART"
[ "$UEFI" -eq 1 ] && mkfs.fat -F32 "$EFI_PART"

# ── Montage ───────────────────────────────────────────────────────────────────
whiptail --title "$TITLE" --infobox "Montage des partitions cibles..." 5 56
mkdir -p "$TARGET_MNT"
mount "$ROOT_PART" "$TARGET_MNT"
[ "$UEFI" -eq 1 ] && { mkdir -p "$TARGET_MNT/boot/efi"; mount "$EFI_PART" "$TARGET_MNT/boot/efi"; }

# ── Copie rsync (tout le système live — ClamAV + YARA + scanner inclus) ───────
whiptail --title "$TITLE" --infobox \
    "Copie du système (ClamAV + YARA + scanner)...\nCette étape dure plusieurs minutes." \
    7 62
rsync -aHAX \
    --exclude=/proc   --exclude=/sys    --exclude=/dev  \
    --exclude=/run    --exclude=/mnt    --exclude=/media \
    --exclude=/tmp    --exclude=/live   \
    / "$TARGET_MNT"/

mkdir -p "$TARGET_MNT"/{proc,sys,dev,run,mnt,media,tmp}
chmod 1777 "$TARGET_MNT/tmp"

# ── fstab ─────────────────────────────────────────────────────────────────────
ROOT_UUID=$(blkid -s UUID -o value "$ROOT_PART")
{
    echo "UUID=$ROOT_UUID  /          ext4  errors=remount-ro  0  1"
    if [ "$UEFI" -eq 1 ]; then
        EFI_UUID=$(blkid -s UUID -o value "$EFI_PART")
        echo "UUID=$EFI_UUID  /boot/efi  vfat  umask=0077         0  1"
    fi
    echo "tmpfs  /tmp  tmpfs  defaults,nosuid,nodev  0  0"
} > "$TARGET_MNT/etc/fstab"

# ── Masquer les services live (inutiles sur le système installé) ───────────────
for svc in live-boot live-config live-tools live-config-components; do
    chroot "$TARGET_MNT" systemctl mask "$svc" 2>/dev/null || true
done
rm -f "$TARGET_MNT/etc/live/boot.conf" 2>/dev/null || true

# ── LightDM : basculer sur la session "installée" (xfwm4 kiosque) ─────────────
mkdir -p "$TARGET_MNT/etc/lightdm/lightdm.conf.d"
cat > "$TARGET_MNT/etc/lightdm/lightdm.conf.d/50-autologin.conf" << 'LIGHTDM_EOF'
[Seat:*]
autologin-user=scanner
autologin-session=usb-antivirus-installed
autologin-user-timeout=0
allow-guest=false
LIGHTDM_EOF

[ -f "$TARGET_MNT/etc/skel/.dmrc" ] && \
cat > "$TARGET_MNT/etc/skel/.dmrc" << 'DMRC_EOF'
[Desktop]
Session=usb-antivirus-installed
DMRC_EOF

[ -f "$TARGET_MNT/home/scanner/.dmrc" ] && \
cat > "$TARGET_MNT/home/scanner/.dmrc" << 'DMRC_EOF'
[Desktop]
Session=usb-antivirus-installed
DMRC_EOF

# ── GRUB ──────────────────────────────────────────────────────────────────────
cat > "$TARGET_MNT/etc/default/grub" << 'GRUBCFG'
GRUB_DEFAULT=0
GRUB_TIMEOUT=3
GRUB_DISTRIBUTOR="USB Antivirus Scanner"
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
GRUBCFG

whiptail --title "$TITLE" --infobox "Installation du chargeur d'amorçage GRUB..." 5 58
mount --bind /dev  "$TARGET_MNT/dev"
mount --bind /proc "$TARGET_MNT/proc"
mount --bind /sys  "$TARGET_MNT/sys"
[ "$UEFI" -eq 1 ] && \
    mount --bind /sys/firmware/efi/efivars \
                 "$TARGET_MNT/sys/firmware/efi/efivars" 2>/dev/null || true

if [ "$UEFI" -eq 1 ]; then
    chroot "$TARGET_MNT" grub-install \
        --target=x86_64-efi \
        --efi-directory=/boot/efi \
        --bootloader-id=AVScanner \
        --recheck
else
    chroot "$TARGET_MNT" grub-install --target=i386-pc --recheck "$TARGET"
fi
chroot "$TARGET_MNT" update-grub

umount "$TARGET_MNT/sys/firmware/efi/efivars" 2>/dev/null || true
umount "$TARGET_MNT/sys"
umount "$TARGET_MNT/proc"
umount "$TARGET_MNT/dev"
[ "$UEFI" -eq 1 ] && umount "$TARGET_MNT/boot/efi"
umount "$TARGET_MNT"

whiptail --title "$TITLE" --msgbox \
"✅  Installation terminée !

Le scanner antiviral USB a été installé sur $TARGET.
ClamAV, YARA et toutes les signatures sont préservés.

Au démarrage :
  - L'interface de scan se lance automatiquement.
  - Le panneau Admin (⚙) permet les mises à jour
    ClamAV/YARA et la gestion Avast.

Retirez la clé USB / le CD et appuyez sur OK pour redémarrer." \
16 65

reboot
INSTALLER
chmod +x /usr/local/bin/install-to-disk.sh

# ── Désactivation des services AV au boot (gérés depuis le panneau Admin) ─────
systemctl disable clamav-freshclam 2>/dev/null || true
systemctl disable clamav-daemon    2>/dev/null || true
systemctl disable avast.target     2>/dev/null || true
systemctl disable avast            2>/dev/null || true

echo ">>> [Hook Système] OpenBox kiosque OK ✅"
HOOK
chmod +x config/hooks/normal/0300-system-config.hook.chroot
ok "Hook système OpenBox kiosque créé"

cat > config/hooks/normal/0400-permissions.hook.chroot << 'HOOK'
#!/bin/bash
set -euo pipefail
echo ">>> [Hook Permissions] Finalisation..."

# Application Python
chmod 644 /opt/usb-antivirus/*.py
chmod 755 /opt/usb-antivirus

# ClamAV – bases officielles + signatures tierces
mkdir -p /var/lib/clamav /var/log/clamav /var/run/clamav
chown -R clamav:clamav /var/lib/clamav /var/log/clamav /var/run/clamav 2>/dev/null || true
chmod 755 /var/lib/clamav /var/log/clamav /var/run/clamav
# Bases officielles
find /var/lib/clamav \( -name "*.cvd" -o -name "*.cld" \) 2>/dev/null \
    | xargs chmod 644 2>/dev/null || true
# Signatures tierces (toutes extensions ClamAV tierces)
find /var/lib/clamav \( -name "*.ndb" -o -name "*.hdb" -o -name "*.hsb" \
    -o -name "*.db" -o -name "*.ftm" -o -name "*.ldb" \
    -o -name "*.cdb" -o -name "*.fp" \) 2>/dev/null \
    | xargs chown clamav:clamav 2>/dev/null || true
find /var/lib/clamav \( -name "*.ndb" -o -name "*.hdb" -o -name "*.hsb" \
    -o -name "*.db" -o -name "*.ftm" -o -name "*.ldb" \
    -o -name "*.cdb" -o -name "*.fp" \) 2>/dev/null \
    | xargs chmod 644 2>/dev/null || true
# Validation au moment du hook permissions — même algorithme que le hook 0150.
# Boucle while : recommence depuis zéro après chaque suppression pour éviter
# de faussement supprimer des fichiers innocents.
# Important : on utilise un fichier temporaire vide, PAS /dev/null.
# /dev/null est un fichier spécial rejeté par clamscan avec code 2 + "Not
# supported file type", ce qui déclencherait un faux positif d'erreur de base.
if command -v clamscan &>/dev/null; then
    _CVAL_TMP="$(mktemp /tmp/clamval_XXXXXX)"
    if ! clamscan --no-summary --database=/var/lib/clamav "$_CVAL_TMP" &>/dev/null; then
        echo ">>> [Hook Perms] ⚠ Base invalide — isolation en cours…"
        CULPRITS_P=0
        while ! clamscan --no-summary --database=/var/lib/clamav "$_CVAL_TMP" &>/dev/null; do
            QDIR="$(mktemp -d /tmp/clamav_perms_quar_XXXXXX)"
            FOUND_P=false
            for f in /var/lib/clamav/*.ndb /var/lib/clamav/*.hdb /var/lib/clamav/*.hsb \
                     /var/lib/clamav/*.db  /var/lib/clamav/*.ftm /var/lib/clamav/*.ldb \
                     /var/lib/clamav/*.cdb /var/lib/clamav/*.fp; do
                [ -f "$f" ] || continue
                BNAME=$(basename "$f")
                mv "$f" "$QDIR/"
                if clamscan --no-summary --database=/var/lib/clamav "$_CVAL_TMP" &>/dev/null; then
                    echo "    Suppression : $BNAME (coupable)"
                    rm -f "$QDIR/$BNAME"
                    CULPRITS_P=$((CULPRITS_P + 1))
                    FOUND_P=true
                    break
                else
                    mv "$QDIR/$BNAME" /var/lib/clamav/
                fi
            done
            rm -rf "$QDIR"
            if ! $FOUND_P; then
                echo ">>> [Hook Perms] ⚠ Conflit non isolable — purge des fichiers tiers."
                find /var/lib/clamav \( -name "*.ndb" -o -name "*.hdb" -o -name "*.hsb" \
                    -o -name "*.db" -o -name "*.ftm" -o -name "*.ldb" \
                    -o -name "*.cdb" -o -name "*.fp" \) -delete 2>/dev/null || true
                break
            fi
        done
        [ "$CULPRITS_P" -gt 0 ] && echo ">>> [Hook Perms] ✅ Base assainie ($CULPRITS_P fichier(s) retiré(s))."
    fi
    rm -f "$_CVAL_TMP"
fi

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

chown -R scanner:scanner /home/scanner/ 2>/dev/null || true

echo ">>> [Hook Permissions] OK ✅"
HOOK
chmod +x config/hooks/normal/0400-permissions.hook.chroot
ok "Hook permissions créé"

# ── Hook 4.5 : script post-installation exécuté après Calamares ───────────────
# Ce script est lancé par un service systemd oneshot sur le SYSTÈME INSTALLÉ
# (pas dans le live) au premier démarrage. Il s'assure que les bases ClamAV
# et les règles YARA copiées depuis le live sont bien utilisées.
step "Création du script de post-installation..."
mkdir -p config/includes.chroot/usr/lib/antivirus-installer
cat > config/includes.chroot/usr/lib/antivirus-installer/post-install.sh << 'POSTINSTALL'
#!/bin/bash
# =============================================================================
# post-install.sh  –  Premier démarrage après installation sur disque.
#
# Tâches :
#   1. Corriger les permissions ClamAV (les services sont maintenant actifs)
#   2. Corriger les permissions YARA
#   3. Reconfigurer l'autologin LightDM avec le compte créé par Calamares
#      (le compte "scanner" du live n'existe plus — Calamares en crée un nouveau)
#   4. Se désactiver (oneshot : ne tourne qu'une seule fois)
# =============================================================================
set -euo pipefail
LOG="/var/log/antivirus-post-install.log"
exec >> "$LOG" 2>&1
echo "=== post-install.sh : $(date) ==="

# ── 1. ClamAV ─────────────────────────────────────────────────────────────────
echo ">> Permissions ClamAV..."
mkdir -p /var/lib/clamav /var/log/clamav /var/run/clamav
chown -R clamav:clamav /var/lib/clamav /var/log/clamav /var/run/clamav 2>/dev/null || true
chmod 755 /var/lib/clamav /var/log/clamav /var/run/clamav
find /var/lib/clamav -type f \( \
    -name "*.cvd" -o -name "*.cld" -o -name "*.ndb" -o -name "*.hdb" \
    -o -name "*.hsb" -o -name "*.db"  -o -name "*.ftm" -o -name "*.ldb" \
    -o -name "*.cdb" -o -name "*.fp"  -o -name "*.ign2" \) \
    -exec chown clamav:clamav {} \; -exec chmod 644 {} \; 2>/dev/null || true
echo "   $(find /var/lib/clamav -type f | wc -l) fichier(s) dans /var/lib/clamav"

# ── 2. YARA ───────────────────────────────────────────────────────────────────
echo ">> Permissions YARA..."
if [ -d /var/lib/yara-rules ]; then
    chmod -R 755 /var/lib/yara-rules
    YR=$(find /var/lib/yara-rules -name "*.yar" | wc -l)
    echo "   $YR règle(s) YARA disponibles"
fi

# ── 3. Répertoire du scanner ──────────────────────────────────────────────────
echo ">> Permissions scanner..."
if [ -d /opt/usb-antivirus ]; then
    chmod 644 /opt/usb-antivirus/*.py 2>/dev/null || true
    chmod 755 /opt/usb-antivirus
fi

# ── 4. Reconfiguration autologin LightDM (session installée) ─────────────────
# On cible le compte "scanner" copié depuis le live par rsync.
# Si l'administrateur a créé un autre compte (uid >= 1000), on le détecte.
REAL_USER=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1; exit}' /etc/passwd)
REAL_USER="${REAL_USER:-scanner}"
echo ">> Autologin → $REAL_USER (session usb-antivirus-installed)"
mkdir -p /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/50-autologin.conf << LDMEOF
[Seat:*]
autologin-user=$REAL_USER
autologin-session=usb-antivirus-installed
autologin-user-timeout=0
allow-guest=false
LDMEOF
cat > /etc/skel/.dmrc << DMRC
[Desktop]
Session=usb-antivirus-installed
DMRC
[ -f "/home/$REAL_USER/.dmrc" ] && cat > "/home/$REAL_USER/.dmrc" << DMRC
[Desktop]
Session=usb-antivirus-installed
DMRC
# sudo sans mot de passe
echo "$REAL_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/antivirus-user
chmod 0440 /etc/sudoers.d/antivirus-user
chown -R "$REAL_USER:$REAL_USER" "/home/$REAL_USER" 2>/dev/null || true

# ── 5. Auto-désactivation du service ─────────────────────────────────────────
echo ">> Désactivation du service post-install..."
systemctl disable antivirus-post-install.service 2>/dev/null || true

echo "=== post-install.sh : terminé ==="
POSTINSTALL
chmod 755 config/includes.chroot/usr/lib/antivirus-installer/post-install.sh

# Service systemd oneshot pour le premier démarrage après installation
mkdir -p config/includes.chroot/etc/systemd/system
cat > config/includes.chroot/etc/systemd/system/antivirus-post-install.service << 'EOF'
[Unit]
Description=Configuration post-installation USB Antivirus Scanner
After=multi-user.target
ConditionPathExists=/usr/lib/antivirus-installer/post-install.sh

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/lib/antivirus-installer/post-install.sh

[Install]
WantedBy=multi-user.target
EOF

# Activé dans le multi-user.target.wants — il se désactive lui-même après exécution
mkdir -p config/includes.chroot/etc/systemd/system/multi-user.target.wants
ln -sf /etc/systemd/system/antivirus-post-install.service \
    config/includes.chroot/etc/systemd/system/multi-user.target.wants/antivirus-post-install.service

ok "Script post-installation créé"

# =============================================================================
# includes.chroot – Fichiers intégrés dans l'image
# =============================================================================
step "Copie des fichiers dans le chroot..."

# ── Application Python ────────────────────────────────────────────────────────
APP_CHROOT="config/includes.chroot/opt/usb-antivirus"
mkdir -p "$APP_CHROOT"
cp -v "$CODE_DIR"/{config.py,log_handler.py,admin_auth.py,\
usb_manager.py,db_manager.py,scanner.py,gui.py,main.py,pdf_viewer.py} "$APP_CHROOT/"
ok "Fichiers Python copiés → $APP_CHROOT"

# ── Répertoire PDFs (../pdf/ relatif au code = /opt/pdf/) ─────────────────────
PDF_CHROOT="config/includes.chroot/opt/pdf"
mkdir -p "$PDF_CHROOT"
# Copier les PDFs présents dans ../pdf/ sur la machine de build, si disponibles
PDF_SRC="$(dirname "$WORK_DIR")/../../pdf"
if [[ -d "$PDF_SRC" ]]; then
    PDF_COUNT=$(find "$PDF_SRC" -maxdepth 1 -name "*.pdf" | wc -l)
    if [[ "$PDF_COUNT" -gt 0 ]]; then
        cp -v "$PDF_SRC"/*.pdf "$PDF_CHROOT/"
        ok "$PDF_COUNT PDF(s) intégré(s) dans le chroot ($PDF_CHROOT)"
    else
        ok "Dossier pdf/ trouvé mais vide — le répertoire /opt/pdf/ sera créé vide"
    fi
else
    warn "Dossier pdf/ introuvable ($PDF_SRC) — /opt/pdf/ sera vide au démarrage"
    warn "Ajoutez des PDFs via le panneau Admin → onglet 📄 PDFs"
fi

# ── Logo (../img/logo.png relatif au code = /opt/img/logo.png) ────────────────
IMG_CHROOT="config/includes.chroot/opt/img"
mkdir -p "$IMG_CHROOT"
LOGO_SRC="$(pwd)/../../img/logo.png"
if [[ -f "$LOGO_SRC" ]]; then
    cp -v "$LOGO_SRC" "$IMG_CHROOT/logo.png"
    ok "Logo copié → $IMG_CHROOT/logo.png"
else
    warn "Logo introuvable ($LOGO_SRC) — l'interface utilisera le texte de remplacement"
    warn "Placez votre logo dans ../img/logo.png et relancez le build"
fi

# ── Bases ClamAV : pré-téléchargement sur la machine de build ─────────────────
step "Pré-téléchargement de la base ClamAV (machine de build)..."
CLAMAV_CHROOT="config/includes.chroot/var/lib/clamav"
mkdir -p "$CLAMAV_CHROOT"

# Téléchargement via freshclam sur la machine de build, puis copie dans le chroot
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

# ── Signatures tierces ClamAV : pré-téléchargement sur la machine de build ────
step "Téléchargement des signatures tierces ClamAV (machine de build)..."

# ── Helpers de téléchargement et de validation de contenu ────────────────────
# Vérifie qu'un fichier est bien une signature ClamAV (texte brut) et non
# une page HTML/HTTP retournée en 200 OK à la place du fichier réel.
_is_valid_clamav_file() {
    local FILE="$1"
    local HEADER
    HEADER=$(head -c 64 "$FILE" 2>/dev/null)
    case "$HEADER" in
        '<'*|'HTTP/'*|'{"'*|'<!DOCTYPE'*|'<!doctype'*) return 1 ;;
    esac
    [[ -n "$HEADER" ]] || return 1
    return 0
}

_dl_tp() {
    local URL="$1" DEST="$2" MIN="$3"
    local TMP FNAME WGETLOG
    FNAME="$(basename "$DEST")"
    TMP="$(mktemp /tmp/clamtp_build_XXXXXX)"
    WGETLOG="$(mktemp /tmp/wget_err_XXXXXX)"

    if wget --timeout=30 --tries=2 -O "$TMP" "$URL" 2>"$WGETLOG"; then
        local SZ; SZ=$(stat -c%s "$TMP" 2>/dev/null || echo 0)
        if [[ "$SZ" -ge "$MIN" ]]; then
            if ! _is_valid_clamav_file "$TMP"; then
                warn "$FNAME : page HTML reçue à la place du fichier (200 OK trompeur) — ignoré"
            else
                mv "$TMP" "$DEST"; chmod 644 "$DEST"
                ok "$FNAME inclus ($(du -h "$DEST" | cut -f1))"
                TMP=""   # déjà déplacé, ne pas supprimer
            fi
        else
            warn "$FNAME trop petit (${SZ} o < ${MIN} o) — ignoré"
        fi
    else
        local ERR; ERR="$(tail -3 "$WGETLOG" 2>/dev/null)"
        warn "Échec téléchargement $FNAME — ignoré"
        echo "    URL    : $URL"
        echo "    Erreur : $ERR"
    fi
    rm -f "$TMP" "$WGETLOG"
    return 0
}

# Liste complète établie depuis https://mirror.ihost.md/?dir=clamav/sanesecurity
# NB : winnow_phish_complete_url.ndb uniquement (pas les deux variantes ensemble).
_SANE_FILES=(
    # Requis
    sanesecurity.ftm  sigwhitelist.ign2
    # Sanesecurity propres
    junk.ndb    jurlbl.ndb   jurlbla.ndb  lott.ndb
    phish.ndb   rogue.hdb    scam.ndb     blurl.ndb
    spamimg.hdb spamattach.hdb spam.ldb   shelter.ldb
    spear.ndb   spearl.ndb   badmacro.ndb
    malwarehash.hsb   hackingteam.hsb
    # Foxhole
    foxhole_generic.cdb  foxhole_filename.cdb  foxhole_js.cdb
    foxhole_js.ndb       foxhole_all.cdb        foxhole_all.ndb
    foxhole_mail.cdb     foxhole_links.ldb
    # MiscreantPunch
    MiscreantPunch099-Low.ldb  MiscreantPunch099-INFO-Low.ldb
    # Porcupine
    porcupine.ndb  phishtank.ndb  porcupine.hsb
    # bofhland
    bofhland_cracked_URL.ndb   bofhland_malware_URL.ndb
    bofhland_phishing_URL.ndb  bofhland_malware_attach.hdb
    # OITC winnow (winnow_phish_complete_url seul, pas les deux variantes)
    winnow_malware.hdb           winnow_malware_links.ndb
    winnow_spam_complete.ndb     winnow_phish_complete_url.ndb
    winnow.complex.patterns.ldb  winnow_extended_malware.hdb
    winnow_extended_malware_links.ndb  winnow.attachments.hdb
    # doppelstern / crdfam / scamnailer / malware.expert
    doppelstern.ndb   doppelstern.hdb   doppelstern-phishtank.ndb
    crdfam.clamav.hdb scamnailer.ndb
    malware.expert.ndb  malware.expert.hdb  malware.expert.ldb
    malware.expert.fp
)

# ── Méthode 1 : rsync (méthode officielle — sanesecurity.com) ─────────────────
_SANE_OK=false
if command -v rsync &>/dev/null; then
    step "Sanesecurity via rsync://rsync.sanesecurity.net ..."
    RSYNC_TMP="$(mktemp -d /tmp/sanesec_rsync_XXXXXX)"
    # --include="*/" requis pour que rsync descende dans les sous-répertoires
    # éventuels, même si la source est plate. Sans lui, certains rsync ignorent
    # silencieusement les filtres d'extension et transfèrent 0 fichier (exit 0).
    if rsync --timeout=30 --contimeout=15 --no-recursive -q \
        rsync://rsync.sanesecurity.net/sanesecurity/ "$RSYNC_TMP/" \
        2>/tmp/rsync-sane.log; then
        # Vérification que des fichiers ont bien été transférés
        RSYNC_COUNT=$(ls "$RSYNC_TMP" 2>/dev/null | wc -l)
        if [[ "$RSYNC_COUNT" -gt 0 ]]; then
            for _fname in "${_SANE_FILES[@]}"; do
                if [[ -f "$RSYNC_TMP/$_fname" ]]; then
                    SZ=$(stat -c%s "$RSYNC_TMP/$_fname" 2>/dev/null || echo 0)
                    if [[ "$SZ" -ge 64 ]]; then
                        cp "$RSYNC_TMP/$_fname" "$CLAMAV_CHROOT/$_fname"
                        chmod 644 "$CLAMAV_CHROOT/$_fname"
                        ok "$_fname (rsync, $(du -h "$CLAMAV_CHROOT/$_fname" | cut -f1))"
                    fi
                fi
            done
            _SANE_OK=true
            ok "Sanesecurity : rsync OK ($RSYNC_COUNT fichier(s) reçus)"
        else
            warn "rsync a réussi mais a transféré 0 fichier — fallback HTTP"
        fi
    else
        warn "rsync Sanesecurity inaccessible — $(head -2 /tmp/rsync-sane.log)"
    fi
    rm -rf "$RSYNC_TMP"
fi

# ── Méthode 2 : HTTP (mirror.ihost.md — miroir vérifié le 2026-03-14) ────────
if ! $_SANE_OK; then
    warn "rsync indisponible ou sans résultat — tentative HTTP..."
    for SANE_HTTP in \
        "https://mirror.ihost.md/clamav/sanesecurity" \
        "https://ftp.swin.edu.au/sanesecurity"; do
        if wget --timeout=15 --tries=1 -q --spider "$SANE_HTTP/sanesecurity.ftm" 2>/dev/null; then
            ok "Miroir HTTP Sanesecurity joignable : $SANE_HTTP"
            _SANE_OK=true
            for _fname in "${_SANE_FILES[@]}"; do
                _dl_tp "$SANE_HTTP/$_fname" "$CLAMAV_CHROOT/$_fname" 64 || true
            done
            break
        else
            warn "$SANE_HTTP inaccessible"
        fi
    done
fi

$_SANE_OK || warn "Aucune source Sanesecurity joignable. L'image fonctionnera avec les bases officielles uniquement."

# ── InterServer (nouvelle URL — sigs.interserver.net) ─────────────────────────
# L'ancienne URL interserver.net/virus-l/ retournait 403.
# Fichiers disponibles : interserver256.hdb, shell.ldb, topline.db
for _ifile in "interserver256.hdb" "topline.db"; do
    _dl_tp "http://sigs.interserver.net/$_ifile" "$CLAMAV_CHROOT/$_ifile" 500 || true
done

# ── URLhaus (abuse.ch) ────────────────────────────────────────────────────────
# L'accès direct abuse.ch nécessite désormais une auth-key.
# On tente néanmoins l'URL publique historique puis le miroir GitHub.
_URLHAUS_OK=false
for _url in \
    "https://urlhaus.abuse.ch/downloads/urlhaus.ndb" \
    "https://curbengh.github.io/malware-filter/urlhaus-filter-clam.ndb"; do
    if _dl_tp "$_url" "$CLAMAV_CHROOT/urlhaus-filter.ndb" 1000; then
        _URLHAUS_OK=true; break
    fi
done
$_URLHAUS_OK || warn "URLhaus inaccessible (auth-key requise ?) — signature ignorée"

# Comptage final — pas de validation clamscan ici.
# Raison : clamscan --database="fichier_unique" retourne toujours une erreur
# quand il n'a pas les bases officielles chargées en parallèle. Tester chaque
# fichier tiers isolément purgerait tous les fichiers à tort.
# La validation réelle est déléguée au hook 0150 qui tourne avec la bonne
# version de ClamAV à l'intérieur du chroot pendant lb build.
TP_BUILD=$(find "$CLAMAV_CHROOT" \( \
    -name "*.ndb" -o -name "*.hdb" -o -name "*.hsb" \
    -o -name "*.db"  -o -name "*.ftm" -o -name "*.ldb" \
    -o -name "*.cdb" -o -name "*.fp" \
    \) 2>/dev/null | wc -l)
ok "$TP_BUILD fichier(s) de signatures tierces intégrés dans le chroot"


# ── Règles YARA : pré-téléchargement sur la machine de build ──────────────────
step "Pré-téléchargement des règles YARA signature-base (machine de build)..."
YARA_CHROOT="config/includes.chroot/var/lib/yara-rules"
mkdir -p "$YARA_CHROOT/signature-base" "$YARA_CHROOT/custom"

# Téléchargement si règles absentes
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
MaxScanSize 0
MaxFileSize 0
MaxRecursion 16
MaxFiles 0
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

# Anti-veille – désactivation complète de la mise en veille / suspend
mkdir -p config/includes.chroot/etc/systemd/logind.conf.d
cat > config/includes.chroot/etc/systemd/logind.conf.d/no-suspend.conf << 'EOF'
[Login]
HandleSuspendKey=ignore
HandleHibernateKey=ignore
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
IdleAction=ignore
EOF

mkdir -p config/includes.chroot/etc/systemd/sleep.conf.d
cat > config/includes.chroot/etc/systemd/sleep.conf.d/no-sleep.conf << 'EOF'
[Sleep]
AllowSuspend=no
AllowHibernation=no
AllowSuspendThenHibernate=no
AllowHybridSleep=no
EOF

# LightDM autologin – session live (usb-antivirus-live.desktop)
mkdir -p config/includes.chroot/etc/lightdm/lightdm.conf.d
cat > config/includes.chroot/etc/lightdm/lightdm.conf.d/50-autologin.conf << 'EOF'
[Seat:*]
autologin-user=scanner
autologin-session=usb-antivirus-live
autologin-user-timeout=0
allow-guest=false
EOF

mkdir -p config/includes.chroot/etc/skel
cat > config/includes.chroot/etc/skel/.dmrc << 'EOF'
[Desktop]
Session=usb-antivirus-live
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

# Répertoires de base pour l'utilisateur scanner
mkdir -p "config/includes.chroot/home/scanner/.config/openbox"
mkdir -p "config/includes.chroot/home/scanner/Desktop"

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

# Règle polkit : sudo sans mot de passe pour le scanner (install-to-disk)
mkdir -p "config/includes.chroot/etc/polkit-1/rules.d"
cat > "config/includes.chroot/etc/polkit-1/rules.d/49-scanner-sudo.rules" << 'EOF'
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.policykit") === 0 &&
        subject.isInGroup("sudo")) {
        return polkit.Result.YES;
    }
});
EOF

ok "Tous les fichiers de configuration générés"


# =============================================================================
# Boot menus : config/includes.binary/ (méthode fiable)
#
# live-build copie config/includes.binary/ dans binary/ lors de lb_binary_includes,
# APRÈS que lb_binary_syslinux et lb_binary_grub_efi ont généré leurs configs.
# Ces fichiers écrasent donc les configs par défaut de live-build.
# Le hook 9999 (ci-dessous) agit en filet de sécurité pour les cas où
# live-build régénère les configs après lb_binary_includes.
# =============================================================================
step "Création des menus de boot (syslinux BIOS + GRUB EFI)..."

# ── Syslinux / isolinux (BIOS legacy) ────────────────────────────────────────
mkdir -p config/includes.binary/isolinux
cat > config/includes.binary/isolinux/isolinux.cfg << SYSLINUX
UI vesamenu.c32
DEFAULT live
TIMEOUT 150
PROMPT 0

MENU TITLE USB Antivirus Scanner v1.0 - Menu de demarrage

LABEL live
  MENU LABEL > Demarrer en mode Live (scanner antiviral)
  MENU DEFAULT
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd.img ${BOOT_PARAMS}

LABEL install
  MENU LABEL > Installer sur le disque (kiosque persistant)
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd.img ${BOOT_PARAMS} installer=1

LABEL live-safe
  MENU LABEL > Demarrer en mode Live - Sans echec (nomodeset)
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd.img ${BOOT_PARAMS} nomodeset
SYSLINUX

# Supprimer live.cfg par défaut (il prendrait le dessus sur isolinux.cfg)
echo "# replaced by isolinux.cfg" > config/includes.binary/isolinux/live.cfg

# ── GRUB EFI (UEFI) ──────────────────────────────────────────────────────────
mkdir -p config/includes.binary/boot/grub
cat > config/includes.binary/boot/grub/grub.cfg << GRUBMENU
set default=0
set timeout=15

if [ x\$feature_all_video_module = xy ]; then
  insmod all_video
fi

menuentry "Demarrer en mode Live (scanner antiviral)" {
  linux /live/vmlinuz ${BOOT_PARAMS}
  initrd /live/initrd.img
}

menuentry "Installer sur le disque (kiosque persistant)" {
  linux /live/vmlinuz ${BOOT_PARAMS} installer=1
  initrd /live/initrd.img
}

menuentry "Demarrer en mode Live - Sans echec (nomodeset)" {
  linux /live/vmlinuz ${BOOT_PARAMS} nomodeset
  initrd /live/initrd.img
}
GRUBMENU

# Même config pour le chemin EFI alternatif
mkdir -p config/includes.binary/EFI/boot
cp config/includes.binary/boot/grub/grub.cfg \
   config/includes.binary/EFI/boot/grub.cfg

ok "Menus de boot syslinux + GRUB EFI créés (config/includes.binary/)"

# =============================================================================
# Hook 9999 (BINAIRE) : filet de sécurité – repatche après lb_binary
# S'exécute APRÈS lb_binary_includes pour garantir les 3 entrées même si
# live-build regénère ses configs dans une phase ultérieure.
# =============================================================================
step "Création du hook de boot (filet de sécurité)..."
mkdir -p config/hooks/normal
cat << HOOK > config/hooks/normal/9999-bootmenu.hook.binary
#!/bin/bash
set -e

BOOT_PARAMS="${BOOT_PARAMS}"

# ── Syslinux (BIOS) ───────────────────────────────────────────────────────────
write_syslinux() {
    local DIR="\$1"
    [ -d "\$DIR" ] || return 0
    cat > "\$DIR/isolinux.cfg" << SYSLINUX
UI vesamenu.c32
DEFAULT live
TIMEOUT 150
PROMPT 0

MENU TITLE USB Antivirus Scanner v1.0 - Menu de demarrage

LABEL live
  MENU LABEL > Demarrer en mode Live (scanner antiviral)
  MENU DEFAULT
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd.img \${BOOT_PARAMS}

LABEL install
  MENU LABEL > Installer sur le disque (kiosque persistant)
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd.img \${BOOT_PARAMS} installer=1

LABEL live-safe
  MENU LABEL > Demarrer en mode Live - Sans echec (nomodeset)
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd.img \${BOOT_PARAMS} nomodeset
SYSLINUX
    echo "# replaced by custom boot menu" > "\$DIR/live.cfg"
    echo "[hook] syslinux patche dans \$DIR"
}

for DIR in binary/isolinux binary/boot/isolinux; do
    write_syslinux "\$DIR"
done

# ── GRUB EFI (UEFI) ───────────────────────────────────────────────────────────
write_grub() {
    local CFG="\$1"
    [ -f "\$CFG" ] || { echo "[hook] \$CFG absent, ignore"; return 0; }
    cat > "\$CFG" << GRUBMENU
set default=0
set timeout=15

if [ x\\\$feature_all_video_module = xy ]; then
  insmod all_video
fi

menuentry "Demarrer en mode Live (scanner antiviral)" {
  linux /live/vmlinuz \${BOOT_PARAMS}
  initrd /live/initrd.img
}

menuentry "Installer sur le disque (kiosque persistant)" {
  linux /live/vmlinuz \${BOOT_PARAMS} installer=1
  initrd /live/initrd.img
}

menuentry "Demarrer en mode Live - Sans echec (nomodeset)" {
  linux /live/vmlinuz \${BOOT_PARAMS} nomodeset
  initrd /live/initrd.img
}
GRUBMENU
    echo "[hook] grub patche dans \$CFG"
}

for CFG in binary/boot/grub/grub.cfg \
           binary/EFI/boot/grub.cfg  \
           binary/boot/grub/x86_64-efi/grub.cfg; do
    write_grub "\$CFG"
done
HOOK
chmod +x config/hooks/normal/9999-bootmenu.hook.binary
ok "Hook 9999-bootmenu créé"

# =============================================================================
# Build de l'ISO
# =============================================================================
step "Lancement de la build live-build (20-40 min)..."
lb build 2>&1 | tee /tmp/lb-build.log

# ── Comptage des fichiers intégrés (avant lb clean qui efface le chroot) ──────
CV_COUNT=$(find "config/includes.chroot/var/lib/clamav" \( -name "*.cvd" -o -name "*.cld" \) 2>/dev/null | wc -l)
TP_COUNT=$(find "config/includes.chroot/var/lib/clamav" \( -name "*.ndb" -o -name "*.hdb" -o -name "*.hsb" \
    -o -name "*.db" -o -name "*.ftm" -o -name "*.ldb" \
    -o -name "*.cdb" -o -name "*.fp" \) 2>/dev/null | wc -l)
YR_COUNT=$(find "config/includes.chroot/var/lib/yara-rules/signature-base" -name "*.yar" 2>/dev/null | wc -l)

# ── Récupération de l'ISO ─────────────────────────────────────────────────────
step "Récupération de l'ISO générée..."
ISO_FOUND=""
for candidate in live-image-amd64.hybrid.iso live-image-amd64.iso binary.hybrid.iso; do
    [[ -f "$candidate" ]] && { ISO_FOUND="$candidate"; break; }
done
[[ -n "$ISO_FOUND" ]] || err "ISO introuvable après la build. Consultez /tmp/lb-build.log"
ok "ISO : $ISO_FOUND ($(du -h "$ISO_FOUND" | cut -f1))"

ISO_SIZE=$(du -h "$ISO_FOUND" | cut -f1)

# ── Renommage final ───────────────────────────────────────────────────────────
step "Finalisation..."
mv "$ISO_FOUND" "$ISO_NAME"
ok "ISO finale : $ISO_NAME"

# ── Nettoyage ─────────────────────────────────────────────────────────────────
step "Nettoyage..."
lb clean

# =============================================================================
# Résumé
# =============================================================================

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo -e "${GREEN}║  🎉  BUILD TERMINÉ AVEC SUCCÈS${RESET}"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  ISO         : $ISO_NAME"
echo "║  Taille      : $ISO_SIZE"
echo "║  ClamAV      : $CV_COUNT fichier(s) de base officielle(s)"
echo "║  Signatures  : $TP_COUNT fichier(s) tiers (Sanesecurity, InterServer, URLhaus)"
echo "║  Avast       : installé (licence requise via panneau Admin)"
echo "║  YARA        : $YR_COUNT règle(s) signature-base incluses"
echo "║  Clavier     : AZERTY (fr)"
echo "║  Autologin   : scanner  (sudo sans mot de passe)"
echo "║  Code admin  : 0000  (À CHANGER au premier démarrage !)"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  MENU DE DÉMARRAGE (BIOS syslinux + UEFI GRUB) :            ║"
echo "║    1. Live       → OpenBox kiosque  (usb-antivirus)         ║"
echo "║    2. Installer  → rsync sur disque + kiosque persistant    ║"
echo "║    3. Live Safe  → Live + nomodeset                         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  ARCHITECTURE SESSION :                                     ║"
echo "║    Live     : LightDM → usb-antivirus-live.desktop          ║"
echo "║               → usb-antivirus-session.sh (OpenBox)          ║"
echo "║               → dispatcher /proc/cmdline                    ║"
echo "║                   installer=1 → install-to-disk.sh (rsync) ║"
echo "║                   (rien)      → /usr/local/bin/usb-antivirus║"
echo "║    Installé : LightDM → usb-antivirus-installed.desktop     ║"
echo "║               → usb-antivirus-session-installed.sh (xfwm4) ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  KIOSK HARDENING :                                          ║"
echo "║    • OpenBox rc.xml : fullscreen, no-decor, no menu         ║"
echo "║    • Xorg DontZap + DontVTSwitch                            ║"
echo "║    • Anti-veille (logind + sleep.conf)                      ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Pour flasher sur une clé USB :                             ║"
echo "║    sudo dd if=$ISO_NAME of=/dev/sdX bs=4M status=progress   ║"
echo "╚══════════════════════════════════════════════════════════════╝"