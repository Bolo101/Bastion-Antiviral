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
for cmd in lb wget curl python3 unzip rsync; do
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
apt-get install -y live-build xorriso syslinux wget curl python3 unzip rsync
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
    --debian-installer live \
    --bootappend-live "boot=live components quiet splash \
hostname=antivirus-usb username=scanner \
locales=fr_FR.UTF-8 keyboard-layouts=fr" \
    --bootappend-install "modules=keyboard-configuration \
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
# Installateur graphique (option "Installer sur le disque")
calamares
os-prober
grub-common
grub2-common
shim-signed
efibootmgr
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

# ── Hook 1.5 : signatures tierces ClamAV ─────────────────────────────────────
step "Création du hook signatures tierces ClamAV..."
cat > config/hooks/normal/0150-clamav-thirdparty.hook.chroot << 'HOOK'
#!/bin/bash
# =============================================================================
# Hook 0150 – Téléchargement des signatures tierces ClamAV
#
# Sources intégrées :
#   Sanesecurity  – phishing, malwares, spam (màj horaire)
#   InterServer   – signatures généralistes
#   URLhaus       – URLs malveillantes actives (abuse.ch)
#
# Toutes les signatures sont déposées dans /var/lib/clamav/ aux côtés des
# bases officielles. ClamAV les charge automatiquement depuis ce répertoire.
# Un fichier corrompu ou trop petit est supprimé : clamscan doit pouvoir
# démarrer même si un téléchargement échoue.
# =============================================================================
set -uo pipefail      # pas de -e : on ne veut pas stopper sur un wget raté

DB_DIR="/var/lib/clamav"
LOG="/var/log/clamav-thirdparty.log"
mkdir -p "$DB_DIR"

echo ">>> [Hook TP] Début des signatures tierces ClamAV…" | tee "$LOG"

# ── Fonction de téléchargement + validation ───────────────────────────────────
# Usage : download_sig <url> <fichier> <seuil_octets>

# Vérifie qu'un fichier est bien une signature ClamAV et non une page HTML/HTTP.
# Tous les formats tiers (.ndb .hdb .hsb .ldb .cdb .db .ftm .fp .ign2) sont du
# texte brut : leur première ligne ne commence JAMAIS par '<' ou 'HTTP'.
_is_valid_clamav_file() {
    local FILE="$1"
    local HEADER
    HEADER=$(head -c 64 "$FILE" 2>/dev/null)
    # Rejeter les réponses HTML/HTTP/JSON (pages d'erreur servies en 200 OK)
    case "$HEADER" in
        '<'*|'HTTP/'*|'{"'*|'<!DOCTYPE'*|'<!doctype'*)
            return 1 ;;
    esac
    # Rejeter les fichiers entièrement vides (0 octet utile)
    [[ -n "$HEADER" ]] || return 1
    return 0
}

download_sig() {
    local URL="$1" FNAME="$2" MIN_SIZE="$3"
    local DEST="$DB_DIR/$FNAME"
    local TMP
    TMP="$(mktemp /tmp/clamtp_XXXXXX)"

    echo "  Téléchargement de $FNAME …" | tee -a "$LOG"
    if wget -q --timeout=30 --tries=3 -O "$TMP" "$URL" 2>>"$LOG"; then
        local SIZE
        SIZE=$(stat -c%s "$TMP" 2>/dev/null || echo 0)
        if [[ "$SIZE" -ge "$MIN_SIZE" ]]; then
            local VALID=true
            # Vérification contenu : rejeter les pages HTML/erreur
            if ! _is_valid_clamav_file "$TMP"; then
                echo "  ⚠ $FNAME contient du HTML/HTTP — page d'erreur masquée en 200 OK" | tee -a "$LOG"
                VALID=false
            fi
            # Vérification sigtool pour les bases officielles uniquement
            if $VALID; then
                case "$FNAME" in
                    *.cvd|*.cld)
                        if command -v sigtool &>/dev/null; then
                            sigtool --info "$TMP" &>/dev/null || {
                                echo "  ⚠ $FNAME invalide selon sigtool — ignoré" | tee -a "$LOG"
                                VALID=false
                            }
                        fi
                        ;;
                esac
            fi
            if $VALID; then
                mv "$TMP" "$DEST"
                chmod 644 "$DEST"
                chown clamav:clamav "$DEST" 2>/dev/null || true
                echo "  ✅ $FNAME installé (${SIZE} octets)" | tee -a "$LOG"
                return 0
            fi
        else
            echo "  ⚠ $FNAME trop petit (${SIZE} < ${MIN_SIZE} octets) — ignoré" | tee -a "$LOG"
        fi
    else
        echo "  ⚠ Échec téléchargement $FNAME (réseau ?)" | tee -a "$LOG"
    fi
    rm -f "$TMP"
    return 1
}

# ── Sanesecurity ──────────────────────────────────────────────────────────────
# Distribution officielle : rsync://rsync.sanesecurity.net/sanesecurity
# Fallback HTTP : http://ftp.swin.edu.au/sanesecurity/ (miroir Swinburne Univ.)
# NB : malware.expert.db/.hdb retirés (absents de la liste officielle).
# Signatures incluses : uniquement celles listées sur sanesecurity.com/usage/signatures/
echo ">>> [Hook TP] Sanesecurity…" | tee -a "$LOG"

# Liste complète établie depuis https://mirror.ihost.md/?dir=clamav/sanesecurity
# NB : ne pas utiliser winnow_phish_complete.ndb ET winnow_phish_complete_url.ndb ensemble.
#      On prend la variante _url (URLs complètes, FP plus faible).
SANE_FILES=(
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

SANE_OK=false

# Méthode 1 : rsync (méthode officielle recommandée par sanesecurity.com)
# --no-recursive : copie uniquement les fichiers du répertoire racine du module.
# Sans --no-recursive les filtres --include peuvent être silencieusement ignorés.
if command -v rsync &>/dev/null; then
    echo "  Tentative rsync://rsync.sanesecurity.net/sanesecurity …" | tee -a "$LOG"
    RSYNC_TMP="$(mktemp -d /tmp/sanesec_rsync_XXXXXX)"
    if rsync --timeout=30 --contimeout=15 --no-recursive -q \
        rsync://rsync.sanesecurity.net/sanesecurity/ "$RSYNC_TMP/" \
        2>>"$LOG"; then
        RSYNC_COUNT=$(ls "$RSYNC_TMP" 2>/dev/null | wc -l)
        if [[ "$RSYNC_COUNT" -gt 0 ]]; then
            for fname in "${SANE_FILES[@]}"; do
                if [[ -f "$RSYNC_TMP/$fname" ]]; then
                    SZ=$(stat -c%s "$RSYNC_TMP/$fname" 2>/dev/null || echo 0)
                    if [[ "$SZ" -ge 64 ]]; then
                        mv "$RSYNC_TMP/$fname" "$DB_DIR/$fname"
                        chmod 644 "$DB_DIR/$fname"
                        chown clamav:clamav "$DB_DIR/$fname" 2>/dev/null || true
                        echo "  ✅ $fname (rsync, ${SZ}o)" | tee -a "$LOG"
                    fi
                fi
            done
            SANE_OK=true
            echo "  ✅ Sanesecurity rsync OK ($RSYNC_COUNT fichiers reçus)" | tee -a "$LOG"
        else
            echo "  ⚠ rsync exit 0 mais 0 fichier — fallback HTTP" | tee -a "$LOG"
        fi
    else
        echo "  ⚠ rsync Sanesecurity inaccessible." | tee -a "$LOG"
    fi
    rm -rf "$RSYNC_TMP"
fi

# Méthode 2 : HTTP (mirror.ihost.md — miroir public vérifié)
if ! $SANE_OK; then
    echo "  Fallback HTTP Sanesecurity…" | tee -a "$LOG"
    for SANE_HTTP in \
        "https://mirror.ihost.md/clamav/sanesecurity" \
        "https://ftp.swin.edu.au/sanesecurity"; do
        if wget --timeout=15 --tries=1 -q --spider "$SANE_HTTP/sanesecurity.ftm" 2>/dev/null; then
            SANE_OK=true
            echo "  Miroir joignable : $SANE_HTTP" | tee -a "$LOG"
            for fname in "${SANE_FILES[@]}"; do
                download_sig "$SANE_HTTP/$fname" "$fname" 64 || true
            done
            break
        else
            echo "  ⚠ $SANE_HTTP inaccessible" | tee -a "$LOG"
        fi
    done
fi

$SANE_OK || echo "  ⚠ Aucune source Sanesecurity joignable." | tee -a "$LOG"

# ── InterServer (nouvelle URL — sigs.interserver.net) ─────────────────────────
echo ">>> [Hook TP] InterServer…" | tee -a "$LOG"
download_sig "http://sigs.interserver.net/interserver256.hdb" "interserver256.hdb" 500 || true
download_sig "http://sigs.interserver.net/topline.db"          "topline.db"          500 || true

# ── URLhaus (abuse.ch) ────────────────────────────────────────────────────────
echo ">>> [Hook TP] URLhaus…" | tee -a "$LOG"
URLHAUS_OK=false
for _url in \
    "https://urlhaus.abuse.ch/downloads/urlhaus.ndb" \
    "https://curbengh.github.io/malware-filter/urlhaus-filter-clam.ndb"; do
    if download_sig "$_url" "urlhaus-filter.ndb" 1000; then
        URLHAUS_OK=true; break
    fi
done
$URLHAUS_OK || echo "  ⚠ URLhaus inaccessible — signature ignorée." | tee -a "$LOG"


# ── Bilan et test de chargement ───────────────────────────────────────────────
TP_INSTALLED=$(find "$DB_DIR" \( \
    -name "*.ndb" -o -name "*.hdb" -o -name "*.hsb" \
    -o -name "*.db"  -o -name "*.ftm" -o -name "*.ldb" \
    -o -name "*.cdb" -o -name "*.fp" \
    \) 2>/dev/null | wc -l)
echo ">>> [Hook TP] $TP_INSTALLED fichier(s) tiers installé(s)." | tee -a "$LOG"

# Validation uniquement si des fichiers tiers sont présents.
# IMPORTANT : on ne teste JAMAIS chaque fichier tiers en isolation :
#   clamscan --database="fichier_unique.ndb" échoue systématiquement
#   sans les bases officielles chargées en parallèle (code 2, faux positif).
# Stratégie : test du répertoire complet (officiel + tiers). Si ça échoue,
#   isolation binaire — on déplace les fichiers tiers un à un hors du DB_DIR
#   et on reteste le répertoire complet. Quand le test repasse, le dernier
#   fichier déplacé est le coupable ; on le supprime et on remet les autres.
if [[ "$TP_INSTALLED" -gt 0 ]] && command -v clamscan &>/dev/null; then
    echo ">>> [Hook TP] Validation base complète (timeout 90s)…" | tee -a "$LOG"
    if timeout 90 clamscan --no-summary --database="$DB_DIR" /dev/null 2>/dev/null; then
        echo ">>> [Hook TP] ✅ Base complète chargée sans erreur." | tee -a "$LOG"
    else
        echo ">>> [Hook TP] ⚠ Fichier(s) tiers problématique(s) — isolation en cours…" | tee -a "$LOG"
        # Algorithme correct : boucle while qui recommence depuis le début après
        # chaque suppression. Sans ça, une fois le 1er coupable supprimé, tous
        # les fichiers suivants passent le test et sont faussement supprimés.
        CULPRITS=0
        GIVE_UP=false
        while ! timeout 90 clamscan --no-summary --database="$DB_DIR" /dev/null 2>/dev/null; do
            QDIR="$(mktemp -d /tmp/clamav_quar_XXXXXX)"
            FOUND=false
            for f in "$DB_DIR"/*.ndb "$DB_DIR"/*.hdb "$DB_DIR"/*.hsb \
                     "$DB_DIR"/*.db  "$DB_DIR"/*.ftm "$DB_DIR"/*.ldb \
                     "$DB_DIR"/*.cdb "$DB_DIR"/*.fp; do
                [[ -f "$f" ]] || continue
                BNAME=$(basename "$f")
                mv "$f" "$QDIR/"
                if timeout 60 clamscan --no-summary --database="$DB_DIR" /dev/null 2>/dev/null; then
                    # Sans ce fichier ça passe : c'est lui le coupable.
                    echo "    ❌ $BNAME défectueux — supprimé" | tee -a "$LOG"
                    rm -f "$QDIR/$BNAME"
                    CULPRITS=$((CULPRITS + 1))
                    FOUND=true
                    break   # Recommencer le while depuis zéro
                else
                    # Innocent : le remettre en place.
                    mv "$QDIR/$BNAME" "$DB_DIR/"
                fi
            done
            rm -rf "$QDIR"
            if ! $FOUND; then
                # Un tour complet sans trouver de coupable = conflit multi-fichiers
                # irrésoluble individuellement. Purge totale des fichiers tiers.
                echo ">>> [Hook TP] ⚠ Conflit non isolable — purge des fichiers tiers." | tee -a "$LOG"
                find "$DB_DIR" \( -name "*.ndb" -o -name "*.hdb" -o -name "*.hsb" \
                    -o -name "*.db" -o -name "*.ftm" -o -name "*.ldb" \
                    -o -name "*.cdb" -o -name "*.fp" \) -delete 2>/dev/null || true
                GIVE_UP=true
                break
            fi
        done
        if ! $GIVE_UP; then
            echo ">>> [Hook TP] ✅ Base assainie — $CULPRITS fichier(s) retiré(s)." | tee -a "$LOG"
        fi
    fi
fi

TP_FINAL=$(find "$DB_DIR" \( \
    -name "*.ndb" -o -name "*.hdb" -o -name "*.hsb" \
    -o -name "*.db"  -o -name "*.ftm" -o -name "*.ldb" \
    -o -name "*.cdb" -o -name "*.fp" \
    \) 2>/dev/null | wc -l)
echo ">>> [Hook TP] Terminé — $TP_FINAL fichier(s) tiers actifs." | tee -a "$LOG"
HOOK
chmod +x config/hooks/normal/0150-clamav-thirdparty.hook.chroot
ok "Hook signatures tierces ClamAV créé"

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

# ── Hook 3.5 : configuration Calamares (installateur graphique) ───────────────
step "Création du hook Calamares..."
cat > config/hooks/normal/0350-calamares.hook.chroot << 'HOOK'
#!/bin/bash
# =============================================================================
# Hook 0350 – Configuration de Calamares, l'installateur graphique.
#
# Ce hook configure Calamares pour installer sur disque le système live
# tel quel (ClamAV + YARA + scanner + XFCE), sans téléchargement réseau.
# La méthode "unsquashfs" copie le squashfs live directement sur la partition
# cible — toutes les bases virales et règles YARA sont donc préservées.
#
# Modules activés (dans l'ordre d'exécution) :
#   welcome → locale → keyboard → partition → users →
#   networkcfg → summary → unpackfs → fstab → bootloader →
#   services-systemd → grubcfg → umount → finished
# =============================================================================
set -euo pipefail
echo ">>> [Hook Calamares] Configuration de l'installateur..."

CALA_DIR="/etc/calamares"
MODULES_DIR="$CALA_DIR/modules"
BRAND_DIR="/usr/share/calamares/branding/antivirus"
mkdir -p "$MODULES_DIR" "$BRAND_DIR"

# ── Paramètres globaux ────────────────────────────────────────────────────────
cat > "$CALA_DIR/settings.conf" << 'CONF'
modules-search: [ local, /usr/lib/calamares/modules ]

sequence:
  - show:
    - welcome
    - locale
    - keyboard
    - partition
    - users
    - summary
  - exec:
    - partition
    - mount
    - unpackfs
    - machineid
    - fstab
    - locale
    - keyboard
    - localecfg
    - users
    - networkcfg
    - hwclock
    - services-systemd
    - grubcfg
    - bootloader
    - umount
  - show:
    - finished

branding: antivirus
prompt-install: true
dont-chroot: false
CONF

# ── Branding ──────────────────────────────────────────────────────────────────
cat > "$BRAND_DIR/branding.desc" << 'BRAND'
componentName: antivirus

strings:
  productName:         "USB Antivirus Scanner"
  shortProductName:    "AV Scanner"
  version:             "1.0"
  shortVersion:        "1.0"
  versionedName:       "USB Antivirus Scanner 1.0"
  shortVersionedName:  "AV Scanner 1.0"
  bootloaderEntryName: "AV Scanner"
  productUrl:          ""
  supportUrl:          ""
  knownIssuesUrl:      ""
  releaseNotesUrl:     ""

images:
  productLogo:   "logo.png"
  productIcon:   "logo.png"
  productWelcome: "languages.png"

slideshow: "show.qml"
BRAND

# Logo minimal (copie l'icône système si disponible)
if [ -f /usr/share/pixmaps/security-high.png ]; then
    cp /usr/share/pixmaps/security-high.png "$BRAND_DIR/logo.png"
elif [ -f /usr/share/icons/hicolor/48x48/apps/clamtk.png ]; then
    cp /usr/share/icons/hicolor/48x48/apps/clamtk.png "$BRAND_DIR/logo.png"
else
    # Crée une image PNG minimale 1×1 transparent pour éviter l'erreur au démarrage
    printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82' \
        > "$BRAND_DIR/logo.png"
fi
cp "$BRAND_DIR/logo.png" "$BRAND_DIR/languages.png" 2>/dev/null || true

# Slideshow minimal QML (obligatoire, sinon Calamares refuse de démarrer)
cat > "$BRAND_DIR/show.qml" << 'QML'
import QtQuick 2.0
import calamares.slideshow 1.0

Presentation {
    id: presentation
    Slide {
        anchors.fill: parent
        Text {
            anchors.centerIn: parent
            text: "Installation en cours…\n\nClamAV, YARA et toutes les bases\nvirales sont copiés sur le disque."
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: 18
            color: "#e0e0e0"
        }
        Rectangle { anchors.fill: parent; color: "#1a1a2e"; z: -1 }
    }
}
QML

# ── Module : unpackfs (copie le squashfs live → partition cible) ──────────────
# C'est l'étape clé : copie tout le système live tel quel (bases AV incluses).
cat > "$MODULES_DIR/unpackfs.conf" << 'CONF'
---
unpack:
  - source: "/run/live/medium/live/filesystem.squashfs"
    sourcefs: "squashfs"
    destination: ""
CONF

# ── Module : partition (KPMcore — partitionnement guidé) ─────────────────────
cat > "$MODULES_DIR/partition.conf" << 'CONF'
---
efiSystemPartition: "/boot/efi"
efiSystemPartitionSize: "300M"
efiSystemPartitionName: "EFI"
defaultPartitionTableType:
  - gpt
  - msdos
userSwapChoices:
  - none
  - small
  - suspend
  - file
requiredStorage: 6.0
CONF

# ── Module : users ────────────────────────────────────────────────────────────
cat > "$MODULES_DIR/users.conf" << 'CONF'
---
defaultGroups:
  - name: users
    state: create
  - name: lp
    state: create
  - name: video
    state: create
  - name: network
    state: create
  - name: storage
    state: create
  - name: wheel
    state: create
  - name: sudo
    state: create
  - name: plugdev
    state: create
  - name: cdrom
    state: create

autologinGroup: autologin
doAutologin: false
sudoersGroup: sudo
setRootPassword: true
doReusePassword: false
passwordRequirements:
  nonempty: true
  minLength: 4
  maxLength: -1
  libpwquality:
    - minlen=4
CONF

# ── Module : bootloader ───────────────────────────────────────────────────────
cat > "$MODULES_DIR/bootloader.conf" << 'CONF'
---
efiBootLoader: "grub"
grubInstall: "grub-install"
grubMkconfig: "grub-mkconfig"
grubCfg: "/boot/grub/grub.cfg"
grubProbe: "grub-probe"
efiBootLoaderId: "AV-Scanner"
installEFIFallback: true
# Calamares installe lui-même le bon paquet GRUB selon le firmware détecté.
# grub-pc (BIOS) et grub-efi-amd64 (UEFI) sont mutuellement exclusifs et ne
# peuvent pas coexister dans le chroot live — on les laisse donc à Calamares.
packages:
  - try_install:
    - grub-pc
    - grub-efi-amd64
CONF

# ── Module : services-systemd ─────────────────────────────────────────────────
# Désactive sur le système installé les services live-only inutiles.
# Active clamav-daemon pour qu'il se lance au boot sur le système installé.
cat > "$MODULES_DIR/services-systemd.conf" << 'CONF'
---
disable:
  - live-boot
  - live-config
  - live-config-components
  - live-networkmanager

enable:
  - clamav-daemon
  - NetworkManager
CONF

# ── Module : networkcfg ───────────────────────────────────────────────────────
cat > "$MODULES_DIR/networkcfg.conf" << 'CONF'
---
backend: networkmanager
CONF

# ── Module : welcome ──────────────────────────────────────────────────────────
cat > "$MODULES_DIR/welcome.conf" << 'CONF'
---
showSupportUrl:       false
showKnownIssuesUrl:   false
showReleaseNotesUrl:  false
showDonateUrl:        false
requirements:
  requiredStorage:    6
  requiredRam:        1.0
  internet:           false
  root:               true
  screen:             false
CONF

# ── Lancement auto avec polkit (pas besoin de mot de passe root) ──────────────
cat > /etc/polkit-1/rules.d/49-calamares.rules << 'POLKIT'
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.calamares") === 0 &&
        subject.isInGroup("sudo")) {
        return polkit.Result.YES;
    }
});
POLKIT

echo ">>> [Hook Calamares] ✅ Configuration terminée."
HOOK
chmod +x config/hooks/normal/0350-calamares.hook.chroot
ok "Hook Calamares créé"
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

# Autostart XFCE : s'assurer que le répertoire appartient à scanner
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

# ── 4. Reconfiguration autologin avec le compte utilisateur réel ──────────────
# Calamares crée un compte dont le nom est inconnu ici.
# On prend le premier utilisateur non-système (uid >= 1000) hors "nobody".
REAL_USER=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1; exit}' /etc/passwd)
if [ -n "$REAL_USER" ]; then
    echo ">> Autologin → $REAL_USER"
    # LightDM
    if [ -f /etc/lightdm/lightdm.conf ]; then
        sed -i "s/^autologin-user=.*/autologin-user=$REAL_USER/" \
            /etc/lightdm/lightdm.conf
    fi
    # sudo sans mot de passe pour le compte installé
    echo "$REAL_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/antivirus-user
    chmod 0440 /etc/sudoers.d/antivirus-user
    # Autostart du scanner
    XFCE_AS="/home/$REAL_USER/.config/autostart"
    mkdir -p "$XFCE_AS"
    cp /home/scanner/.config/autostart/usb-antivirus.desktop "$XFCE_AS/" \
        2>/dev/null || true
    chown -R "$REAL_USER:$REAL_USER" "/home/$REAL_USER/.config" 2>/dev/null || true
    # Wrapper usb-antivirus
    if ! [ -f /usr/local/bin/usb-antivirus ]; then
        cat > /usr/local/bin/usb-antivirus << 'WRAPPER'
#!/bin/bash
exec sudo -E python3 /opt/usb-antivirus/main.py "$@"
WRAPPER
        chmod 755 /usr/local/bin/usb-antivirus
    fi
else
    echo "⚠ Aucun utilisateur uid >= 1000 trouvé — autologin non reconfiguré"
fi

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
                rm -f "$TMP" "$WGETLOG"
                return 1
            fi
            mv "$TMP" "$DEST"; chmod 644 "$DEST"
            ok "$FNAME inclus ($(du -h "$DEST" | cut -f1))"
        else
            warn "$FNAME trop petit (${SZ} o < ${MIN} o) — ignoré"
            rm -f "$TMP"
        fi
    else
        local ERR; ERR="$(tail -3 "$WGETLOG" 2>/dev/null)"
        warn "Échec téléchargement $FNAME"
        echo "    URL    : $URL"
        echo "    Erreur : $ERR"
        rm -f "$TMP"
    fi
    rm -f "$WGETLOG"
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
                _dl_tp "$SANE_HTTP/$_fname" "$CLAMAV_CHROOT/$_fname" 64
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

# Raccourci bureau : lancer l'installateur graphique Calamares
mkdir -p "config/includes.chroot/home/scanner/Desktop"
cat > "config/includes.chroot/home/scanner/Desktop/install-to-disk.desktop" << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Installer sur le disque
GenericName=Installer le système
Comment=Copie le système live (ClamAV + YARA + scanner) sur un disque dur ou SSD
Exec=sudo -E calamares
Icon=system-software-install
Terminal=false
Categories=System;
X-XFCE-Source=file:///home/scanner/Desktop/install-to-disk.desktop
EOF
chmod +x "config/includes.chroot/home/scanner/Desktop/install-to-disk.desktop"

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

# Règle polkit pour Calamares (lancé sans mot de passe depuis le bureau)
mkdir -p "config/includes.chroot/etc/polkit-1/rules.d"
cat > "config/includes.chroot/etc/polkit-1/rules.d/49-calamares.rules" << 'EOF'
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.calamares") === 0 &&
        subject.isInGroup("sudo")) {
        return polkit.Result.YES;
    }
});
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

# ── Comptage des fichiers intégrés (avant lb clean qui efface le chroot) ──────
ISO_SIZE=$(du -h "$ISO_NAME" | cut -f1)
CV_COUNT=$(find "$CLAMAV_CHROOT" \( -name "*.cvd" -o -name "*.cld" \) 2>/dev/null | wc -l)
TP_COUNT=$(find "$CLAMAV_CHROOT" \( -name "*.ndb" -o -name "*.hdb" -o -name "*.hsb" \
    -o -name "*.db" -o -name "*.ftm" -o -name "*.ldb" \
    -o -name "*.cdb" -o -name "*.fp" \) 2>/dev/null | wc -l)
YR_COUNT=$(find "$YARA_CHROOT/signature-base" -name "*.yar" 2>/dev/null | wc -l)

# ── Nettoyage ─────────────────────────────────────────────────────────────────
step "Nettoyage..."
lb clean

# =============================================================================
# Résumé
# =============================================================================

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
echo "  MODES DE DÉMARRAGE :"
echo "    • Live   : démarre directement le scanner (mode mémoire, rien écrit)"
echo "    • Install: icône bureau 'Installer sur le disque' → Calamares"
echo "               copie le système live entier (ClamAV + YARA + scanner)"
echo "               sur le disque dur. Le service antivirus-post-install"
echo "               reconfigure le compte au premier démarrage."
echo ""
echo "  Pour flasher sur une clé USB :"
echo "    sudo dd if=$ISO_NAME of=/dev/sdX bs=4M status=progress"
echo "═══════════════════════════════════════════════════════════"