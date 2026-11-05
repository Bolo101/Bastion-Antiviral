#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# make_bastion.sh — crée / met à jour le dossier « bastion » d'une clé USB
# avec les bases de mise à jour HORS-LIGNE de la borne :
#
#   bastion/clamav/              main.cvd  daily.cvd|cld  bytecode.cvd
#   bastion/clamav-thirdparty/   signatures tierces (URLhaus, Sanesecurity, …)
#   bastion/avast/               fichier VPS Avast  (voir « Avast » ci-dessous)
#   bastion/yara/signature-base/ règles YARA (Florian Roth, GitHub)
#   bastion/yara/custom/         vos règles .yar/.yara (copiées à la main)
#   bastion/MANIFEST.tsv         date (epoch UTC) + sha256 de chaque fichier
#
# À placer à la RACINE de la clé et à lancer sur un poste Linux CONNECTÉ À
# INTERNET, clé branchée et montée en écriture :
#
#       bash /chemin/de/la/clé/make_bastion.sh [options]
#
# (« bash script » plutôt que ./script : la clé est souvent montée noexec.)
# Dans le panneau admin de la borne : onglet « MAJ offline ».
#
# Options :
#   --only LISTE            clamav,thirdparty,avast,yara (défaut : tout)
#   --avast-vps-url URL     télécharge le fichier VPS Avast à cette adresse
#   --avast-vps-file FICHIER  copie un fichier VPS déjà téléchargé
#   -h, --help
#
# Variables : AVAST_VPS_URL (équivalent de --avast-vps-url)
#
# Avast — IMPORTANT : aucune adresse publique de téléchargement du VPS pour
#   Avast Business for Linux n'est documentée ; ce script ne devine donc rien.
#   Fournissez l'URL de votre source (--avast-vps-url), un fichier déjà obtenu
#   (--avast-vps-file) ou déposez-le vous-même dans bastion/avast/ (il sera
#   pris en compte et inscrit au manifeste). Sans source, Avast est sauté et
#   l'éventuel fichier précédent est conservé.
#
# ClamAV — les bases officielles sont récupérées avec freshclam (méthode
#   officielle, mises à jour incrémentales : les fichiers déjà présents sur la
#   clé servent de point de départ). Repli sur curl/wget si freshclam est
#   absent : ClamAV limite fortement ce mode (erreur 429), à éviter.
#
# Chaque famille est traitée indépendamment : un échec (réseau, source
# indisponible…) n'efface JAMAIS la version précédente de cette famille.
# Prérequis : bash ≥ 4, curl ou wget, sha256sum, et pour YARA unzip ou python3.
# La liste des signatures tierces ci-dessous est générée à partir de
# THIRD_PARTY_SIGNATURES (db_manager.py) : la régénérer si cette liste change.
# ══════════════════════════════════════════════════════════════════════════════

set -u -o pipefail

if (( BASH_VERSINFO[0] < 4 )); then
    echo "[ERREUR] bash ≥ 4 requis (version actuelle : $BASH_VERSION)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASTION="$SCRIPT_DIR/bastion"
SIGBASE_ZIP_URL="https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
SIGBASE_YARA_PREFIX="signature-base-master/yara/"
UA="make_bastion/1.0"
CLAM_UA="ClamAV/1.0.0 (OS: linux-gnu, ARCH: $(uname -m), CPU: $(uname -m))"
RUN_EPOCH="$(date +%s)"

ONLY=""
AVAST_URL="${AVAST_VPS_URL:-}"
AVAST_FILE=""

# ── Signatures tierces ClamAV : fichier|url|url_secours|taille_min_octets ─────
read -r -d '' THIRD_PARTY_LIST <<'LIST_EOF'
urlhaus-filter.ndb|https://urlhaus.abuse.ch/downloads/urlhaus.ndb|https://curbengh.github.io/malware-filter/urlhaus-filter-clam.ndb|1000
interserver256.hdb|http://sigs.interserver.net/interserver256.hdb||500
topline.db|http://sigs.interserver.net/topline.db||500
sanesecurity.ftm|https://mirror.ihost.md/clamav/sanesecurity/sanesecurity.ftm||64
sigwhitelist.ign2|https://mirror.ihost.md/clamav/sanesecurity/sigwhitelist.ign2||64
phish.ndb|https://mirror.ihost.md/clamav/sanesecurity/phish.ndb||64
junk.ndb|https://mirror.ihost.md/clamav/sanesecurity/junk.ndb||64
jurlbl.ndb|https://mirror.ihost.md/clamav/sanesecurity/jurlbl.ndb||64
jurlbla.ndb|https://mirror.ihost.md/clamav/sanesecurity/jurlbla.ndb||64
lott.ndb|https://mirror.ihost.md/clamav/sanesecurity/lott.ndb||64
scam.ndb|https://mirror.ihost.md/clamav/sanesecurity/scam.ndb||64
blurl.ndb|https://mirror.ihost.md/clamav/sanesecurity/blurl.ndb||64
spam.ldb|https://mirror.ihost.md/clamav/sanesecurity/spam.ldb||64
shelter.ldb|https://mirror.ihost.md/clamav/sanesecurity/shelter.ldb||64
spear.ndb|https://mirror.ihost.md/clamav/sanesecurity/spear.ndb||64
spearl.ndb|https://mirror.ihost.md/clamav/sanesecurity/spearl.ndb||64
badmacro.ndb|https://mirror.ihost.md/clamav/sanesecurity/badmacro.ndb||64
rogue.hdb|https://mirror.ihost.md/clamav/sanesecurity/rogue.hdb||64
spamimg.hdb|https://mirror.ihost.md/clamav/sanesecurity/spamimg.hdb||64
spamattach.hdb|https://mirror.ihost.md/clamav/sanesecurity/spamattach.hdb||64
malwarehash.hsb|https://mirror.ihost.md/clamav/sanesecurity/malwarehash.hsb||64
hackingteam.hsb|https://mirror.ihost.md/clamav/sanesecurity/hackingteam.hsb||64
foxhole_generic.cdb|https://mirror.ihost.md/clamav/sanesecurity/foxhole_generic.cdb||64
foxhole_filename.cdb|https://mirror.ihost.md/clamav/sanesecurity/foxhole_filename.cdb||64
foxhole_js.cdb|https://mirror.ihost.md/clamav/sanesecurity/foxhole_js.cdb||64
foxhole_js.ndb|https://mirror.ihost.md/clamav/sanesecurity/foxhole_js.ndb||64
foxhole_all.cdb|https://mirror.ihost.md/clamav/sanesecurity/foxhole_all.cdb||64
foxhole_all.ndb|https://mirror.ihost.md/clamav/sanesecurity/foxhole_all.ndb||64
foxhole_mail.cdb|https://mirror.ihost.md/clamav/sanesecurity/foxhole_mail.cdb||64
foxhole_links.ldb|https://mirror.ihost.md/clamav/sanesecurity/foxhole_links.ldb||64
MiscreantPunch099-Low.ldb|https://mirror.ihost.md/clamav/sanesecurity/MiscreantPunch099-Low.ldb||64
MiscreantPunch099-INFO-Low.ldb|https://mirror.ihost.md/clamav/sanesecurity/MiscreantPunch099-INFO-Low.ldb||64
porcupine.ndb|https://mirror.ihost.md/clamav/sanesecurity/porcupine.ndb||64
porcupine.hsb|https://mirror.ihost.md/clamav/sanesecurity/porcupine.hsb||64
phishtank.ndb|https://mirror.ihost.md/clamav/sanesecurity/phishtank.ndb||64
bofhland_cracked_URL.ndb|https://mirror.ihost.md/clamav/sanesecurity/bofhland_cracked_URL.ndb||64
bofhland_malware_URL.ndb|https://mirror.ihost.md/clamav/sanesecurity/bofhland_malware_URL.ndb||64
bofhland_phishing_URL.ndb|https://mirror.ihost.md/clamav/sanesecurity/bofhland_phishing_URL.ndb||64
bofhland_malware_attach.hdb|https://mirror.ihost.md/clamav/sanesecurity/bofhland_malware_attach.hdb||64
winnow_malware.hdb|https://mirror.ihost.md/clamav/sanesecurity/winnow_malware.hdb||64
winnow_malware_links.ndb|https://mirror.ihost.md/clamav/sanesecurity/winnow_malware_links.ndb||64
winnow_spam_complete.ndb|https://mirror.ihost.md/clamav/sanesecurity/winnow_spam_complete.ndb||64
winnow_phish_complete_url.ndb|https://mirror.ihost.md/clamav/sanesecurity/winnow_phish_complete_url.ndb||64
winnow.complex.patterns.ldb|https://mirror.ihost.md/clamav/sanesecurity/winnow.complex.patterns.ldb||64
winnow_extended_malware.hdb|https://mirror.ihost.md/clamav/sanesecurity/winnow_extended_malware.hdb||64
winnow_extended_malware_links.ndb|https://mirror.ihost.md/clamav/sanesecurity/winnow_extended_malware_links.ndb||64
winnow.attachments.hdb|https://mirror.ihost.md/clamav/sanesecurity/winnow.attachments.hdb||64
doppelstern.ndb|https://mirror.ihost.md/clamav/sanesecurity/doppelstern.ndb||64
doppelstern.hdb|https://mirror.ihost.md/clamav/sanesecurity/doppelstern.hdb||64
doppelstern-phishtank.ndb|https://mirror.ihost.md/clamav/sanesecurity/doppelstern-phishtank.ndb||64
crdfam.clamav.hdb|https://mirror.ihost.md/clamav/sanesecurity/crdfam.clamav.hdb||64
scamnailer.ndb|https://mirror.ihost.md/clamav/sanesecurity/scamnailer.ndb||64
malware.expert.ndb|https://mirror.ihost.md/clamav/sanesecurity/malware.expert.ndb||64
malware.expert.hdb|https://mirror.ihost.md/clamav/sanesecurity/malware.expert.hdb||64
malware.expert.ldb|https://mirror.ihost.md/clamav/sanesecurity/malware.expert.ldb||64
malware.expert.fp|https://mirror.ihost.md/clamav/sanesecurity/malware.expert.fp||64
LIST_EOF

# ── Utilitaires ───────────────────────────────────────────────────────────────
have()  { command -v "$1" >/dev/null 2>&1; }
info()  { printf '%s\n' "$*"; }
ok()    { printf '[OK] %s\n' "$*"; }
warn()  { printf '[ATTENTION] %s\n' "$*" >&2; }
err()   { printf '[ERREUR] %s\n' "$*" >&2; }
want()  { [[ -z "$ONLY" || ",$ONLY," == *",$1,"* ]]; }

usage() { sed -n '2,/^set -u/{/^set -u/!p}' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while (( $# )); do
    case "$1" in
        --only)            ONLY="${2:-}"; shift 2 ;;
        --avast-vps-url)   AVAST_URL="${2:-}"; shift 2 ;;
        --avast-vps-file)  AVAST_FILE="${2:-}"; shift 2 ;;
        -h|--help)         usage; exit 0 ;;
        *) err "option inconnue : $1 (voir --help)"; exit 1 ;;
    esac
done

# fetch URL DEST [délai_max_s] [user-agent]
fetch() {
    local url="$1" dest="$2" max="${3:-120}" ua="${4:-$UA}"
    if have curl; then
        curl -fsSL --connect-timeout 15 --max-time "$max" -A "$ua" -o "$dest" "$url"
    elif have wget; then
        wget -q -T 30 --tries=2 -U "$ua" -O "$dest" "$url"
    else
        return 127
    fi
}

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

# Remplace le dossier $2 par le dossier $1 (restaure l'ancien si le déplacement échoue)
swap_dir() {
    local new="$1" target="$2" bak="$2.old.$$"
    [[ -d "$target" ]] && mv "$target" "$bak"
    if mv "$new" "$target"; then
        rm -rf "$bak"
    else
        [[ -d "$bak" ]] && mv "$bak" "$target"
        return 1
    fi
}

# Reprend le contenu existant d'une famille comme base de départ
seed_stage() { # <dossier existant> <stage>
    mkdir -p "$2"
    if [[ -d "$1" ]]; then
        find "$1" -maxdepth 1 -type f ! -name '.*' -exec cp -f {} "$2"/ \; 2>/dev/null
    fi
}

# ── Préparation ───────────────────────────────────────────────────────────────
have sha256sum || { err "commande requise absente : sha256sum"; exit 1; }
have curl || have wget || { err "curl ou wget requis"; exit 1; }

mkdir -p "$BASTION" || { err "impossible de créer $BASTION (clé en lecture seule ?)"; exit 1; }
WORK="$(mktemp -d "$BASTION/.work.XXXXXX")" || { err "zone de travail impossible sur la clé"; exit 1; }
trap 'rm -rf "$WORK"' EXIT INT TERM

avail_mb=$(( $(df --output=avail -B1 "$BASTION" 2>/dev/null | tail -n1 | tr -dc '0-9') / 1048576 ))
(( avail_mb > 0 && avail_mb < 1200 )) && \
    warn "seulement ${avail_mb} Mo libres sur la clé (≈ 1,2 Go conseillés pour ClamAV)"

declare -A OLD_EPOCH=() OLD_SHA=() MINB=()
if [[ -f "$BASTION/MANIFEST.tsv" ]]; then
    while IFS=$'\t' read -r kind rel epoch sha extra; do
        [[ -z "$kind" || "$kind" == \#* ]] && continue
        OLD_EPOCH["$rel"]="$epoch"; OLD_SHA["$rel"]="$sha"
    done < "$BASTION/MANIFEST.tsv"
fi

FAILED=()

# ══════════════════════════════════════════════════════════════════════════════
# ClamAV (bases officielles)
# ══════════════════════════════════════════════════════════════════════════════
valid_cvd() { # fichier
    [[ "$(head -c 10 "$1" 2>/dev/null)" == "ClamAV-VDB" ]] || return 1
    if [[ "$1" == *.cvd ]] && have sigtool; then
        sigtool --info "$1" 2>&1 | grep -q "Verification OK" || return 1
    fi
    return 0
}

do_clamav() {
    info "── ClamAV (bases officielles) ──"
    local stage="$WORK/clamav"
    seed_stage "$BASTION/clamav" "$stage"
    find "$stage" -type f ! -name '*.cvd' ! -name '*.cld' -delete 2>/dev/null

    if have freshclam; then
        info "freshclam (mise à jour incrémentale depuis le contenu de la clé)…"
        local conf="$WORK/freshclam.conf"
        {
            echo "DatabaseDirectory $stage"
            echo "DatabaseMirror database.clamav.net"
            echo "DatabaseOwner $(id -un)"
            echo "ScriptedUpdates yes"
            echo "Bytecode yes"
        } > "$conf"
        freshclam --stdout --config-file="$conf" --datadir="$stage"
        local rc=$?
        if (( rc != 0 && rc != 1 )); then
            err "freshclam a échoué (code $rc)"
            return 1
        fi
    else
        warn "freshclam absent : repli sur téléchargement direct (ClamAV peut répondre 429)"
        local f
        for f in main daily bytecode; do
            info "téléchargement de $f.cvd…"
            if fetch "https://database.clamav.net/$f.cvd" "$stage/$f.cvd.part" 900 "$CLAM_UA"; then
                mv -f "$stage/$f.cvd.part" "$stage/$f.cvd"
            else
                rm -f "$stage/$f.cvd.part"
                warn "$f.cvd : téléchargement impossible"
            fi
        done
    fi

    local f n=0 has_main=0 has_daily=0
    for f in "$stage"/*.cvd "$stage"/*.cld; do
        [[ -f "$f" ]] || continue
        if valid_cvd "$f"; then
            n=$((n + 1))
            case "$(basename "$f")" in main.*) has_main=1 ;; daily.*) has_daily=1 ;; esac
        else
            warn "$(basename "$f") invalide (en-tête ou signature) : retiré"
            rm -f "$f"
        fi
    done
    if (( ! has_main || ! has_daily )); then
        err "ClamAV : main et daily sont requis (obtenus : $n fichier(s)) — version précédente conservée"
        return 1
    fi
    swap_dir "$stage" "$BASTION/clamav" || { err "ClamAV : remplacement du dossier impossible"; return 1; }
    ok "ClamAV : $n base(s) dans bastion/clamav/"
}

# ══════════════════════════════════════════════════════════════════════════════
# Signatures tierces ClamAV
# ══════════════════════════════════════════════════════════════════════════════
valid_text_sig() { # fichier taille_min
    local sz; sz=$(stat -c %s "$1" 2>/dev/null || echo 0)
    (( sz >= $2 )) || return 1
    local head; head="$(head -c 16 "$1" | tr -d '\0')"
    [[ "$head" == "<"* || "$head" == "HTTP/"* || "$head" == '{"'* ]] && return 1
    return 0
}

do_thirdparty() {
    info "── Signatures tierces ClamAV ──"
    local stage="$WORK/thirdparty" good=0 bad=0 badnames=()
    seed_stage "$BASTION/clamav-thirdparty" "$stage"
    local file url url2 minb tmp
    while IFS='|' read -r file url url2 minb; do
        [[ -z "$file" || "$file" == \#* ]] && continue
        tmp="$stage/.$file.part"
        if fetch "$url" "$tmp" 90 \
           || { [[ -n "$url2" ]] && fetch "$url2" "$tmp" 90; }; then
            if valid_text_sig "$tmp" "${minb:-64}"; then
                mv -f "$tmp" "$stage/$file"; good=$((good + 1)); continue
            fi
            badnames+=("$file (contenu invalide)")
        else
            badnames+=("$file (inaccessible)")
        fi
        rm -f "$tmp"; bad=$((bad + 1))
    done <<< "$THIRD_PARTY_LIST"
    if (( bad > 0 && bad <= 8 )); then
        local b; for b in "${badnames[@]}"; do warn "$b — version précédente conservée"; done
    elif (( bad > 8 )); then
        warn "$bad fichier(s) non mis à jour (versions précédentes conservées) : ${badnames[*]:0:5} …"
    fi

    if (( good == 0 )); then
        err "signatures tierces : aucune source accessible — rien modifié"
        return 1
    fi
    swap_dir "$stage" "$BASTION/clamav-thirdparty" || { err "remplacement du dossier impossible"; return 1; }
    ok "signatures tierces : $good téléchargée(s), $bad inchangée(s)/en échec"
}

# ══════════════════════════════════════════════════════════════════════════════
# Avast (fichier VPS)
# ══════════════════════════════════════════════════════════════════════════════
avast_name() { # nom → nom compatible avec les motifs reconnus par la borne
    local n="$1"
    case "${n,,}" in
        *.vps|vps*.zip|avast_vps*|*.vpz) printf '%s' "$n" ;;
        *) printf 'avast_vps_%s' "$n" ;;
    esac
}

do_avast() {
    info "── Avast (base VPS) ──"
    local stage="$WORK/avast" name
    mkdir -p "$stage"
    if [[ -n "$AVAST_FILE" ]]; then
        [[ -f "$AVAST_FILE" ]] || { err "Avast : fichier introuvable : $AVAST_FILE"; return 1; }
        name="$(avast_name "$(basename "$AVAST_FILE")")"
        cp -f "$AVAST_FILE" "$stage/$name" || { err "Avast : copie impossible"; return 1; }
    elif [[ -n "$AVAST_URL" ]]; then
        name="$(avast_name "$(basename "${AVAST_URL%%\?*}")")"
        info "téléchargement de $name…"
        if ! fetch "$AVAST_URL" "$stage/$name.part" 1800; then
            rm -f "$stage/$name.part"
            err "Avast : téléchargement impossible — version précédente conservée"
            return 1
        fi
        mv -f "$stage/$name.part" "$stage/$name"
    else
        local existing; existing=$(find "$BASTION/avast" -maxdepth 1 -type f ! -name '.*' 2>/dev/null | wc -l)
        if (( existing > 0 )); then
            ok "Avast : aucune source indiquée, $existing fichier(s) déjà présent(s) conservé(s)"
            return 0
        fi
        warn "Avast : aucune source (--avast-vps-url / --avast-vps-file / dépôt manuel dans bastion/avast/) — sauté"
        mkdir -p "$BASTION/avast"
        return 0
    fi
    local sz; sz=$(stat -c %s "$stage/$name")
    if (( sz < 100000 )) || ! valid_text_sig "$stage/$name" 100000; then
        err "Avast : $name semble invalide ($sz octets) — version précédente conservée"
        return 1
    fi
    # Un seul VPS à la fois dans le bastion : le nouveau remplace les anciens
    swap_dir "$stage" "$BASTION/avast" || { err "Avast : remplacement du dossier impossible"; return 1; }
    ok "Avast : $name ($((sz / 1048576)) Mo)"
}

# ══════════════════════════════════════════════════════════════════════════════
# YARA (signature-base) — yara/custom est laissé tel quel
# ══════════════════════════════════════════════════════════════════════════════
extract_yara() { # zip dossier_sortie
    if have unzip; then
        unzip -qq -j -o "$1" "${SIGBASE_YARA_PREFIX}*" -d "$2"
    elif have python3; then
        python3 - "$1" "$2" "$SIGBASE_YARA_PREFIX" <<'PY'
import os, sys, zipfile
zpath, out, prefix = sys.argv[1:4]
with zipfile.ZipFile(zpath) as zf:
    for m in zf.namelist():
        if m.startswith(prefix) and not m.endswith("/"):
            with zf.open(m) as s, open(os.path.join(out, os.path.basename(m)), "wb") as d:
                d.write(s.read())
PY
    else
        return 127
    fi
}

do_yara() {
    info "── YARA (signature-base) ──"
    local stage="$WORK/yara" zip="$WORK/signature-base.zip"
    mkdir -p "$stage"
    info "téléchargement de signature-base (≈ 30 Mo)…"
    if ! fetch "$SIGBASE_ZIP_URL" "$zip" 900; then
        err "YARA : téléchargement impossible — version précédente conservée"
        return 1
    fi
    if ! extract_yara "$zip" "$stage"; then
        err "YARA : extraction impossible (unzip ou python3 requis, archive valide ?)"
        return 1
    fi
    find "$stage" -type f ! -name '*.yar' ! -name '*.yara' -delete
    local n; n=$(find "$stage" -maxdepth 1 -type f \( -name '*.yar' -o -name '*.yara' \) | wc -l)
    if (( n == 0 )); then
        err "YARA : aucune règle trouvée dans l'archive — version précédente conservée"
        return 1
    fi
    mkdir -p "$BASTION/yara/custom"
    swap_dir "$stage" "$BASTION/yara/signature-base" || { err "YARA : remplacement du dossier impossible"; return 1; }
    ok "YARA : $n règle(s) dans bastion/yara/signature-base/"
}

# ══════════════════════════════════════════════════════════════════════════════
# Manifeste : (re)généré d'après le contenu réel du bastion
#   epoch conservé si le fichier n'a pas changé, sinon date de cette exécution
# ══════════════════════════════════════════════════════════════════════════════
write_manifest() {
    while IFS='|' read -r file _ _ minb; do
        [[ -n "$file" && "$file" != \#* ]] && MINB["$file"]="${minb:-64}"
    done <<< "$THIRD_PARTY_LIST"

    local out="$WORK/MANIFEST.tsv" kind sub f rel sha epoch extra
    {
        echo "# bastion-manifest v1"
        echo "# generated_epoch=$RUN_EPOCH generated=$(date -u +%Y-%m-%dT%H:%M:%SZ) host=$(hostname -s 2>/dev/null || echo ?) tool=make_bastion.sh"
        echo "# colonnes: kind<TAB>relpath<TAB>epoch<TAB>sha256<TAB>extra"
    } > "$out"
    for entry in "clamav:clamav" "thirdparty:clamav-thirdparty" "avast:avast" \
                 "yara:yara/signature-base" "yara-custom:yara/custom"; do
        kind="${entry%%:*}"; sub="${entry#*:}"
        [[ -d "$BASTION/$sub" ]] || continue
        while IFS= read -r -d '' f; do
            rel="$sub/$(basename "$f")"
            sha="$(sha_of "$f")"
            if [[ "${OLD_SHA[$rel]:-}" == "$sha" && -n "${OLD_EPOCH[$rel]:-}" ]]; then
                epoch="${OLD_EPOCH[$rel]}"
            else
                epoch="$RUN_EPOCH"
            fi
            extra=""
            [[ "$kind" == "thirdparty" ]] && extra="${MINB[$(basename "$f")]:-64}"
            printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$rel" "$epoch" "$sha" "$extra" >> "$out"
        done < <(find "$BASTION/$sub" -maxdepth 1 -type f ! -name '.*' -print0 | sort -z)
    done
    mv -f "$out" "$BASTION/MANIFEST.tsv"
    ok "manifeste écrit : $(grep -vc '^#' "$BASTION/MANIFEST.tsv") fichier(s) référencé(s)"
}

# ══════════════════════════════════════════════════════════════════════════════
info "Bastion : $BASTION"
info "Date    : $(date '+%Y-%m-%d %H:%M:%S')"
info ""

want clamav     && { do_clamav     || FAILED+=("clamav");     info ""; }
want thirdparty && { do_thirdparty || FAILED+=("thirdparty"); info ""; }
want avast      && { do_avast      || FAILED+=("avast");      info ""; }
want yara       && { do_yara       || FAILED+=("yara");       info ""; }

mkdir -p "$BASTION/clamav" "$BASTION/clamav-thirdparty" "$BASTION/avast" \
         "$BASTION/yara/signature-base" "$BASTION/yara/custom" 2>/dev/null
write_manifest
sync

info ""
if (( ${#FAILED[@]} )); then
    warn "terminé avec des familles en échec : ${FAILED[*]} (leurs versions précédentes sont conservées)"
    exit 1
fi
ok "bastion à jour — vous pouvez démonter la clé et la brancher sur la borne"
exit 0