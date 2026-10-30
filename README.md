# 🛡 Bastion Antiviral

Station de décontamination antivirale pour supports USB, conçue pour fonctionner en mode kiosque (plein écran, sans interaction clavier nécessaire). L'interface affiche en permanence des documents PDF de sensibilisation ou de communication pendant que l'analyse se déroule en arrière-plan.

---

## Sommaire

- [Aperçu](#aperçu)
- [Arborescence du projet](#arborescence-du-projet)
- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Créer l'ISO](#créer-liso)
- [Lancement](#lancement)
- [Interface utilisateur](#interface-utilisateur)
- [Panneau d'administration](#panneau-dadministration)
- [Visionneuse PDF](#visionneuse-pdf)
- [Moteurs antivirus](#moteurs-antivirus)
- [Structure des modules](#structure-des-modules)

---

## Aperçu

Bastion Antiviral est une application Python/Tkinter qui tourne en plein écran sur une station dédiée (ou en mode live depuis un ISO). Elle détecte automatiquement les clés USB branchées, les analyse en parallèle avec plusieurs moteurs antivirus (ClamAV, Avast, YARA), et affiche le résultat dans un journal horodaté. L'accès aux réglages est protégé par un code administrateur.

<div style="display: flex; align-items: center;">
  <img src="./img/gui.png" alt="GUI" width="600" style="margin-right: 20px;">
</div>

---

## Arborescence du projet

```
.
├── code/
│   ├── admin_auth.py       # Authentification et panneau d'administration
│   ├── antivirus_manager.py# Gestion des moteurs antivirus installés
│   ├── config.py           # Chemins et constantes globales
│   ├── db_manager.py       # Mise à jour des bases de signatures
│   ├── gui.py              # Interface graphique principale (Tkinter)
│   ├── log_handler.py      # Journalisation et export PDF des sessions
│   ├── main.py             # Point d'entrée
│   ├── pdf_viewer.py       # Visionneuse PDF cyclique (PyMuPDF)
│   ├── sandbox.py          # Isolation de chaque analyse (bubblewrap + seccomp)
│   ├── sandbox_selftest.py # Vérification du sandbox avec EICAR (sudo)
│   ├── userns_exec.py      # Helper : user namespace « identité »
│   ├── scanner.py          # Moteur de scan et résultats
│   ├── yara_worker.py      # Worker YARA exécuté dans le sandbox
│   ├── usb_manager.py      # Détection et montage des partitions USB
│   └── utils.py            # Fonctions utilitaires partagées
├── iso/
│   ├── makefile            # Génération de l'ISO ou démarrage en mode live
│   └── iso-64-bits/
│       └── forgeIso64.sh # Script de construction de l'image 64 bits
├── pdf/
│   └── *.pdf               # Documents affichés en boucle (sensibilisation, communication…)
└── README.md
```

---

## Fonctionnalités

**Analyse USB**
- Détection automatique et en temps réel des clés USB branchées
- Sélection multi-supports : plusieurs clés peuvent être analysées simultanément (scans parallèles par threading)
- Modes de scan : rapide (*quick*) ou complet (*full*)
- Suppression optionnelle des fichiers infectés
- Statistiques cumulées par session (fichiers analysés, menaces détectées, hachages uniques)

**Moteurs antivirus**
- **ClamAV** — moteur open-source, mise à jour via `freshclam` ou depuis une clé USB
- **Avast** — moteur commercial (licence requise), mise à jour de la base VPS
- **YARA** — règles personnalisées, importables depuis GitHub ou une clé USB

**Interface**
- Affichage plein écran, adapté aux bornes en libre-service
- Journal d'activité colorisé en temps réel (info / avertissement / menace / ok)
- Bandeau d'état permanent des moteurs actifs
- Export du journal de session en PDF
- Visionneuse PDF cyclique pour diffusion de contenus de sensibilisation

**Administration (protégée par code)**
- Sélection des moteurs actifs et du mode de scan
- Mise à jour des bases de signatures (en ligne ou depuis USB)
- Planification automatique via crontab (ClamAV, Avast, YARA, signatures tierces)
- Export et purge des journaux
- Analyse système complète (ClamAV, chkrootkit)
- Changement du code administrateur
- Arrêt ou redémarrage propre de la station

---

## Prérequis

| Élément | Version minimale |
|---|---|
| Python | 3.9+ |
| Tkinter | inclus dans Python standard |
| ClamAV | `apt install clamav clamav-daemon` |
| PyMuPDF | `pip install pymupdf` |
| Pillow | `pip install pillow` |
| Avast (optionnel) | paquet `.deb` officiel + licence |
| bubblewrap + python3-seccomp | `apt install bubblewrap python3-seccomp` (isolation des analyses) |

> L'application **doit être lancée avec les droits root** (`sudo`) pour accéder aux périphériques USB et exécuter les commandes système.

---

## Installation

```bash
# 1. Cloner le dépôt
git clone <url-du-depot>
cd usb-antivirus-scanner

# 2. Installer les dépendances Python
pip install pymupdf pillow

# 3. Installer ClamAV et mettre à jour la base virale
sudo apt install clamav clamav-daemon
sudo freshclam

# 4. (Optionnel) Placer vos documents PDF dans le dossier pdf/
cp mes_documents/*.pdf pdf/
```

---

## Créer l'ISO

Le `makefile` situé dans `iso/` permet de construire une image ISO bootable basée sur XFCE 64 bits, intégrant directement l'application. Deux modes sont disponibles :

```bash
cd iso

# Construire l'image ISO d'installation
make iso

# Démarrer directement en mode live (sans installation)
make live
```

Le script `xfce-64-bits/forgeIsoXfce.sh` prend en charge la construction de l'image de base, l'intégration des paquets nécessaires et la configuration du démarrage automatique de l'application.

---

## Lancement

```bash
# Depuis le dossier code/
sudo python3 main.py
```

Au premier démarrage, le code administrateur par défaut est **`0000`**. Il est **fortement conseillé** de le modifier immédiatement depuis le panneau d'administration (onglet 🔑 Sécurité).

---

## Interface utilisateur

L'écran est divisé en deux zones principales :

**Colonne gauche**
- Liste des supports USB détectés avec leur taille et leur état de montage
- Journal d'activité horodaté avec code couleur
- Boutons *Lancer l'analyse* / *Annuler*

**Colonne droite**
- Visionneuse PDF : affiche en boucle les documents du dossier `pdf/`, à raison d'une page toutes les 35 secondes

---

## Panneau d'administration

Accessible via le bouton **⚙ Administration** (en haut à droite) après saisie du code. Le panneau est organisé en onglets :

| Onglet | Contenu |
|---|---|
| 🔧 Moteurs | Activer/désactiver ClamAV, Avast, YARA — mode scan — suppression automatique |
| 📡 Supports | Vue exhaustive de tous les supports USB détectés |
| 🛡 ClamAV | Mise à jour en ligne ou depuis USB — signatures tierces |
| 🔐 Avast | Installation, licence, mise à jour de la base VPS |
| 🔍 YARA | Import de règles depuis GitHub ou depuis une clé USB |
| ⏰ Planification | Configuration des tâches crontab (freshclam, Avast, YARA…) |
| 🖥 Système | Mise à jour APT, analyse ClamAV système, chkrootkit |
| 📋 Journaux | Export vers USB, purge |
| 🔑 Sécurité | Changement du code administrateur |
| ⏻ Arrêt | Démontage propre des USB puis poweroff / reboot |
| 🚪 Quitter | Fermeture propre de l'application |

---

## Visionneuse PDF

Le dossier `pdf/` contient les documents diffusés en boucle sur la partie droite de l'écran. Ces documents sont destinés à la **sensibilisation** (bonnes pratiques informatiques, risques liés aux supports amovibles…) ou à la **communication** interne (affiches, notes d'information…).

- Les fichiers sont triés par ordre alphabétique et parcourus en cycle continu.
- Chaque page est affichée pendant **35 secondes**.
- Tout fichier `.pdf` déposé dans le dossier est automatiquement pris en compte au prochain cycle.
- Dépendances requises : `pymupdf` et `pillow`.

---

## Moteurs antivirus

### ClamAV
Moteur open-source intégré par défaut. La base de signatures est stockée dans `/var/lib/clamav` et peut être mise à jour :
- **En ligne** : via `freshclam`
- **Hors ligne** : depuis un fichier `.cvd` ou `.cld` présent sur une clé USB

### Avast
Moteur commercial optionnel. Nécessite l'installation du paquet Avast pour Linux et une licence valide. La base VPS peut être importée depuis une clé USB en environnement isolé.

### YARA
Moteur de détection par règles personnalisées. Les règles (`.yar` / `.yara`) peuvent être téléchargées depuis le dépôt [signature-base](https://github.com/Neo23x0/signature-base) sur GitHub ou importées manuellement depuis une clé USB.

---

## Sécurité

- L'application requiert les droits `root` pour monter les partitions USB et exécuter les commandes système.
- Le code administrateur est stocké sous forme de condensat SHA-256 dans `/etc/virusscanner/admin.json` (permissions `600`).
- **Isolation des analyses** : voir ci-dessous.
- La fermeture de la fenêtre principale est elle-même protégée par le code administrateur, rendant l'interface résistante aux manipulations non autorisées en contexte kiosque.

### Isolation des analyses (sandbox)

Les moteurs analysent des fichiers hostiles (parseurs d'archives, PE, PDF…) alors que l'application tourne en `root`. Pour qu'une faille d'un moteur ne compromette pas la station, **chaque moteur est lancé dans un conteneur éphémère** ([bubblewrap](https://github.com/containers/bubblewrap), mêmes primitives noyau que Docker/Podman, sans démon) créé pour l'analyse puis détruit.

| Mesure | Effet |
|---|---|
| namespaces mount / pid / ipc / uts / cgroup / **net** | aucun accès réseau, aucun processus de l'hôte visible |
| racine `tmpfs` vide, puis **lecture seule** ; `/usr`, bases et règles en lecture seule | pas d'accès à `/etc`, `/home`, logs, identifiants admin |
| support analysé monté en **lecture seule**, une seule clé par sandbox | rien n'est modifiable sur la clé, aucune autre clé n'est visible |
| capabilities : **uniquement `CAP_DAC_READ_SEARCH`** | lecture de tous les fichiers de la clé quel que soit leur propriétaire (clé ext4, droits 600) ; aucune écriture possible |
| **seccomp** généré (`python3-seccomp`) | interdit `open_by_handle_at`/`name_to_handle_at` (évasion classique liée à `CAP_DAC_READ_SEARCH`), `ptrace`, `mount`, `bpf`, `io_uring`, `keyctl`, `kexec`, `unshare`/`setns`, userns imbriqués… |
| `no_new_privs`, `--new-session`, env vidé, pas de core dump | pas d'élévation, pas d'injection TIOCSTI |
| `/tmp` éphémère borné (`SANDBOX_TMPFS_SIZE_MB`) | pas de persistance, pas de saturation du disque hôte |
| YARA exécuté par `yara_worker.py` | plus aucun parsing de fichier dans le processus du GUI |
| chemins remontés par les moteurs validés (`_accept_path`) | un moteur compromis ne peut pas faire supprimer un fichier hors de la clé |

**Deux modes** (`SANDBOX_MODE = "auto"` choisit le premier qui passe l'auto-test, réalisé au démarrage) :
- `idmap` : user namespace « identité » créé par `userns_exec.py` ; les capabilities n'existent que *dans* ce namespace (confinement maximal) ;
- `root` : sans user namespace, pour les noyaux qui les interdisent ; root réel réduit à `CAP_DAC_READ_SEARCH` + seccomp.

**Échec fermé, et jamais de faux « sain »** : si `bwrap` est absent ou si l'auto-test échoue, l'analyse est refusée (`SANDBOX_REQUIRED = True`). Toute analyse refusée, incomplète (fichier illisible, moteur absent ou en erreur) est affichée « ANALYSE INCOMPLÈTE — support NON validé » ; le message « aucune menace » n'apparaît que si tout s'est déroulé sans erreur. Le bandeau en haut de l'interface affiche l'état du sandbox.

**Avast** (`AVAST_SANDBOX_MODE`) : `strict` (défaut) exécute `scan` entièrement dans le sandbox ; s'il tente de joindre son démon, l'erreur est affichée avec la marche à suivre. `daemon` autorise l'accès au socket du démon : l'analyse est alors faite **par le démon, hors sandbox** (signalé dans le journal).

**Vérifier une installation** : `sudo python3 sandbox_selftest.py` analyse un fichier EICAR (lisible et illisible-par-autres) avec chaque moteur installé, *dans* le sandbox, et échoue si une détection manque.

### Durcissement du montage des supports

Le noyau hôte analyse lui-même la structure du système de fichiers au montage, avant tout sandbox. Pour réduire cette surface (`usb_manager.py`, `config.py`) :
- **liste blanche** `USB_ALLOWED_FSTYPES` (vfat, exfat, ntfs, ext2/3/4, iso9660, udf) ; tout autre type est refusé, et le type est passé explicitement à `mount -t` (le noyau n'essaie pas d'autres pilotes) ;
- **`nosuid,nodev,noexec`** sur chaque montage *et remontage* (`USB_MOUNT_HARDEN_OPTS`), y compris pour un montage créé par le système, qui est durci ou démonté ;
- **`noload`** sur ext3/ext4 en lecture seule : pas de rejeu du journal (aucune écriture sur un support piégé) ;
- sur l'ISO : pilotes de systèmes de fichiers inutiles **interdits au chargement** (`/etc/modprobe.d/bastion-fs-hardening.conf`) et montage automatique udisks2 par défaut en `ro,nosuid,nodev,noexec`.

### Limites connues

- Les pilotes noyau des systèmes de fichiers autorisés (vfat, exfat, ntfs, ext4, iso9660, udf) restent exposés à un support piégé : la surface est réduite, pas supprimée. Garder le noyau à jour.
- Une faille du noyau lui-même (appels système autorisés, namespaces) reste hors périmètre.
- Sans `python3-seccomp`, le sandbox reste actif mais **dégradé** (signalé « limité » dans le bandeau) : les fichiers d'un autre propriétaire en droits 600 ne sont plus lisibles et sont signalés comme *non analysés*.
- Le filtre seccomp est généré et testé sur x86-64 uniquement.
- Le comportement d'Avast dans le sandbox dépend du produit installé : utiliser `sandbox_selftest.py`.

---

## Licence

TODO