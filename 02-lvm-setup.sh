#!/bin/bash
# 02-lvm-setup.sh -- BillU Sprint 5
# Cree le VG "vg-billu-data" sur sdb + sdc
# 3 volumes logiques : lv-data (80G) + lv-homes (50G) + lv-backup (50G)
# ATTENTION : sdb et sdc doivent etre vierges (verifier avec lsblk)

set -e   # Arreter le script si une commande echoue

echo "=== Verification des disques ==="
lsblk /dev/sdb /dev/sdc || { echo "ERREUR : sdb ou sdc manquant"; exit 1; }

# Verifier qu ils sont bien vierges (pas de partitions)
if lsblk /dev/sdb | grep -q "part"; then
    echo "ERREUR : sdb a deja des partitions -- utiliser un disque vierge"
    exit 1
fi

echo "=== Etape 1 : Creer les Physical Volumes (PV) ==="
# pvcreate "enregistre" les disques dans LVM
pvcreate /dev/sdb /dev/sdc
pvdisplay   # Verifier

echo ""
echo "=== Etape 2 : Creer le Volume Group (VG) ==="
# vgcreate cree le "pool" en regroupant les 2 PV
vgcreate vg-billu-data /dev/sdb /dev/sdc
vgdisplay   # Verifier -- tu dois voir ~190G disponibles

echo ""
echo "=== Etape 3 : Creer les Logical Volumes (LV) ==="
# lv-data : donnees partagees (80G)
lvcreate -n lv-data   -L 5G  vg-billu-data
# lv-homes : dossiers personnels (50G)
lvcreate -n lv-homes  -L 5G  vg-billu-data
# lv-backup : sauvegarde sur disque different (50G)
lvcreate -n lv-backup -L 10G  vg-billu-data
lvdisplay   # Verifier

echo ""
echo "=== Etape 4 : Formater en ext4 ==="
# ext4 = systeme de fichiers Linux standard
mkfs.ext4 -q /dev/vg-billu-data/lv-data
mkfs.ext4 -q /dev/vg-billu-data/lv-homes
mkfs.ext4 -q /dev/vg-billu-data/lv-backup
echo "[OK] Formatage ext4 termine"

echo ""
echo "=== Resume ==="
pvs   # Liste les PV
vgs   # Liste les VG
lvs   # Liste les LV
