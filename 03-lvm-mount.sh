#!/bin/bash
# 03-lvm-mount.sh -- montage des LV et persistance via fstab

set -e

echo "=== Creer les points de montage ==="
# Les dossiers ou on va "accrocher" les volumes
mkdir -p /srv/data    # pour lv-data
mkdir -p /srv/homes   # pour lv-homes
mkdir -p /srv/backup  # pour lv-backup

echo "=== Monter les volumes ==="
mount /dev/vg-billu-data/lv-data    /srv/data
mount /dev/vg-billu-data/lv-homes   /srv/homes
mount /dev/vg-billu-data/lv-backup  /srv/backup
echo "[OK] Volumes montes"

echo "=== Verifier l espace disponible ==="
df -h /srv/data /srv/homes /srv/backup

echo "=== Ajouter dans /etc/fstab pour persistence au demarrage ==="
# On utilise les UUID (identifiants uniques) plutot que /dev/sdb
# car les UUID ne changent jamais meme si on change l ordre des disques
for LV in lv-data lv-homes lv-backup; do
    UUID=$(blkid -s UUID -o value /dev/vg-billu-data/$LV)
    MNT=$(mount | grep "$LV" | awk '{print $3}')

    # Supprimer l ancienne entree si elle existe
    sed -i "/$LV/d" /etc/fstab
    sed -i "/$UUID/d" /etc/fstab

    # Ajouter la nouvelle ligne dans fstab
    echo "UUID=$UUID  $MNT  ext4  defaults  0  2" >> /etc/fstab
    echo "  [fstab] $LV -> $MNT (UUID: ${UUID:0:8}...)"
done

echo ""
echo "=== Tester fstab (re-monter tout depuis fstab) ==="
mount -a   # Si pas d erreur, fstab est correct
echo "[OK] fstab valide"

echo ""
echo "=== Etat final ==="
df -h /srv/data /srv/homes /srv/backup
cat /etc/fstab | grep "vg-billu"
