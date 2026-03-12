#!/bin/bash
set -e  # Stop script on error

# -------- 3. LVM sur sdb + sdc --------
# Vérifier que les disques existent
for DISK in /dev/sdb /dev/sdc; do
    if [ ! -b "$DISK" ]; then
        echo "Erreur : $DISK n'existe pas."
        exit 1
    fi
done
lsblk /dev/sdb /dev/sdc

VG="vg-billu-data"

# Créer les PV et VG
pvcreate -y /dev/sdb /dev/sdc
vgcreate "$VG" /dev/sdb /dev/sdc || echo "VG existe déjà, on continue..."

# Créer les LVs
lvcreate -n lv-partages -L 80G "$VG" || true
lvcreate -n lv-homes    -L 50G "$VG" || true
lvcreate -n lv-backup   -L 50G "$VG" || true

# Formater les LVs
for LV in lv-partages lv-homes lv-backup; do
    mkfs.ext4 -F -q /dev/$VG/$LV
done

# Créer les points de montage
mkdir -p /srv/samba/partages /srv/samba/homes /srv/backup

# Monter les systèmes de fichiers
mount -o defaults,acl /dev/$VG/lv-partages /srv/samba/partages
mount -o defaults,acl /dev/$VG/lv-homes    /srv/samba/homes
mount -o defaults      /dev/$VG/lv-backup   /srv/backup

# Persistance dans /etc/fstab via UUID
declare -A MOUNTS=(
    [lv-partages]="/srv/samba/partages"
    [lv-homes]="/srv/samba/homes"
    [lv-backup]="/srv/backup"
)

for LV in "${!MOUNTS[@]}"; do
    UUID=$(blkid -s UUID -o value /dev/$VG/$LV)
    MNT="${MOUNTS[$LV]}"
    OPT=$([ "$LV" = "lv-backup" ] && echo "defaults" || echo "defaults,acl")
    # Supprimer entrée existante si présente
    sed -i "/$LV/d" /etc/fstab
    echo "UUID=$UUID  $MNT  ext4  $OPT  0  2" >> /etc/fstab
done

# Monter tout
mount -a

echo "=== FS01 initialisé ==="
pvs; vgs; lvs
df -h /srv/samba/partages /srv/samba/homes /srv/backup
