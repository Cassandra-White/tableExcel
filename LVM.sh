# -------- 3. LVM sur sdb + sdc --------
# Verifier que les disques existent
lsblk /dev/sdb /dev/sdc

VG="vg-billu-data"

pvcreate /dev/sdb /dev/sdc
vgcreate "$VG" /dev/sdb /dev/sdc

lvcreate -n lv-partages -L 10G  "$VG"   # Dossiers J: et K:
lvcreate -n lv-homes    -L 10G  "$VG"   # Dossiers I:
lvcreate -n lv-backup   -L 20G  "$VG"   # Sauvegarde rsync (Obj.4)

mkfs.ext4 -q /dev/vg-billu-data/lv-partages
mkfs.ext4 -q /dev/vg-billu-data/lv-homes
mkfs.ext4 -q /dev/vg-billu-data/lv-backup

mkdir -p /srv/samba/partages /srv/samba/homes /srv/backup

# Monter avec acl : indispensable pour setfacl
mount -o defaults,acl /dev/vg-billu-data/lv-partages /srv/samba/partages
mount -o defaults,acl /dev/vg-billu-data/lv-homes    /srv/samba/homes
mount -o defaults      /dev/vg-billu-data/lv-backup   /srv/backup

# Persistance fstab via UUID
for LV in lv-partages lv-homes lv-backup; do
    UUID=$(blkid -s UUID -o value /dev/vg-billu-data/"$LV")
    MNT=$(mount | grep "$LV" | awk '{print $3}')
    OPT=$([ "$LV" = "lv-backup" ] && echo "defaults" || echo "defaults,acl")
    sed -i "/$LV/d" /etc/fstab
    echo "UUID=$UUID  $MNT  ext4  $OPT  0  2" >> /etc/fstab
done
mount -a

echo "=== FS01 initialise ==="
pvs; vgs; lvs
df -h /srv/samba/partages /srv/samba/homes /srv/backup
