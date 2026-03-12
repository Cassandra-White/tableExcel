# -------- 2. Paquets --------
# samba + winbind + libnss/libpam : integration SMB dans AD billu.local
# krb5-user : authentification Kerberos (requis pour la jonction)
# acl attr : ACL POSIX etendues (setfacl / getfacl)
# lvm2 : gestion volumes logiques (Obj.3)
# mdadm : RAID logiciel (Obj.2)
# rsync : sauvegarde incrementielle (Obj.4)

apt-get update

DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    samba winbind libnss-winbind libpam-winbind \
    krb5-user smbclient \
    acl attr \
    lvm2 mdadm \
    rsync chrony net-tools curl
