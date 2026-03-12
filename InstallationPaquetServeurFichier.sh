# -------- 2. Paquets -- Debian 13 Trixie (Samba 4.20+) --------
# samba-common-bin : inclut la commande 'net ads join'
# winbind + libnss-winbind + libpam-winbind : integration AD
# krb5-user (MIT Kerberos) : authentification Kerberos
# acl attr : ACL POSIX etendues
# lvm2 mdadm rsync : stockage et sauvegarde
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y     samba samba-common-bin winbind     libnss-winbind libpam-winbind     krb5-user smbclient     acl attr     lvm2 mdadm     rsync net-tools curl

# -------- 3. LVM
