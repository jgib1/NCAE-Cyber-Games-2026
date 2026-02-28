#!/bin/bash
set -e

#Config — Change these first - may set up a read later
#################################################################################################
TEAM_NUM="20"
DNS_HOSTNAME="ns01"
INTERNAL_IP="192.168.${TEAM_NUM}.12"
INTERNAL_SUBNET="192.168.${TEAM_NUM}.0/24"
EXTERNAL_DNS="172.18.0.12"
EXTERNAL_SUBNET="172.18.0.0/16"
EXTERNAL_ROUTER_IP="172.18.13.${TEAM_NUM}"
EXTERNAL_ROUTER_OCTET3=$(echo ${EXTERNAL_ROUTER_IP} | cut -d. -f3)
EXTERNAL_ROUTER_OCTET4=$(echo ${EXTERNAL_ROUTER_IP} | cut -d. -f4)
EXTERNAL_REVERSE_ZONE="18.172"
SERIAL=$(date +%Y%m%d01)
DOMAIN="team20.ncaecybergames.org"
#################################################################################################

#Internal Network IPs
IP_ROUTER="192.168.${TEAM_NUM}.1"
IP_WEB="192.168.${TEAM_NUM}.5"
IP_DB="192.168.${TEAM_NUM}.7"
IP_DNS="192.168.${TEAM_NUM}.12"
IP_BACKUP="192.168.${TEAM_NUM}.15"

#Reverse
REVERSE_ZONE="${TEAM_NUM}.168.192"

#Zone/Log paths
ZONE_DIR="/var/named/zones"
ZONE_INTERNAL="${ZONE_DIR}/forward.internal.${DOMAIN}"
ZONE_EXTERNAL="${ZONE_DIR}/forward.external.${DOMAIN}"
ZONE_REVERSE_INT="${ZONE_DIR}/reverse.internal.${DOMAIN}"
ZONE_REVERSE_EXT="${ZONE_DIR}/reverse.external.${DOMAIN}"
LOG_DIR="/var/log/named"

#FUN COLORS!!!
#################################################################################################
info()    { echo -e "\e[32m[INFO]\e[0m    $1"; }
warn()    { echo -e "\e[33m[WARN]\e[0m    $1"; }
error()   { echo -e "\e[31m[ERROR]\e[0m   $1"; exit 1; }
section() { echo -e "\n\e[36m(╯°□°）╯︵ ┻━┻  $1 ┬─┬﻿ ノ( ゜-゜ノ)\e[0m"; }


#Check that script is being run as root
################################################################################################
#https://askubuntu.com/questions/15853/how-can-a-script-check-if-its-being-run-as-root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

#0 - Set Hostname
#################################################################################################
section "Setting Hostname"
if [[ "$HOSTNAME" != "$DNS_HOSTNAME" ]]; then
	hostnamectl set-hostname "$DNS_HOSTNAME"
	info "Hostname Set to $DNS_HOSTNAME Successfully"
else
	info "DNS Hostname is already $DNS_HOSTNAME"
fi


#1 - Install BIND9
#################################################################################################
section "Installing BIND9"
if rpm -q bind &>/dev/null; then
    info "bind already installed, skipping."
else
    dnf install -y bind bind-utils
    info "bind installed successfully."
fi


#2 - Create directories
#################################################################################################
section "Creating Directories"
mkdir -p "${ZONE_DIR}"
mkdir -p "${LOG_DIR}"
info "Created ${ZONE_DIR}"
info "Created ${LOG_DIR}"


#3 - Create internal forward zone file
#################################################################################################
section "Creating Internal Forward Zone File"
cat > "${ZONE_INTERNAL}" << EOF
\$TTL 10800
@	IN	SOA	${DNS_HOSTNAME}.${DOMAIN}. hostmaster.${DOMAIN}. (
            ${SERIAL} ; Serial
            3600      ; Refresh
            1800      ; Retry
            604800    ; Expire
            86400 )   ; Minimum TTL

;
@	IN	NS	${DNS_HOSTNAME}.${DOMAIN}.
${DNS_HOSTNAME} IN A ${INTERNAL_IP}
router	IN  A   ${IP_ROUTER}
web     	IN  A   ${IP_WEB}
db      	IN  A   ${IP_DB}
dns     	IN  A   ${IP_DNS}
backup  IN  A   ${IP_BACKUP}
www				IN  A   ${IP_WEB}
EOF
info "Internal forward zone created."


#4 - Create external forward zone file
#################################################################################################
section "Creating External Forward Zone File"
cat > "${ZONE_EXTERNAL}" << EOF
\$TTL 10800
@	IN	SOA	${DNS_HOSTNAME}.${DOMAIN}. hostmaster.${DOMAIN}. (
			${SERIAL} ; Serial
            3600      ; Refresh
            1800      ; Retry
            604800    ; Expire
            86400 )   ; Minimum TTL

;
@		IN  NS ${DNS_HOSTNAME}.${DOMAIN}.
${DNS_HOSTNAME}		IN  A   ${EXTERNAL_ROUTER_IP}
router  	               IN  A   ${EXTERNAL_ROUTER_IP}
web		IN  A   ${EXTERNAL_ROUTER_IP}
www                    IN  A   ${EXTERNAL_ROUTER_IP}
EOF
info "External forward zone created."


#5 - Create internal reverse zone file
#################################################################################################
section "Creating Internal Reverse Zone File"
cat > "${ZONE_REVERSE_INT}" << EOF
\$TTL 10800
@   IN  SOA	${DNS_HOSTNAME}.${DOMAIN}. hostmaster.${DOMAIN}. (
            ${SERIAL} ; Serial
            3600      ; Refresh
            1800      ; Retry
            604800    ; Expire
            86400 )   ; Minimum TTL

;
@	IN  NS  ${DNS_HOSTNAME}.${DOMAIN}.
1	IN  PTR router.${DOMAIN}.
5            IN  PTR web.${DOMAIN}.
7            IN  PTR db.${DOMAIN}.
12          IN  PTR ${DNS_HOSTNAME}.${DOMAIN}.
15          IN  PTR backup.${DOMAIN}.
EOF
info "Internal reverse zone created."


#6 - Create external reverse zone file
#################################################################################################
section "Creating External Reverse Zone File"
cat > "${ZONE_REVERSE_EXT}" << EOF
\$TTL 10800
@   IN  SOA	${DNS_HOSTNAME}.${DOMAIN}. hostmaster.${DOMAIN}. (
            ${SERIAL} ; Serial
            3600      ; Refresh
            1800      ; Retry
            604800    ; Expire
            86400 )   ; Minimum TTL

;
@       IN  NS  ${DNS_HOSTNAME}.${DOMAIN}.
${EXTERNAL_ROUTER_OCTET4}.${EXTERNAL_ROUTER_OCTET3}  IN  PTR  router.${DOMAIN}.
EOF
info "External reverse zone created."


#7 - Create named.conf
#################################################################################################
section "Creating /etc/named.conf"
if [[ -f /etc/named.conf ]]; then
    cp /etc/named.conf "/etc/named.conf.bak.$(date +%F_%T)"
    info "Backed up original named.conf"
fi

cat > /etc/named.conf << EOF

options {
    listen-on port 53       { 127.0.0.1; ${INTERNAL_IP}; ${EXTERNAL_SUBNET}; };
    listen-on-v6 port 53    { none; };
    directory               "/var/named";
    dump-file               "/var/named/data/cache_dump.db";
    statistics-file         "/var/named/data/named_stats.txt";
    memstatistics-file      "/var/named/data/named_mem_stats.txt";
    secroots-file           "/var/named/data/named.secroots";
    recursing-file          "/var/named/data/named.recursing";

    // Allow queries from trusted networks only
    allow-query             { localhost; ${INTERNAL_SUBNET}; ${EXTERNAL_SUBNET}; };
    recursion               no;
    allow-transfer          { none; };
    allow-update            { none; };

    // Security hardening
    dnssec-validation       no;
    version                 "none";        // Hide BIND version

    managed-keys-directory  "/var/named/dynamic";
    geoip-directory        "/usr/share/GeoIP";
    pid-file                       "/run/named/named.pid";
    session-keyfile         "/run/named/session.key";

    include "/etc/crypto-policies/back-ends/bind.config";
};

logging {
    channel default_debug {
        file "data/named.run";
        severity dynamic;
    };

    channel query_log {
        file "${LOG_DIR}/queries.log" versions 3 size 5m;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };

    category queries        { query_log; };
    category query-errors   { query_log; };
};

// Split Horizon 
view "internal" {
    match-clients           { localhost; ${INTERNAL_SUBNET}; };
    forwarders              { ${EXTERNAL_DNS}; };       
    forward                 only;      
    recursion               yes;
    allow-recursion         { localhost; ${INTERNAL_SUBNET}; };

    zone "." IN {
        type hint;
        file "named.ca";
    };

    zone "${DOMAIN}" IN {
        type master;
        file "zones/forward.internal.${DOMAIN}";
        allow-query         { localhost; ${INTERNAL_SUBNET}; };
    };

    zone "${REVERSE_ZONE}.in-addr.arpa" IN {
        type master;
        file "zones/reverse.internal.${DOMAIN}";
        allow-query         { localhost; ${INTERNAL_SUBNET}; };
    };

    include "/etc/named.rfc1912.zones";
    include "/etc/named.root.key";
};

view "external" {
    match-clients           { ${EXTERNAL_SUBNET}; any; };
    recursion               no;

    zone "${DOMAIN}" IN {
        type master;
        file "zones/forward.external.${DOMAIN}";
        allow-query         { any; };
    };

    zone "${EXTERNAL_REVERSE_ZONE}.in-addr.arpa" IN {
        type master;
        file "zones/reverse.external.${DOMAIN}";
        allow-query         { any; };
    };

};
EOF
info "named.conf created."


#8 - Fix SELinux/Permissions/Ownership
#################################################################################################
section "SELinux Fun"

chown named:named "${ZONE_DIR}"
chown named:named "${ZONE_DIR}"/*
chmod 750 "${ZONE_DIR}"
chmod 640 "${ZONE_DIR}"/*
info "Zone file ownership/permissions set."

chown named:named "${LOG_DIR}"
chmod 750 "${LOG_DIR}"
info "Log directory ownership/permissions set."

chown root:named /etc/named.conf
chmod 640 /etc/named.conf
info "named.conf ownership/permissions set."

restorecon -Rv "${ZONE_DIR}"
restorecon -Rv "${LOG_DIR}"
info "SELinux Section Complete."


#9 - Verify SELinux is enforcing
#################################################################################################
section "Checking SELinux"
SELINUX_STATUS=$(getenforce)
if [[ "${SELINUX_STATUS}" == "Enforcing" ]]; then
    info "SELinux is Enforcing."
else
    warn "SELinux is ${SELINUX_STATUS} — setting to Enforcing."
    setenforce 1
    sed -i 's/SELINUX=permissive/SELINUX=enforcing/g' /etc/selinux/config
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/g' /etc/selinux/config
    info "SELinux set to Enforcing."
fi


#10 - Open firewall
#################################################################################################
section "Configuring Firewall"
firewall-cmd --add-service=dns --permanent
firewall-cmd --reload
info "Firewall rule added for DNS (port 53)."


#11 - Checks
#################################################################################################
section "Checks"

if ! named-checkconf /etc/named.conf; then
    error "named.conf has errors — fix ts"
fi
info "named.conf syntax OK"

if ! named-checkzone "${DOMAIN}" "${ZONE_INTERNAL}"; then
    error "Internal forward be trippin."
fi
info "Internal forward zone OK"

if ! named-checkzone "${DOMAIN}" "${ZONE_EXTERNAL}"; then
    error "External forward zone is wiggin out."
fi
info "External forward zone OK"

if ! named-checkzone "${REVERSE_ZONE}.in-addr.arpa" "${ZONE_REVERSE_INT}"; then
    error "Internal reverse zone is not HIM."
fi
info "Internal reverse zone OK"

if ! named-checkzone "${EXTERNAL_REVERSE_ZONE}.in-addr.arpa" "${ZONE_REVERSE_EXT}"; then
    error "External reverse zone... has died..."
fi
info "External reverse zone OK"


#12 - Enable/start named.service
#################################################################################################
section "Starting Named Service"
systemctl enable named
systemctl restart named
sleep 2

if systemctl is-active --quiet named; then
    info "named is groovy."
else
    error "named has commited seppuku, which is most definetly NOT groovy... — check: journalctl -u named --no-pager | tail -30"
fi

#13 - Hash
#################################################################################################
section "Creating basline hashes"
sha256sum "${ZONE_DIR}"/* > ~/zone_hashes.txt
info "Hashes saved to ~/zone_hashes.txt"
info "Run 'sha256sum -c ~/zone_hashes.txt' to detect ch-ch-ch-ch-chaannggeesss."

# DONE
#################################################################################################
section "Setup Complete"
echo ""
echo "  DNS Server IP       : ${INTERNAL_IP}"
echo "  Domain              : ${DOMAIN}"
echo "  Internal fwd zone   : ${ZONE_INTERNAL}"
echo "  External fwd zone   : ${ZONE_EXTERNAL}"
echo "  Internal rev zone   : ${ZONE_REVERSE_INT}"
echo "  External rev zone   : ${ZONE_REVERSE_EXT}"
echo "  Forwarder           : ${EXTERNAL_DNS}"
echo "  Query logs          : ${LOG_DIR}/queries.log"
echo "  Zone hashes         : ~/zone_hashes.txt"
echo ""
echo "  To check for zone file tampering:"
echo "    sha256sum -c ~/zone_hashes.txt"
echo ""
echo "  To monitor DNS queries live:"
echo "    sudo tail -f ${LOG_DIR}/queries.log"







