#!/bin/bash
set -e
# CONFIGURATION — Edit these before running!
#################################################################################################
TEAM_NUM="20"
INTERNAL_IP="192.168.${TEAM_NUM}.12"
INTERNAL_SUBNET="192.168.${TEAM_NUM}.0/24"
EXTERNAL_DNS="172.18.0.12"
EXTERNAL_SUBNET="172.18.0.0/16"
EXTERNAL_ROUTER_IP="172.18.13.${TEAM_NUM}"   # Team router's external IP
DOMAIN="team20.ncaecybergames.org"
#################################################################################################

# Internal host IPs
IP_ROUTER="192.168.${TEAM_NUM}.1"
IP_WEB="192.168.${TEAM_NUM}.5"
IP_DB="192.168.${TEAM_NUM}.7"
IP_DNS="192.168.${TEAM_NUM}.12"
IP_BACKUP="192.168.${TEAM_NUM}.15"

# Reverse zone
REVERSE_ZONE="${TEAM_NUM}.168.192"

# Paths
ZONE_DIR="/var/named/zones"
ZONE_INTERNAL="${ZONE_DIR}/forward.internal.${DOMAIN}"
ZONE_EXTERNAL="${ZONE_DIR}/forward.external.${DOMAIN}"
ZONE_REVERSE="${ZONE_DIR}/reverse.${DOMAIN}"
LOG_DIR="/var/log/named"

# FUN COLORS!!!
#################################################################################################
info()    { echo -e "\e[32m[INFO]\e[0m    $1"; }
warn()    { echo -e "\e[33m[WARN]\e[0m    $1"; }
error()   { echo -e "\e[31m[ERROR]\e[0m   $1"; exit 1; }
section() { echo -e "\n\e[36m(╯°□°）╯︵ ┻━┻  $1 ┬─┬﻿ ノ( ゜-゜ノ)\e[0m"; }


#Check that script is being run as root
#################################################################################################
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
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
@   IN  SOA     team${TEAM_NUM}dns.${DOMAIN}. hostmaster.${DOMAIN}. (
                1       ; Serial
                3600    ; Refresh
                1800    ; Retry
                604800  ; Expire
                86400 ) ; Minimum TTL

; Name Servers
@               IN  NS      team${TEAM_NUM}dns.${DOMAIN}.

; Internal A Records — returns private IPs to internal clients
team${TEAM_NUM}router  IN  A   ${IP_ROUTER}
team${TEAM_NUM}web     IN  A   ${IP_WEB}
team${TEAM_NUM}db      IN  A   ${IP_DB}
team${TEAM_NUM}dns     IN  A   ${IP_DNS}
team${TEAM_NUM}backup  IN  A   ${IP_BACKUP}

; 
www             IN  A   ${IP_WEB}
EOF
info "Internal forward zone created."

#4 - Create external forward zone file
#################################################################################################
section "Writing External Forward Zone File"
cat > "${ZONE_EXTERNAL}" << EOF
\$TTL 10800
@   IN  SOA     team${TEAM_NUM}dns.${DOMAIN}. admin.${DOMAIN}. (
                1       ; Serial
                3600    ; Refresh
                1800    ; Retry
                604800  ; Expire
                86400 ) ; Minimum TTL

; 
@               IN  NS      team${TEAM_NUM}dns.${DOMAIN}.
team${TEAM_NUM}router  IN  A   ${EXTERNAL_ROUTER_IP}
team${TEAM_NUM}web     IN  A   ${EXTERNAL_ROUTER_IP}
team${TEAM_NUM}dns     IN  A   ${EXTERNAL_ROUTER_IP}

; 
www             IN  A   ${EXTERNAL_ROUTER_IP}
EOF
info "External forward zone created."

#5 - Create reverse zone file
#################################################################################################
section "Creating Reverse Zone File"
cat > "${ZONE_REVERSE}" << EOF
\$TTL 10800
@   IN  SOA     team${TEAM_NUM}dns.${DOMAIN}. hostmaster.${DOMAIN}. (
                1       ; Serial
                3600    ; Refresh
                1800    ; Retry
                604800  ; Expire
                86400 ) ; Minimum TTL

; Name Servers
@       IN  NS  team${TEAM_NUM}dns.${DOMAIN}.

; PTR Records
1       IN  PTR team${TEAM_NUM}router.${DOMAIN}.
5       IN  PTR team${TEAM_NUM}web.${DOMAIN}.
7       IN  PTR team${TEAM_NUM}db.${DOMAIN}.
12      IN  PTR team${TEAM_NUM}dns.${DOMAIN}.
15      IN  PTR team${TEAM_NUM}backup.${DOMAIN}.
EOF
info "Reverse zone created."

#6 - Create named.conf
#################################################################################################
section "Creating /etc/named.conf"
if [[ -f /etc/named.conf ]]; then
    cp /etc/named.conf /etc/named.conf.bak.$(date +%F_%T)
    info "Backed up original named.conf"
fi

cat > /etc/named.conf << EOF

options {
    listen-on port 53       { 127.0.0.1; ${INTERNAL_IP}; };
    listen-on-v6 port 53    { none; };
    directory               "/var/named";
    dump-file               "/var/named/data/cache_dump.db";
    statistics-file         "/var/named/data/named_stats.txt";
    memstatistics-file      "/var/named/data/named_mem_stats.txt";
    secroots-file           "/var/named/data/named.secroots";
    recursing-file          "/var/named/data/named.recursing";

    // Only allow queries from trusted networks
    allow-query             { localhost; ${INTERNAL_SUBNET}; ${EXTERNAL_SUBNET}; };
    allow-recursion         { localhost; ${INTERNAL_SUBNET}; };

    // Forward unknown queries to Black team external DNS
    forwarders              { ${EXTERNAL_DNS}; };
    forward                 only;
    recursion               yes;

    // Security hardening
    dnssec-validation       no;
    version                 "none";        // Hide BIND version

    managed-keys-directory  "/var/named/dynamic";
    geoip-directory         "/usr/share/GeoIP";
    pid-file                "/run/named/named.pid";
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

//Split-horizon for internal/external
view "internal" {
    match-clients           { localhost; ${INTERNAL_SUBNET}; };
    recursion               yes;

    zone "." IN {
        type hint;
        file "named.ca";
    };

    zone "${DOMAIN}" IN {
        type master;
        file "zones/forward.internal.${DOMAIN}";
        allow-query         { any; };
        allow-transfer      { none; };     // Block zone transfers
        allow-update        { none; };     // Block dynamic updates
    };

    zone "${REVERSE_ZONE}.in-addr.arpa" IN {
        type master;
        file "zones/reverse.${DOMAIN}";
        allow-query         { any; };
        allow-transfer      { none; };
        allow-update        { none; };
    };

    include "/etc/named.rfc1912.zones";
    include "/etc/named.root.key";
};

view "external" {
    match-clients           { ${EXTERNAL_SUBNET}; any; };
    recursion               no;           // No recursion for external clients

    zone "${DOMAIN}" IN {
        type master;
        file "zones/forward.external.${DOMAIN}";
        allow-query         { any; };
        allow-transfer      { none; };
        allow-update        { none; };
    };

    include "/etc/named.rfc1912.zones";
    include "/etc/named.root.key";
};
EOF
info "named.conf created."


#7 - Fixing SELinux/Permissions/Ownershiop
#################################################################################################
section "Setting Permissions and SELinux Context"

# Zone files
chown named:named "${ZONE_DIR}"
chown named:named "${ZONE_DIR}"/*
chmod 750 "${ZONE_DIR}"
chmod 640 "${ZONE_DIR}"/*
info "Zone file ownership and permissions set."

# Log directory
chown named:named "${LOG_DIR}"
chmod 750 "${LOG_DIR}"
info "Log directory ownership set."

# named.conf
chown root:named /etc/named.conf
chmod 640 /etc/named.conf
info "named.conf permissions hardened."

# SELinux
restorecon -Rv "${ZONE_DIR}"
restorecon -Rv "${LOG_DIR}"
info "SELinux context restored."


#8 - Verify SELinux is enforcing
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


#9 - Open firewall
#################################################################################################
section "Configuring Firewall"
firewall-cmd --add-service=dns --permanent
firewall-cmd --reload
info "Firewall rule added for DNS (port 53)."


#10 - Validate configuration
#################################################################################################
section "Validating Configuration"
named-checkconf /etc/named.conf \
    && info "named.conf syntax OK" \
    || error "named.conf has errors — fix before continuing."

named-checkzone ${DOMAIN} "${ZONE_INTERNAL}" \
    && info "Internal forward zone OK" \
    || error "Internal forward zone has errors."

named-checkzone ${DOMAIN} "${ZONE_EXTERNAL}" \
    && info "External forward zone OK" \
    || error "External forward zone has errors."

named-checkzone "${REVERSE_ZONE}.in-addr.arpa" "${ZONE_REVERSE}" \
    && info "Reverse zone OK" \
    || error "Reverse zone has errors."


#11 - Enable/start named.service
#################################################################################################
section "Starting Named Service"
systemctl enable named
systemctl restart named
sleep 2

if systemctl is-active --quiet named; then
    info "named is running."
else
    error "named failed to start — run: journalctl -u named --no-pager | tail -30"
fi


#12 - Take baseline hash of zone files
#################################################################################################
section "Creating Zone File Baseline Hashes"
sha256sum "${ZONE_DIR}"/* > ~/zone_hashes.txt
info "Baseline hashes saved to ~/zone_hashes.txt"
info "Run 'sha256sum -c ~/zone_hashes.txt' to detect tampering."


#13 - Test resolution
#################################################################################################
section "Testing DNS Resolution"

# Internal test
INTERNAL_RESULT=$(dig @${INTERNAL_IP} www.${DOMAIN} +short)
if [[ "${INTERNAL_RESULT}" == "${IP_WEB}" ]]; then
    info "Internal view test PASSED: www.${DOMAIN} → ${INTERNAL_RESULT}"
else
    warn "Internal view test returned: '${INTERNAL_RESULT}' (expected ${IP_WEB})"
fi

# External view test
EXTERNAL_RESULT=$(dig @${INTERNAL_IP} www.${DOMAIN} -b ${EXTERNAL_ROUTER_IP} +short 2>/dev/null || echo "")
if [[ "${EXTERNAL_RESULT}" == "${EXTERNAL_ROUTER_IP}" ]]; then
    info "External view test PASSED: www.${DOMAIN} → ${EXTERNAL_RESULT}"
else
    warn "External view test returned: '${EXTERNAL_RESULT}' (expected ${EXTERNAL_ROUTER_IP})"
    warn "Check from a device on the '${EXTERNAL_SUBNET}' network."
fi

# Version hiding test
VERSION_RESULT=$(dig @${INTERNAL_IP} version.bind chaos txt +short)
if [[ "${VERSION_RESULT}" == '"none"' ]]; then
    info "Version hiding PASSED: version.bind returns 'none'."
else
    warn "Version hiding returned: '${VERSION_RESULT}'"
fi


# DONE

section "Setup Complete"
echo ""
echo "  DNS Server IP      : ${INTERNAL_IP}"
echo "  Domain             : ${DOMAIN}"
echo "  Internal zone      : ${ZONE_INTERNAL}"
echo "  External zone      : ${ZONE_EXTERNAL}"
echo "  Reverse zone       : ${ZONE_REVERSE}"
echo "  Forwarder          : ${EXTERNAL_DNS}"
echo "  Query logs         : ${LOG_DIR}/queries.log"
echo "  Zone hashes        : ~/zone_hashes.txt"
echo "  To check for zone file tampering:"
echo "    sha256sum -c ~/zone_hashes.txt"
echo ""
echo "  To monitor DNS queries:"
echo "    sudo tail -f ${LOG_DIR}/queries.log"
echo ""
