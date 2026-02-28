# NCAE Cyber Games 2026 Regional - Team 19 RouterOS Hardening Script
# Role: MikroTik RouterOS boundary router
# WAN (ether1): 172.18.13.19 | LAN (ether2): 192.168.19.1
# Jump host: 172.18.12.15 | Router SSH port: 2213
# Sean Hughes (newahntz) - 2026

:local T 19
:local WAN_IF "ether5
:local LAN_IF "ether6"

:local JUMP_IP "172.18.12.15"
:local ROUTER_SSH_PORT 2213

:local LAN_NET ("192.168.".$T.".0/24")
:local WEB_IP  ("192.168.".$T.".5")
:local DB_IP   ("192.168.".$T.".7")
:local DNS_IP  ("192.168.".$T.".12")
:local BAK_IP  ("192.168.".$T.".15")

:local LAN_MGMT_NET $LAN_NET

# ----------------------------
# INTERFACE LISTS
# ----------------------------
/interface list
add name=WAN comment="NCAE WAN list"
add name=LAN comment="NCAE LAN list"

/interface list member
add interface=$WAN_IF list=WAN
add interface=$LAN_IF list=LAN

# ----------------------------
# ADDRESS LISTS
# ----------------------------
/ip firewall address-list
add list=MGMT_JUMP  address=($JUMP_IP."/32")    comment="Jump host"
add list=MGMT_LAN   address=$LAN_MGMT_NET       comment="LAN management scope"
add list=SRV_WEB    address=$WEB_IP             comment="Web server"
add list=SRV_DNS    address=$DNS_IP             comment="DNS server"
add list=SRV_DB     address=$DB_IP              comment="DB server"
add list=SRV_BAK    address=$BAK_IP             comment="Backup server"

# ----------------------------
# DISABLE UNNECESSARY SERVICES
# ----------------------------
/ip service
set telnet  disabled=yes
set ftp     disabled=yes
set www     disabled=yes
set www-ssl disabled=yes
set ssh     port=$ROUTER_SSH_PORT disabled=no address=($JUMP_IP."/32,".$LAN_MGMT_NET)
set winbox  disabled=yes
set api     disabled=yes
set api-ssl disabled=yes

# ----------------------------
# FIREWALL - INPUT CHAIN
# Protects the router itself.
# Order is critical: evaluated top-down, first match wins.
# ----------------------------
/ip firewall filter

# 1. Drop invalid connection states immediately
add chain=input action=drop connection-state=invalid \
    comment="IN drop invalid" \
    log=yes log-prefix="IN_INVALID"

# 2. Accept established and related (return traffic for permitted sessions)
add chain=input action=accept connection-state=established,related \
    comment="IN accept established,related"

# 3. Accept ICMP from WAN - required for 500pt scoring check
#    No rate limit - scoring engine cadence is not under our control
add chain=input action=accept protocol=icmp in-interface-list=WAN \
    comment="IN accept ICMP from WAN (scoring)" \
    log=yes log-prefix="IN_ICMP"

# 4. Accept ICMP from LAN - internal troubleshooting
add chain=input action=accept protocol=icmp in-interface-list=LAN \
    comment="IN accept ICMP from LAN"

# 5. Accept SSH from jump host on management port only, rate limited
add chain=input action=accept \
    in-interface-list=WAN \
    src-address-list=MGMT_JUMP \
    protocol=tcp dst-port=$ROUTER_SSH_PORT \
    connection-state=new limit=2,5 \
    comment="IN allow SSH from jump host" \
    log=yes log-prefix="IN_SSH_JUMP"

# 6. Accept SSH from LAN management scope on management port
add chain=input action=accept \
    in-interface-list=LAN \
    src-address-list=MGMT_LAN \
    protocol=tcp dst-port=$ROUTER_SSH_PORT \
    connection-state=new \
    comment="IN allow SSH from LAN mgmt"

# 7. Drop any other new SSH attempts to the router
add chain=input action=drop \
    protocol=tcp dst-port=$ROUTER_SSH_PORT \
    connection-state=new \
    comment="IN drop unauthorized SSH" \
    log=yes log-prefix="IN_SSH_DROP"

# 8. Drop everything else inbound from WAN
add chain=input action=drop in-interface-list=WAN \
    comment="IN drop all other WAN" \
    log=yes log-prefix="IN_WAN_DROP"

# 9. Implicit deny - catches anything not matched above
add chain=input action=drop \
    comment="IN implicit deny" \
    log=yes log-prefix="IN_DROP"

# ----------------------------
# FIREWALL - FORWARD CHAIN
# Controls traffic passing through the router between WAN and LAN.
# DNAT-forwarded packets arrive here after NAT table rewrite.
# ----------------------------

# 10. Drop invalid forwarded connections
add chain=forward action=drop connection-state=invalid \
    comment="FW drop invalid" \
    log=yes log-prefix="FW_INVALID"

# 11. Accept established and related forwarded traffic (return paths)
add chain=forward action=accept connection-state=established,related \
    comment="FW accept established,related"

# 12. Allow all LAN to WAN egress (updates, cert fetching, DNS upstream)
add chain=forward action=accept \
    in-interface-list=LAN out-interface-list=WAN \
    comment="FW allow LAN to WAN egress"

# 13. Allow DNAT-forwarded inbound traffic (web HTTP/HTTPS, DNS external)
#     connection-nat-state=dstnat catches packets rewritten by NAT table
add chain=forward action=accept connection-nat-state=dstnat \
    comment="FW allow dstnat forwards" \
    log=yes log-prefix="FW_DNAT_OK"

# 14. Allow LAN to DNS server port 53 UDP (internal DNS resolution)
add chain=forward action=accept \
    in-interface-list=LAN \
    dst-address-list=SRV_DNS \
    protocol=udp dst-port=53 \
    comment="FW LAN to DNS UDP"

# 15. Allow LAN to DNS server port 53 TCP (zone transfers, large responses)
add chain=forward action=accept \
    in-interface-list=LAN \
    dst-address-list=SRV_DNS \
    protocol=tcp dst-port=53 \
    comment="FW LAN to DNS TCP"

# 16. Allow LAN scoring agent to Postgres (500pt check, internal)
add chain=forward action=accept \
    in-interface-list=LAN \
    dst-address-list=SRV_DB \
    protocol=tcp dst-port=5432 \
    comment="FW LAN to Postgres 5432"

# 17. Allow LAN management SSH to web server (remediation access)
add chain=forward action=accept \
    in-interface-list=LAN \
    src-address-list=MGMT_LAN \
    dst-address-list=SRV_WEB \
    protocol=tcp dst-port=22 \
    comment="FW MGMT_LAN to WWW SSH"

# 18. Allow LAN management SSH to DNS server
add chain=forward action=accept \
    in-interface-list=LAN \
    src-address-list=MGMT_LAN \
    dst-address-list=SRV_DNS \
    protocol=tcp dst-port=22 \
    comment="FW MGMT_LAN to DNS SSH"

# 19. Allow LAN management SSH to DB server
add chain=forward action=accept \
    in-interface-list=LAN \
    src-address-list=MGMT_LAN \
    dst-address-list=SRV_DB \
    protocol=tcp dst-port=22 \
    comment="FW MGMT_LAN to DB SSH"

# 20. Allow LAN management SSH to backup server
add chain=forward action=accept \
    in-interface-list=LAN \
    src-address-list=MGMT_LAN \
    dst-address-list=SRV_BAK \
    protocol=tcp dst-port=22 \
    comment="FW MGMT_LAN to BACKUP SSH"

# 21. Drop WAN to LAN traffic that did not arrive via DNAT
#     This is your lateral movement chokepoint. Anything Red Team
#     tries to push inbound that isn't a scoring-permitted service dies here.
add chain=forward action=drop \
    in-interface-list=WAN out-interface-list=LAN \
    connection-nat-state=!dstnat \
    comment="FW drop WAN to LAN not dstnat" \
    log=yes log-prefix="FW_WAN_NO_DNAT"

# 22. Forward implicit deny
add chain=forward action=drop \
    comment="FW implicit deny" \
    log=yes log-prefix="FW_DROP"

# ----------------------------
# NAT
# ----------------------------
/ip firewall nat

# Masquerade all LAN egress through WAN interface
add chain=srcnat action=masquerade \
    out-interface-list=WAN \
    comment="NAT masquerade LAN to WAN"

# DNAT: HTTP to web server (500pt WWW Port 80 + 1500pt WWW Content)
add chain=dstnat action=dst-nat \
    in-interface-list=WAN \
    protocol=tcp dst-port=80 \
    to-addresses=$WEB_IP to-ports=80 \
    comment="DNAT HTTP to WEB"

# DNAT: HTTPS to web server (1500pt WWW SSL)
add chain=dstnat action=dst-nat \
    in-interface-list=WAN \
    protocol=tcp dst-port=443 \
    to-addresses=$WEB_IP to-ports=443 \
    comment="DNAT HTTPS to WEB"

# DNAT: DNS UDP external (500pt DNS EXT FWD + 500pt DNS EXT REV)
add chain=dstnat action=dst-nat \
    in-interface-list=WAN \
    protocol=udp dst-port=53 \
    to-addresses=$DNS_IP to-ports=53 \
    comment="DNAT DNS UDP to DNS"

# DNAT: DNS TCP external
add chain=dstnat action=dst-nat \
    in-interface-list=WAN \
    protocol=tcp dst-port=53 \
    to-addresses=$DNS_IP to-ports=53 \
    comment="DNAT DNS TCP to DNS"

# ----------------------------
# POST-LOAD VERIFICATION COMMANDS (run manually after import)
# ----------------------------
# /ip service print
# /ip firewall filter print
# /ip firewall nat print
# /ip firewall filter print stats
# /log print
# /system history print