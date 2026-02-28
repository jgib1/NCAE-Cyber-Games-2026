:local T 19
:local WAN_IF "ether1"
:local LAN_IF "ether2"
:local LAN_NET "192.168.".$T.".0/24"
:local WEB_IP ("192.168.".$T.".5")
:local DB_IP ("192.168.".$T.".7")
:local DNS_IP ("192.168.".$T.".12")
:local BAK_IP ("192.168.".$T.".15")
:local LAN_MGMT_NET $LAN_NET
:local EXT_GW "172.18.0.1"
:local EXT_DNS "172.18.0.12"
:local EXT_CA "172.18.0.38"
:local EXT_CDN "172.18.13.25"
:local JUMP_IP "172.18.12.15"

/interface list
add name=WAN comment="NCAE WAN list"
add name=LAN comment="NCAE LAN list"

/interface list member
add interface=$WAN_IF list=WAN
add interface=$LAN_IF list=LAN

/ip firewall address-list
add list=MGMT_LAN address=$LAN_MGMT_NET comment="LAN management scope"
add list=SRV_WEB address=$WEB_IP comment="Web server"
add list=SRV_DNS address=$DNS_IP comment="DNS server"
add list=SRV_DB address=$DB_IP comment="DB server"
add list=SRV_BAK address=$BAK_IP comment="Backup server"
add list=PERMITTED_EXT address=$EXT_GW comment="Competition gateway"
add list=PERMITTED_EXT address=$EXT_DNS comment="External DNS"
add list=PERMITTED_EXT address=$EXT_CA comment="Certificate Authority"
add list=PERMITTED_EXT address=$EXT_CDN comment="CDN"
add list=MGMT_JUMP address=($JUMP_IP."/32") comment="Jump host"

/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set www-ssl disabled=yes
set ssh disabled=yes
set winbox disabled=yes
set api disabled=yes
set api-ssl disabled=yes

/ip firewall filter

# INPUT CHAIN
add chain=input action=drop connection-state=invalid comment="IN drop invalid" log=yes log-prefix="IN_INVALID"
add chain=input action=accept connection-state=established,related comment="IN accept established,related"
add chain=input action=accept protocol=icmp in-interface-list=WAN comment="IN accept ICMP from WAN scoring" log=yes log-prefix="IN_ICMP"
add chain=input action=accept protocol=icmp in-interface-list=LAN comment="IN accept ICMP from LAN"
add chain=input action=drop in-interface-list=WAN comment="IN drop all other WAN" log=yes log-prefix="IN_WAN_DROP"
add chain=input action=drop comment="IN implicit deny" log=yes log-prefix="IN_DROP"

# FORWARD CHAIN
add chain=forward action=drop connection-state=invalid comment="FW drop invalid" log=yes log-prefix="FW_INVALID"
add chain=forward action=accept connection-state=established,related comment="FW accept established,related"

# Inbound DNAT forwarded traffic (HTTP, HTTPS, DNS external scoring)
add chain=forward action=accept connection-nat-state=dstnat comment="FW allow dstnat forwards" log=yes log-prefix="FW_DNAT_OK"

# Internal service access (LAN to LAN through router)
add chain=forward action=accept in-interface-list=LAN dst-address-list=SRV_DNS protocol=udp dst-port=53 comment="FW LAN to DNS UDP"
add chain=forward action=accept in-interface-list=LAN dst-address-list=SRV_DNS protocol=tcp dst-port=53 comment="FW LAN to DNS TCP"
add chain=forward action=accept in-interface-list=LAN dst-address-list=SRV_DB protocol=tcp dst-port=5432 comment="FW LAN to Postgres 5432"

# LAN management SSH to internal VMs
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMT_LAN dst-address-list=SRV_WEB protocol=tcp dst-port=22 comment="FW MGMT_LAN to WWW SSH"
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMT_LAN dst-address-list=SRV_DNS protocol=tcp dst-port=22 comment="FW MGMT_LAN to DNS SSH"
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMT_LAN dst-address-list=SRV_DB protocol=tcp dst-port=22 comment="FW MGMT_LAN to DB SSH"
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMT_LAN dst-address-list=SRV_BAK protocol=tcp dst-port=22 comment="FW MGMT_LAN to BACKUP SSH"

# Egress filtering - permit only required external destinations
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN dst-address-list=PERMITTED_EXT protocol=tcp dst-port=80,443 comment="FW LAN to permitted ext TCP 80,443"
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN dst-address-list=PERMITTED_EXT protocol=udp dst-port=53 comment="FW LAN to permitted ext DNS UDP"
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN dst-address-list=PERMITTED_EXT protocol=tcp dst-port=53 comment="FW LAN to permitted ext DNS TCP"
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN dst-address=$EXT_GW comment="FW LAN to competition gateway"

# Drop all other LAN egress to WAN - C2 containment
add chain=forward action=drop in-interface-list=LAN out-interface-list=WAN comment="FW drop all other LAN egress" log=yes log-prefix="FW_EGRESS_DROP"

# Drop unsolicited WAN to LAN
add chain=forward action=drop in-interface-list=WAN out-interface-list=LAN connection-nat-state=!dstnat comment="FW drop WAN to LAN not dstnat" log=yes log-prefix="FW_WAN_NO_DNAT"

# Forward implicit deny
add chain=forward action=drop comment="FW implicit deny" log=yes log-prefix="FW_DROP"

# NAT
/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN comment="NAT masquerade LAN to WAN"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=80 to-addresses=$WEB_IP to-ports=80 comment="DNAT HTTP to WEB"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=443 to-addresses=$WEB_IP to-ports=443 comment="DNAT HTTPS to WEB"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=53 to-addresses=$DNS_IP to-ports=53 comment="DNAT DNS UDP to DNS"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=53 to-addresses=$DNS_IP to-ports=53 comment="DNAT DNS TCP to DNS"
add chain=dstnat action=dst-nat in-interface-list=WAN src-address-list=MGMT_JUMP protocol=tcp dst-port=2205 to-addresses=$WEB_IP to-ports=22 comment="DNAT JUMP to WWW SSH"
add chain=dstnat action=dst-nat in-interface-list=WAN src-address-list=MGMT_JUMP protocol=tcp dst-port=2207 to-addresses=$DB_IP to-ports=22 comment="DNAT JUMP to DB SSH"
add chain=dstnat action=dst-nat in-interface-list=WAN src-address-list=MGMT_JUMP protocol=tcp dst-port=2212 to-addresses=$DNS_IP to-ports=22 comment="DNAT JUMP to DNS SSH"
add chain=dstnat action=dst-nat in-interface-list=WAN src-address-list=MGMT_JUMP protocol=tcp dst-port=2215 to-addresses=$BAK_IP to-ports=22 comment="DNAT JUMP to BACKUP SSH"

# ----------------------------
# POST-LOAD VERIFICATION (run manually after import)
# /ip service print
# /ip firewall filter print
# /ip firewall nat print
# /ip firewall filter print stats
# /log print
# /system history print
# ----------------------------