# NCAE Cyber Games 2026 Regional - Team 19 RouterOS Hardening Script
# WAN (ether5): 172.18.13.19 | LAN (ether6): 192.168.19.1
# Jump host: 172.18.12.15 | Router SSH port: 2213
# Sean Hughes (newahntz) - 2026

:local T 19
:local WAN_IF "ether5"
:local LAN_IF "ether6"
:local JUMP_IP "172.18.12.15"
:local ROUTER_SSH_PORT 2213
:local LAN_NET ("192.168.".$T.".0/24")
:local WEB_IP ("192.168.".$T.".5")
:local DB_IP ("192.168.".$T.".7")
:local DNS_IP ("192.168.".$T.".12")
:local BAK_IP ("192.168.".$T.".15")
:local LAN_MGMT_NET $LAN_NET

/interface list
add name=WAN comment="NCAE WAN list"
add name=LAN comment="NCAE LAN list"

/interface list member
add interface=$WAN_IF list=WAN
add interface=$LAN_IF list=LAN

/ip firewall address-list
add list=MGMT_JUMP address=($JUMP_IP."/32") comment="Jump host"
add list=MGMT_LAN address=$LAN_MGMT_NET comment="LAN management scope"
add list=SRV_WEB address=$WEB_IP comment="Web server"
add list=SRV_DNS address=$DNS_IP comment="DNS server"
add list=SRV_DB address=$DB_IP comment="DB server"
add list=SRV_BAK address=$BAK_IP comment="Backup server"

/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set www-ssl disabled=yes
set ssh port=$ROUTER_SSH_PORT disabled=no address=($JUMP_IP."/32,".$LAN_MGMT_NET)
set winbox disabled=yes
set api disabled=yes
set api-ssl disabled=yes

/ip firewall filter
add chain=input action=drop connection-state=invalid comment="IN drop invalid" log=yes log-prefix="IN_INVALID"
add chain=input action=accept connection-state=established,related comment="IN accept established,related"
add chain=input action=accept protocol=icmp in-interface-list=WAN comment="IN accept ICMP from WAN scoring" log=yes log-prefix="IN_ICMP"
add chain=input action=accept protocol=icmp in-interface-list=LAN comment="IN accept ICMP from LAN"
add chain=input action=accept in-interface-list=WAN src-address-list=MGMT_JUMP protocol=tcp dst-port=$ROUTER_SSH_PORT connection-state=new limit=2,5 comment="IN allow SSH from jump host" log=yes log-prefix="IN_SSH_JUMP"
add chain=input action=accept in-interface-list=LAN src-address-list=MGMT_LAN protocol=tcp dst-port=$ROUTER_SSH_PORT connection-state=new comment="IN allow SSH from LAN mgmt"
add chain=input action=drop protocol=tcp dst-port=$ROUTER_SSH_PORT connection-state=new comment="IN drop unauthorized SSH" log=yes log-prefix="IN_SSH_DROP"
add chain=input action=drop in-interface-list=WAN comment="IN drop all other WAN" log=yes log-prefix="IN_WAN_DROP"
add chain=input action=drop comment="IN implicit deny" log=yes log-prefix="IN_DROP"
add chain=forward action=drop connection-state=invalid comment="FW drop invalid" log=yes log-prefix="FW_INVALID"
add chain=forward action=accept connection-state=established,related comment="FW accept established,related"
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN comment="FW allow LAN to WAN egress"
add chain=forward action=accept connection-nat-state=dstnat comment="FW allow dstnat forwards" log=yes log-prefix="FW_DNAT_OK"
add chain=forward action=accept in-interface-list=LAN dst-address-list=SRV_DNS protocol=udp dst-port=53 comment="FW LAN to DNS UDP"
add chain=forward action=accept in-interface-list=LAN dst-address-list=SRV_DNS protocol=tcp dst-port=53 comment="FW LAN to DNS TCP"
add chain=forward action=accept in-interface-list=LAN dst-address-list=SRV_DB protocol=tcp dst-port=5432 comment="FW LAN to Postgres 5432"
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMT_LAN dst-address-list=SRV_WEB protocol=tcp dst-port=22 comment="FW MGMT_LAN to WWW SSH"
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMT_LAN dst-address-list=SRV_DNS protocol=tcp dst-port=22 comment="FW MGMT_LAN to DNS SSH"
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMT_LAN dst-address-list=SRV_DB protocol=tcp dst-port=22 comment="FW MGMT_LAN to DB SSH"
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMT_LAN dst-address-list=SRV_BAK protocol=tcp dst-port=22 comment="FW MGMT_LAN to BACKUP SSH"
add chain=forward action=drop in-interface-list=WAN out-interface-list=LAN connection-nat-state=!dstnat comment="FW drop WAN to LAN not dstnat" log=yes log-prefix="FW_WAN_NO_DNAT"
add chain=forward action=drop comment="FW implicit deny" log=yes log-prefix="FW_DROP"

/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN comment="NAT masquerade LAN to WAN"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=80 to-addresses=$WEB_IP to-ports=80 comment="DNAT HTTP to WEB"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=443 to-addresses=$WEB_IP to-ports=443 comment="DNAT HTTPS to WEB"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=53 to-addresses=$DNS_IP to-ports=53 comment="DNAT DNS UDP to DNS"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=53 to-addresses=$DNS_IP to-ports=53 comment="DNAT DNS TCP to DNS"

# ----------------------------
# POST-LOAD VERIFICATION (run manually after import)
# /ip service print
# /ip firewall filter print
# /ip firewall nat print
# /ip firewall filter print stats
# /log print
# /system history print
# ----------------------------