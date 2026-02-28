# NCAE RouterOS initial hardening with jump-host SSH management
# Jump host: 172.18.12.15, router SSH port: 2213
# Sean Hughes (newahntz) - 2024-06-17

:local T 19
:local WAN_IF "ether1-WAN"
:local LAN_IF "ether2-LAN"

:local JUMP_IP "172.18.12.15"
:local ROUTER_SSH_PORT 2213

:local LAN_NET ("192.168.".$T.".0/24")
:local WEB_IP  ("192.168.".$T.".5")
:local DB_IP   ("192.168.".$T.".7")
:local DNS_IP  ("192.168.".$T.".12")

# LAN management scope (who on LAN can admin servers like DB/DNS)
:local LAN_MGMT_NET $LAN_NET

# ----------------------------
# INTERFACE LISTS
# ----------------------------
/interface list
add name=WAN comment="NCAE WAN list" disabled=no
add name=LAN comment="NCAE LAN list" disabled=no

/interface list member
add interface=$WAN_IF list=WAN
add interface=$LAN_IF list=LAN

# ----------------------------
# ADDRESS LISTS
# ----------------------------
/ip firewall address-list
add list=MGMT_JUMP address=($JUMP_IP."/32") comment="Jump host allowed to manage router"
add list=MGMT_LAN  address=$LAN_MGMT_NET comment="LAN management scope"
add list=SRV_WEB   address=$WEB_IP comment="Web server"
add list=SRV_DNS   address=$DNS_IP comment="DNS server"
add list=SRV_DB    address=$DB_IP  comment="DB server"

# ----------------------------
# SERVICES (minimize attack surface)
# Only SSH for router management, restricted to jump host (and optionally LAN MGMT).
# ----------------------------
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set www-ssl disabled=yes
set ssh port=$ROUTER_SSH_PORT disabled=no
set winbox disabled=yes
set api disabled=yes
set api-ssl disabled=yes

# Restrict SSH at service layer
/ip service
set ssh address=($JUMP_IP."/32,".$LAN_MGMT_NET)

# ----------------------------
# FIREWALL FILTERS
# INPUT: protect router
# FORWARD: preserve scoring services and allow internal admin to DB/DNS
# ----------------------------
/ip firewall filter

# INPUT baseline
add chain=input action=drop connection-state=invalid comment="IN drop invalid" place-before=0 log=yes log-prefix="IN_INVALID"
add chain=input action=accept connection-state=established,related comment="IN accept established,related" place-before=0

# INPUT ICMP (keep limited for scoring and troubleshooting)
/ip firewall filter add chain=input action=accept protocol=icmp limit=5,10 comment="IN ICMP limited" place-before=0 log=yes log-prefix="IN_ICMP_OK"
/ip firewall filter add chain=input action=drop protocol=icmp comment="IN drop excess ICMP" place-before=0 log=yes log-prefix="IN_ICMP_DROP"

# INPUT SSH from jump host only (rate limited)
/ip firewall filter add chain=input action=accept in-interface-list=WAN src-address-list=MGMT_JUMP protocol=tcp dst-port=$ROUTER_SSH_PORT connection-state=new limit=2,5 comment="IN allow SSH from jump (limited)" place-before=0 log=yes log-prefix="IN_SSH_JUMP_OK"
/ip firewall filter add chain=input action=drop protocol=tcp dst-port=$ROUTER_SSH_PORT connection-state=new comment="IN drop other/new SSH" place-before=0 log=yes log-prefix="IN_SSH_DROP"

# Drop all other WAN input to router
add chain=input action=drop in-interface-list=WAN comment="IN drop all other WAN to router" place-before=0 log=yes log-prefix="IN_WAN_DROP"

# Final input deny
add chain=input action=drop comment="IN implicit deny" place-before=0 log=yes log-prefix="IN_DROP"

# FORWARD baseline
add chain=forward action=drop connection-state=invalid comment="FW drop invalid" place-before=0 log=yes log-prefix="FW_INVALID"
add chain=forward action=accept connection-state=established,related comment="FW accept established,related" place-before=0
add chain=forward action=fasttrack-connection connection-state=established,related comment="FW fasttrack established,related" place-before=0

# Allow LAN to WAN
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN comment="FW allow LAN to WAN" place-before=0

# Allow internal DNS usage (LAN clients to DNS server)
add chain=forward action=accept in-interface-list=LAN dst-address-list=SRV_DNS protocol=udp dst-port=53 comment="FW LAN to DNS UDP" place-before=0
add chain=forward action=accept in-interface-list=LAN dst-address-list=SRV_DNS protocol=tcp dst-port=53 comment="FW LAN to DNS TCP" place-before=0

# Allow LAN management to SSH into DB and DNS servers (server-side SSH ports)
/ip firewall filter add chain=forward action=accept in-interface-list=LAN src-address-list=MGMT_LAN dst-address-list=SRV_DNS protocol=tcp dst-port=22 comment="FW MGMT_LAN to DNS SSH" place-before=0
/ip firewall filter add chain=forward action=accept in-interface-list=LAN src-address-list=MGMT_LAN dst-address-list=SRV_DB  protocol=tcp dst-port=22 comment="FW MGMT_LAN to DB SSH" place-before=0

# Allow dst-nat forwarded services (web and external DNS)
/ip firewall filter add chain=forward action=accept connection-nat-state=dstnat comment="FW allow dstnat forwards" place-before=0 log=yes log-prefix="FW_DNAT_OK"

# Block direct WAN to LAN that is not dst-nat
add chain=forward action=drop in-interface-list=WAN out-interface-list=LAN connection-nat-state=!dstnat comment="FW drop WAN to LAN not dstnat" place-before=0 log=yes log-prefix="FW_WAN_NO_DNAT"

# Final forward deny
add chain=forward action=drop comment="FW implicit deny" place-before=0 log=yes log-prefix="FW_DROP"

# ----------------------------
# NAT (scoring services)
# ----------------------------
/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN comment="NAT masquerade LAN to WAN"

add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=80  to-addresses=$WEB_IP to-ports=80  comment="DNAT HTTP to WEB"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=443 to-addresses=$WEB_IP to-ports=443 comment="DNAT HTTPS to WEB"

add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=53 to-addresses=$DNS_IP to-ports=53 comment="DNAT DNS UDP to DNS"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=53 to-addresses=$DNS_IP to-ports=53 comment="DNAT DNS TCP to DNS"

# ----------------------------
# VERIFY
# ----------------------------
# /ip service print
# /ip firewall filter print stats
# /ip firewall nat print
# /system history print